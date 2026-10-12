import {isAbsolute} from 'node:path';
import {pinnedExecutable,runFixed} from './process.mjs';
import {gitObjectID,sha256} from './core.mjs';
import {canonical} from '../ledger.mjs';
import {stat} from 'node:fs/promises';
import {resolve as resolvePath} from 'node:path';
const sha=/^[a-f0-9]{40}$/;

// An operator-owned local clone only. No fetch, push, hooks, key operations, or
// provider credentials. Retention and classification are independent capabilities.
export async function createLocalGitSource({repositoryPath,gitProgram,gitProgramSHA256,archive,inventory,maxObjects=100000,maxBytes=64*1024*1024}){
 if(!isAbsolute(repositoryPath??'')||typeof archive?.retain!=='function'||typeof archive?.read!=='function'||typeof inventory?.classify!=='function'||!Number.isSafeInteger(maxObjects)||maxObjects<1||maxObjects>100000||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>256*1024*1024)throw Error('Fixed Git source capabilities required');
 const program=await pinnedExecutable(gitProgram,gitProgramSHA256);
 async function git(args,input,limit=maxBytes){await pinnedExecutable(gitProgram,gitProgramSHA256);return runFixed(program,['-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',...args],{cwd:repositoryPath,input,limit,env:{GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_NO_REPLACE_OBJECTS:'1',GIT_TERMINAL_PROMPT:'0',GIT_OPTIONAL_LOCKS:'0'},timeoutMs:120000});}
 async function resolve(ref){if(!/^refs\/heads\/[A-Za-z0-9_/-]+$/.test(ref??''))throw Error('Invalid pinned source ref');const value=(await git(['rev-parse','--verify',`${ref}^{commit}`],undefined,100)).toString().trim();if(!sha.test(value))throw Error('Unsupported Git object format');return value;}
 return Object.freeze({main:config=>resolve(config.targetRef),source:config=>resolve(config.sourceRef),async snapshot(config){
  if((await git(['rev-parse','--is-shallow-repository'],undefined,100)).toString().trim()!=='false'||(await git(['rev-parse','--show-object-format'],undefined,100)).toString().trim()!=='sha1')throw Error('Complete SHA1 Git history required');
  const configuration=(await git(['config','--includes','--list'],undefined,65536)).toString();if(/^merge\..*\.driver=|^extensions\.partialclone=|^remote\..*\.promisor=/mi.test(configuration))throw Error('External merge drivers and partial clones are not eligible');
  const grafts=(await git(['rev-parse','--git-path','info/grafts'],undefined,4096)).toString().trim();let graftFile;try{graftFile=await stat(resolvePath(repositoryPath,grafts));}catch(error){if(error.code!=='ENOENT')throw error;}if(graftFile)throw Error('Grafted Git history is not eligible');
  const sourceSHA=await resolve(config.sourceRef),mainSHA=await resolve(config.targetRef),sourceBaseSHA=(await git(['merge-base',mainSHA,sourceSHA],undefined,100)).toString().trim();if(!sha.test(sourceBaseSHA))throw Error('Source has no unambiguous normal Git base');
  const merged=(await git(['merge-tree','--write-tree','--no-messages',mainSHA,sourceSHA],undefined,65536)).toString().trim();if(!sha.test(merged))throw Error('Conflicting or unsupported source merge');const treeSHA=merged;
  const ids=[...new Set((await git(['rev-list','--objects','--no-object-names',mainSHA,sourceSHA,treeSHA])).toString().trim().split('\n'))];if(!ids.length||ids.length>maxObjects||ids.some(id=>!sha.test(id)))throw Error('History closure exceeds retention limit');
  const raw=await git(['cat-file','--batch'],ids.join('\n')+'\n'),objects=[];let offset=0;
  for(const expected of ids){const end=raw.indexOf(10,offset);if(end<0)throw Error('Truncated Git object closure');const fields=raw.subarray(offset,end).toString().split(' '),size=Number(fields[2]);if(fields[0]!==expected||!['commit','tree','blob','tag'].includes(fields[1])||!Number.isSafeInteger(size)||size<0||end+1+size>=raw.length)throw Error('Invalid Git object closure');const payload=raw.subarray(end+1,end+1+size);if(gitObjectID(fields[1],payload)!==expected||raw[end+1+size]!==10)throw Error('Git object hash mismatch');objects.push({sha:expected,type:fields[1],payload:payload.toString('base64')});offset=end+size+2;}
  if(offset!==raw.length)throw Error('Extra Git object data');
  const closure={schema:'repoctl-source-history/v1',repositoryID:config.repositoryID,repository:config.repository,sourceSHA,mainSHA,sourceBaseSHA,treeSHA,objects},historyDigest=sha256(canonical(closure));
  const retained=await archive.retain({digest:historyDigest,closure});if(retained?.digest!==historyDigest||typeof retained.reference!=='string'||sha256(canonical(await archive.read(retained.reference)))!==historyDigest)throw Error('Immutable history retention unverified');
  const tree=(await git(['ls-tree','-r','-z','--full-tree',treeSHA])).toString('utf8').split('\0').filter(Boolean).map(line=>{const match=/^(100644|100755|120000) blob ([a-f0-9]{40})\t([^\0]+)$/.exec(line);if(!match||match[3].includes('\n'))throw Error('Submodules or unsupported tree entries require separate policy');return {mode:match[1],sha:match[2],path:match[3]};});
  const classified=await inventory.classify({repositoryID:config.repositoryID,treeSHA,entries:tree,objects});const paths=tree.map(e=>e.path).sort(),inventoryDigest=sha256(canonical(tree));
  if(classified?.complete!==true||canonical(classified.paths?.slice().sort())!==canonical(paths)||!['languages','frameworks','manifests'].every(k=>Array.isArray(classified[k])))throw Error('Complete workspace classification unavailable');
  return {sourceSHA,sourceBaseSHA,mainSHA,treeSHA,historyDigest,retentionReference:retained.reference,verified:true,inventory:{digest:inventoryDigest,complete:true,paths,languages:classified.languages,frameworks:classified.frameworks,manifests:classified.manifests}};
 }});
}
