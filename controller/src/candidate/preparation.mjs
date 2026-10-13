import {candidateGit} from './git-job.mjs';
import {preparationIntent} from './intent.ts';
import {mkdir,realpath,writeFile,lstat} from 'node:fs/promises';
import {isAbsolute,join} from 'node:path';
import {createHash} from 'node:crypto';
const sha=/^[a-f0-9]{40}$/;
const fingerprint=bytes=>createHash('sha256').update(bytes).digest('hex');
// Isolated local/remote-builder job adapter, never a Worker route. Installed job
// configuration binds the repository directory and numeric identity.
export async function candidatePreparation({sourceGitDirectory,gitExecutable,repositoryID,maxBytes=64*1024*1024}) {
 if(!isAbsolute(sourceGitDirectory??'')||!isAbsolute(gitExecutable??'')||!Number.isSafeInteger(repositoryID)||repositoryID<1||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>256*1024*1024)throw Error('Invalid candidate builder configuration');
 const source=await realpath(sourceGitDirectory);
 if(source!==sourceGitDirectory)throw Error('Candidate source must be a canonical directory');
 async function requireIndependentSource(){
  for(const name of ['objects','objects/info']){
   const path=join(source,name);
   if((await realpath(path))!==path||!(await lstat(path)).isDirectory())throw Error('Candidate source must have complete independent objects');
  }
  for(const name of ['objects/info/alternates','objects/info/http-alternates','shallow','commondir']){try{await lstat(join(source,name));throw Error('Candidate source must have complete independent objects');}catch(error){if(error.code!=='ENOENT')throw error;}}
 }
 await requireIndependentSource();
 const git=candidateGit(gitExecutable,maxBytes);
 return {async prepare(intent,outputDirectory) {
  intent=preparationIntent(intent,repositoryID);
  if(!isAbsolute(outputDirectory??''))throw Error('Invalid candidate preparation intent');
  const parent=await realpath(join(outputDirectory,'..'));
  const output=join(parent,outputDirectory.split('/').at(-1));
  if(output!==outputDirectory||output===source||output.startsWith(source+'/'))throw Error('Candidate output must be canonical and outside source Git directory');
  await requireIndependentSource(); // Recheck configured storage at each new job.
  await mkdir(output,{mode:0o700}); // Private source evidence; never overwrite/resume.
  try {
   const objects=join(output,'objects.git');
   await git(objects,['init','--bare','--quiet'],undefined,1024);
   // Preserve exact submitted history before calculating a candidate tree.
   const pack=await git(source,['pack-objects','--revs','--stdout','--threads=1'],Buffer.from(intent.baseSHA+'\n'+intent.sourceSHA+'\n'));
   await writeFile(join(output,'submission.pack'),pack,{flag:'wx',mode:0o600});
   await git(objects,['index-pack','--stdin'],pack,1024);
   for(const id of [intent.baseSHA,intent.sourceSHA])if((await git(objects,['cat-file','-t',id],undefined,32)).toString().trim()!=='commit')throw Error('Candidate source and base must be commits');
   const bases=(await git(objects,['merge-base','--all',intent.baseSHA,intent.sourceSHA],undefined,256)).toString().trim().split('\n');
   if(bases.length!==1||!sha.test(bases[0]))throw Error('Ambiguous or unrelated candidate ancestry');
   const patch=await git(objects,['diff','--binary','--full-index','--no-ext-diff','--no-textconv',bases[0],intent.sourceSHA,'--']);
   if(!patch.length)throw Error('Submission contains no changes');
   await writeFile(join(output,'submission.patch'),patch,{flag:'wx',mode:0o600});
   await git(objects,['read-tree',intent.baseSHA],undefined,1024);
   await git(objects,['apply','--cached','--binary','--whitespace=nowarn','-'],patch,1024);
   const treeSHA=(await git(objects,['write-tree'],undefined,64)).toString().trim();
   if(!sha.test(treeSHA))throw Error('Invalid prepared candidate tree');
   const manifest={protocol:'repoctl-candidate-preparation-v1',state:'prepared-awaiting-signature',...intent,mergeBaseSHA:bases[0],treeSHA,snapshotDigest:fingerprint(pack),patchDigest:fingerprint(patch),signingRequired:true};
   await writeFile(join(output,'preparation.json'),JSON.stringify(manifest)+'\n',{flag:'wx',mode:0o600});
   return manifest;
  }catch(error){await writeFile(join(output,'failed.json'),JSON.stringify({state:'failed',requiresNewPreparation:true})+'\n',{flag:'wx',mode:0o600});throw error;}
 }};
}
