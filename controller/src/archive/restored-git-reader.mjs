import {spawn} from 'node:child_process';
import {realpath,lstat} from 'node:fs/promises';
import {isAbsolute,join} from 'node:path';
const sha=/^[a-f0-9]{40}$/,hash=/^[a-f0-9]{64}$/;
// Local recovery-job adapter, not a Worker module. Its directory must be a
// fresh independently verified restore, supplied by installed job configuration.
export async function restoredGitReader({directory,gitExecutable,repositoryID,archiveDigest,maxObjectBytes=64*1024*1024}){
 if(!isAbsolute(directory??'')||!isAbsolute(gitExecutable??'')||!Number.isSafeInteger(repositoryID)||repositoryID<1||!hash.test(archiveDigest??'')||!Number.isSafeInteger(maxObjectBytes)||maxObjectBytes<1)throw Error('Invalid restored Git configuration');
 const root=await realpath(directory);if(root!==directory||!(await lstat(root)).isDirectory())throw Error('Recovery directory must be an absolute real directory');
 for(const name of ['objects/info/alternates','objects/info/http-alternates','shallow']){try{await lstat(join(root,name));throw Error('Incomplete or externally linked recovery');}catch(e){if(e.code!=='ENOENT')throw e;}}
 // Reject filesystem links throughout the object store, including packfiles.
 const {readdir}=await import('node:fs/promises');
 async function walk(path){for(const e of await readdir(path,{withFileTypes:true})){if(e.isSymbolicLink())throw Error('Recovery object store contains a symlink');if(e.isDirectory())await walk(join(path,e.name));else if(!e.isFile())throw Error('Recovery object store contains a special file');}}
 await walk(join(root,'objects'));
 async function run(args,limit){return await new Promise((resolve,reject)=>{
  const child=spawn(gitExecutable,['--no-replace-objects','--git-dir='+root,'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',...args],{cwd:root,env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_TERMINAL_PROMPT:'0',GIT_OPTIONAL_LOCKS:'0',GIT_NO_LAZY_FETCH:'1'},stdio:['ignore','pipe','ignore']});
  const chunks=[];let bytes=0,failed=false;const timer=setTimeout(()=>{failed=true;child.kill();reject(Error('Recovery Git timeout'));},10000);
  child.stdout.on('data',chunk=>{bytes+=chunk.length;if(bytes>limit){failed=true;child.kill();reject(Error('Recovered object exceeds limit'));}else chunks.push(chunk);});
  child.on('error',e=>{clearTimeout(timer);reject(e);});child.on('close',code=>{clearTimeout(timer);if(!failed){if(code!==0)reject(Error('Recovered Git object unavailable'));else resolve(Buffer.concat(chunks));}});
 });}
 return {async object({repositoryID:requested,objectID,archiveDigests}){
  if(requested!==repositoryID||!sha.test(objectID??'')||!Array.isArray(archiveDigests)||!archiveDigests.includes(archiveDigest))throw Error('Recovery request outside installed archive binding');
  const type=(await run(['cat-file','-t',objectID],32)).toString().trim();if(!['commit','tree','blob'].includes(type))throw Error('Unsupported recovered object type');
  const body=await run(['cat-file',type,objectID],maxObjectBytes);
  return {archiveDigest,bytes:new Uint8Array(Buffer.concat([Buffer.from(type+' '+body.length+'\0'),body]))};
 }};
}
