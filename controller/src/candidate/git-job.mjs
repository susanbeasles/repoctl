import {spawn} from 'node:child_process';
export function candidateGit(gitExecutable,maxBytes){
 return async function git(directory,args,input,limit=maxBytes) {
  return await new Promise((resolve,reject)=>{
   const child=spawn(gitExecutable,['--no-replace-objects','--git-dir='+directory,'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',...args],{env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_TERMINAL_PROMPT:'0',GIT_NO_LAZY_FETCH:'1',GIT_GRAFT_FILE:'/dev/null'},stdio:['pipe','pipe','ignore']});
   let failure,bytes=0;const chunks=[];let escalation;
   const fail=message=>{failure??=Error(message);child.kill('SIGTERM');escalation??=setTimeout(()=>child.kill('SIGKILL'),2000);};
   const timer=setTimeout(()=>fail('Candidate Git command timed out'),10000);
   child.stdout.on('data',chunk=>{bytes+=chunk.length;if(bytes>limit)fail('Candidate object/patch exceeds configured bound');else chunks.push(chunk);});
   child.stdin.on('error',()=>fail('Candidate Git input failed'));
   child.on('error',error=>{clearTimeout(timer);clearTimeout(escalation);reject(error);});
   child.on('close',code=>{clearTimeout(timer);clearTimeout(escalation);if(failure)reject(failure);else if(code!==0)reject(Error('Candidate Git command failed; conflict or unavailable objects'));else resolve(Buffer.concat(chunks));});
   child.stdin.end(input);
  });
 }
}
