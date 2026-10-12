import {spawn} from 'node:child_process';
import {readFile,realpath,stat} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';

export async function pinnedExecutable(path,digest){
 if(typeof path!=='string'||!isAbsolute(path)||/[\0\r\n]/.test(path)||!/^[a-f0-9]{64}$/.test(digest??''))throw Error('Fixed executable pin required');
 const resolved=await realpath(path),info=await stat(resolved);
 if(!info.isFile()||(info.mode&0o022)||createHash('sha256').update(await readFile(resolved)).digest('hex')!==digest)throw Error('Installed executable differs from trusted pin');
 return resolved;
}
export function runFixed(program,args,{cwd,input='',env={},limit=65536,timeoutMs=30000}={}){
 return new Promise((resolve,reject)=>{
  const child=spawn(program,args,{cwd,env:{PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',...env},stdio:['pipe','pipe','pipe'],shell:false});
  const chunks=[];let size=0,stderrSize=0,failed=false;
  const fail=()=>{if(!failed){failed=true;child.kill('SIGKILL');reject(Error('Fixed command failed or exceeded bounds'));}};
  const timer=setTimeout(fail,timeoutMs);child.on('error',fail);child.stdin.on('error',()=>{});
  child.stdout.on('data',chunk=>{size+=chunk.length;if(size>limit)fail();else chunks.push(chunk);});
  child.stderr.on('data',chunk=>{stderrSize+=chunk.length;if(stderrSize>65536)fail();});
  child.on('close',code=>{clearTimeout(timer);if(!failed){if(code!==0)fail();else resolve(Buffer.concat(chunks));}});
  child.stdin.end(input);
 });
}
