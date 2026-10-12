import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const exec=promisify(execFile);
const runDefault=async(program,args,options)=>(await exec(program,args,{...options,encoding:'buffer',timeout:30000,maxBuffer:1024*1024})).stdout;
const check=ok=>{if(!ok)throw Error('Conditional main advancement denied');};
// Trusted executor only: no checkout or candidate code is run. The caller
// independently verifies signature, policy, checks and fresh promotion authority.
export async function advanceMain(input,{run=runDefault,clock=()=>Math.floor(Date.now()/1000)}={}){
 check(input&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(input.repository)&&[input.baseSHA,input.commitSHA,input.treeSHA].every(v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v))&&typeof input.token==='string'&&input.token.length>0&&input.token.length<=8192&&!/[\s\0]/.test(input.token)&&Number.isSafeInteger(input.expiresAt)&&input.expiresAt>clock()&&input.expiresAt<=clock()+300);
 const directory=await mkdtemp(join(tmpdir(),'main-advance-')),remote=`https://github.com/${input.repository}.git`;
 const env={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null',GIT_NO_REPLACE_OBJECTS:'1',GIT_TERMINAL_PROMPT:'0',GIT_CONFIG_COUNT:'1',GIT_CONFIG_KEY_0:`http.${remote}.extraheader`,GIT_CONFIG_VALUE_0:'Authorization: Basic '+Buffer.from('x-access-token:'+input.token).toString('base64')};
 const prefix=['--git-dir='+directory,'-c','core.hooksPath=/dev/null','-c','credential.helper=','-c','http.followRedirects=false','-c','http.sslVerify=true','-c','protocol.ext.allow=never','-c','push.followTags=false'];
 const git=async args=>(await run('/usr/bin/git',[...prefix,...args],{cwd:directory,env})).toString('utf8').trim();
 try{
  await run('/usr/bin/git',['init','--bare','--quiet',directory],{cwd:directory,env});
  await git(['fetch','--no-tags','--depth=2',remote,input.commitSHA]);
  const headers=(await git(['cat-file','commit',input.commitSHA])).split('\n\n')[0].split('\n');
  const parents=headers.filter(v=>v.startsWith('parent '));check(parents.length===1&&parents[0]==='parent '+input.baseSHA&&headers[0]==='tree '+input.treeSHA);
  check(await git(['rev-list','--count',input.baseSHA+'..'+input.commitSHA])==='1');
  check(input.expiresAt>clock());
  await git(['push','--porcelain','--no-follow-tags',`--force-with-lease=refs/heads/main:${input.baseSHA}`,remote,`${input.commitSHA}:refs/heads/main`]);
  check((await git(['ls-remote',remote,'refs/heads/main'])).split(/\s+/)[0]===input.commitSHA);
 }catch{throw Error('Conditional main advancement failed; reconcile remote state');}
 finally{await rm(directory,{recursive:true,force:true});}
}
