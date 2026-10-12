import {isIntegrationRef} from './integration-ref.mjs';
import {spawn} from 'node:child_process';
import {readFile,realpath,stat} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
const check=(value,message='Normal Git transport denied')=>{if(!value)throw Error(message);};
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const SHA=/^[a-f0-9]{40}$/;

// Process output is bounded and private. No shell, hooks, inherited credentials,
// application code, signing request, or command selected by a workflow is used.
function runBounded(program,args,{cwd,input='',env,timeoutMs=30000,maxOutputBytes=131072}){
 return new Promise((resolve,reject)=>{
  const child=spawn(program,args,{cwd,env,stdio:['pipe','pipe','pipe'],shell:false,detached:true});let size=0,failed=false;const chunks=[];
  const fail=()=>{if(failed)return;failed=true;try{process.kill(-child.pid,'SIGKILL');}catch{child.kill('SIGKILL');}reject(Error('Normal Git command failed'));};
  const timer=setTimeout(fail,timeoutMs);child.on('error',()=>{clearTimeout(timer);fail();});child.stdin.on('error',()=>{});
  child.stdout.on('data',bytes=>{size+=bytes.length;if(size>maxOutputBytes)fail();else chunks.push(bytes);});child.stderr.on('data',bytes=>{size+=bytes.length;if(size>maxOutputBytes)fail();});
  child.on('close',code=>{clearTimeout(timer);if(failed)return;if(code!==0)fail();else resolve(Buffer.concat(chunks));});child.stdin.end(input);
 });
}
export function createNormalGitTransport({config,run=runBounded,clock=()=>Math.floor(Date.now()/1000)}){
 check(config&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(config.repository)&&Number.isSafeInteger(config.repositoryID)&&config.repositoryID>0&&[config.gitPath,config.gitDirectory].every(v=>typeof v==='string'&&isAbsolute(v)&&!/[\0\r\n]/.test(v))&&/^[a-f0-9]{64}$/.test(config.gitDigest??''));
 const remote=`https://github.com/${config.repository}.git`;
 const environment={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null',GIT_ATTR_NOSYSTEM:'1',GIT_NO_REPLACE_OBJECTS:'1',GIT_TERMINAL_PROMPT:'0'};
 const prefix=['--no-optional-locks','--git-dir='+config.gitDirectory,'-c','core.hooksPath=/dev/null','-c','credential.helper=','-c','protocol.allow=never','-c','protocol.https.allow=always','-c','http.followRedirects=false','-c','http.sslVerify=true','-c','push.followTags=false'];
 async function installed(){
  const path=await realpath(config.gitPath),executable=await stat(path),directory=await stat(config.gitDirectory);check(executable.isFile()&&!(executable.mode&0o022)&&digest(await readFile(path))===config.gitDigest,'Installed Git executable differs');check(directory.isDirectory()&&!(directory.mode&0o022)&&await realpath(config.gitDirectory)===config.gitDirectory,'Git directory is not operator owned');
  const raw=await run(path,[...prefix,'config','--local','--no-includes','--null','--list'],{cwd:config.gitDirectory,env:environment});
  const entries=raw.toString('utf8').split('\0').filter(Boolean),seen=new Set();let bare=false;
  const permitted={'core.repositoryformatversion':['0'],'core.filemode':['true','false'],'core.bare':['true'],'core.logallrefupdates':['true','false'],'remote.origin.url':[remote],'remote.origin.fetch':['+refs/heads/*:refs/remotes/origin/*']};
  for(const entry of entries){const index=entry.indexOf('\n'),key=entry.slice(0,index),value=entry.slice(index+1);check(index>0&&!seen.has(key)&&permitted[key]?.includes(value),'Untrusted local Git configuration');seen.add(key);if(key==='core.bare')bare=true;}check(bare,'Bare Git source store required');return path;
 }
 async function execute(args,{input='',env=environment}={}){const path=await installed();return run(path,[...prefix,...args],{cwd:config.gitDirectory,input,env});}
 return Object.freeze({
  async putObject(type,bytes){check(['commit','tag'].includes(type)&&typeof bytes==='string'&&Buffer.byteLength(bytes)>0&&Buffer.byteLength(bytes)<=65536&&!bytes.includes('\0'));const result=(await execute(['hash-object','-w','-t',type,'--stdin'],{input:bytes})).toString('utf8').trim();check(SHA.test(result));return result;},
  async readObject(type,id){check(['commit','tag'].includes(type)&&SHA.test(id));return (await execute(['cat-file',type,id])).toString('utf8');},
  async pushDeleteOnly(input){
   check(input&&Object.keys(input).sort().join()==='expectedSHA,expiresAt,ref,repository,repositoryID,token'&&input.repository===config.repository&&input.repositoryID===config.repositoryID&&isIntegrationRef(input.ref)&&SHA.test(input.expectedSHA)&&typeof input.token==='string'&&input.token.length>0&&input.token.length<=8192&&!/[\s\0]/.test(input.token)&&Number.isSafeInteger(input.expiresAt)&&input.expiresAt>clock()&&input.expiresAt<=clock()+300);
   const path=await installed(),env={...environment,GIT_CONFIG_COUNT:'1',GIT_CONFIG_KEY_0:`http.${remote}.extraheader`,GIT_CONFIG_VALUE_0:'Authorization: Basic '+Buffer.from('x-access-token:'+input.token).toString('base64')};
   check(input.expiresAt>clock());
   try{await run(path,[...prefix,'push','--porcelain','--no-follow-tags',`--force-with-lease=${input.ref}:${input.expectedSHA}`,remote,`:${input.ref}`],{cwd:config.gitDirectory,env,timeoutMs:30000,maxOutputBytes:65536});}catch{throw Error('Conditional integration deletion outcome uncertain');}
  },
  async pushCreateOnly(input){
   check(input&&Object.keys(input).sort().join()==='expiresAt,objectSHA,ref,repository,repositoryID,token'&&input.repository===config.repository&&input.repositoryID===config.repositoryID&&SHA.test(input.objectSHA)&&typeof input.token==='string'&&input.token.length>0&&input.token.length<=8192&&!/[\s\0]/.test(input.token)&&Number.isSafeInteger(input.expiresAt)&&input.expiresAt>clock()&&input.expiresAt<=clock()+300);
   const match=/^refs\/tags\/promotion\/([1-9][0-9]*)\/(?:source|main)$/.exec(input.ref);check(isIntegrationRef(input.ref)||(match&&Number.isSafeInteger(Number(match[1]))));
   const path=await installed(),type=(await run(path,[...prefix,'cat-file','-t',input.objectSHA],{cwd:config.gitDirectory,env:environment})).toString('utf8').trim();check(type===(input.ref.startsWith('refs/tags/')?'tag':'commit'));
   const env={...environment,GIT_CONFIG_COUNT:'1',GIT_CONFIG_KEY_0:`http.${remote}.extraheader`,GIT_CONFIG_VALUE_0:'Authorization: Basic '+Buffer.from('x-access-token:'+input.token).toString('base64')};
   check(input.expiresAt>clock(),'Normal Git publication grant expired');try{await run(path,[...prefix,'push','--porcelain','--no-follow-tags',`--force-with-lease=${input.ref}:`,remote,`${input.objectSHA}:${input.ref}`],{cwd:config.gitDirectory,env,timeoutMs:30000,maxOutputBytes:65536});}catch{throw Error('Normal Git publication outcome uncertain');}
  }
 });
}
