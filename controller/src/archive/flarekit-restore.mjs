import {spawn} from 'node:child_process';
import {mkdtemp,realpath,rm} from 'node:fs/promises';
import {isAbsolute,join} from 'node:path';
import {tmpdir} from 'node:os';
// Installed binary/configuration only. No caller-controlled commands or paths.
export function flarekitRestore({executable,configuration,environment={},archives,timeoutMs=300000}){
 if(!isAbsolute(executable??'')||!isAbsolute(configuration??'')||!Array.isArray(archives)||!archives.length||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>300000)throw Error('Invalid FlareKit restore installation');
 const installed=structuredClone(archives);
 async function invoke(operation,parameters,profile){
  const requestID=crypto.randomUUID();const input={schemaVersion:1,requestID,operation,profile:profile??null,parameters};
  return await new Promise((resolve,reject)=>{
   const child=spawn(executable,['run','--request','-','--config',configuration],{env:{...environment},stdio:['pipe','pipe','pipe'],shell:false});let output=[],size=0,failed=false;
   const fail=()=>{if(!failed){failed=true;child.kill('SIGKILL');reject(Error('FlareKit recovery operation failed'));}};
   const timer=setTimeout(fail,timeoutMs);child.on('error',fail);child.stdin.on('error',fail);
   child.stdout.on('data',b=>{size+=b.length;if(size>1024*1024)fail();else output.push(b);});
   child.stderr.on('data',()=>{}); // Do not expose credential-adjacent diagnostics.
   child.on('close',code=>{clearTimeout(timer);if(failed)return;try{if(code!==0)throw Error();const r=JSON.parse(Buffer.concat(output).toString('utf8'));if(r.schemaVersion!==1||r.requestID!==requestID||r.operation!==operation||r.status!=='succeeded')throw Error();resolve(r.output);}catch{fail();}});
   child.stdin.end(JSON.stringify(input));
  });
 }
 return {async run(intent){
  const matches=installed.filter(a=>a.repositoryID===intent.repositoryID&&intent.archiveDigests?.includes(a.archiveDigest));
  if(matches.length!==1)throw Error('Recovery requires one installed snapshot');const a=matches[0];
  if(!/^[a-f0-9]{64}$/.test(a.archiveDigest??'')||!/^[a-f0-9]{64}$/.test(a.gitManifestDigest??'')||!isAbsolute(a.vault??'')||typeof a.snapshotID!=='string'||!a.identity)throw Error('Invalid installed snapshot');
  const root=await realpath(await mkdtemp(join(tmpdir(),'repoctl-fk-recovery-'))),capture=join(root,'capture'),destination=join(root,'repository');
  const cleanup=()=>rm(root,{recursive:true,force:true});
  try{
   if(a.fetch===true)await invoke('snapshot.fetch',{vault:a.vault,vaultID:a.vaultID,snapshotID:a.snapshotID,expectedManifestDigest:a.archiveDigest,identity:a.identity},a.profile);
   const restored=await invoke('snapshot.restore',{vault:a.vault,snapshotID:a.snapshotID,destination:capture,expectedManifestDigest:a.archiveDigest,identity:a.identity});
   if(restored.manifestDigest!==a.archiveDigest||restored.verification!=='full-ciphertext-and-authenticated-plaintext')throw Error('FlareKit plaintext verification missing');
   const git=await invoke('git.restore',{capture,destination,expectedManifestDigest:a.gitManifestDigest});
   if(git.gitFsck!==true||git.allLocalObjectsRestored!==true||git.unsafeConfigAndHooksActivated!==false)throw Error('FlareKit Git recovery verification missing');
   return {directory:await realpath(join(destination,'.git')),archiveDigest:a.archiveDigest,cleanup};
  }catch(e){await cleanup();throw e;}
 }};
}
