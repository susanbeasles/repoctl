import {installationCredentials} from '../authorization/github-credentials.mjs';
import {githubJWKS} from '../authorization/oidc.mjs';
import {reconcileExecution} from '../execution/reconcile.mjs';
import {journaledCredentials,cleanupCredential} from './custody.mjs';
const hash=/^[a-f0-9]{64}$/,sha=/^[a-f0-9]{40}$/;
// Binding identity is infrastructure-controlled. Requests cannot select a URL.
export async function boundJSON(binding,path,body) {
 if(typeof binding?.fetch!=='function')throw Error('Required remote service unavailable');
 const response=await binding.fetch(`https://internal${path}`,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 if(!response.ok)throw Error('Remote service denied request');
 const reader=response.body?.getReader();if(!reader)throw Error('Empty remote response');
 let size=0;const chunks=[];
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>65536){await reader.cancel();throw Error('Oversized remote response');}chunks.push(value);}
 const raw=new Uint8Array(size);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
}
export function runtimeReady(env) {
 return env.BROKER_ENABLED==='true'&&typeof env.TOKEN_KEYRING_JSON==='string'&&['BROKER_AUTHORITY','BROKER_VERIFIER','BROKER_SIGNER','BROKER_RECEIPTS'].every(name=>typeof env[name]?.fetch==='function');
}
export async function loadAuthorization(env,operations,id) {
 let record=await operations.record(id);
 if(!record){
  record=await boundJSON(env.BROKER_AUTHORITY,'/v1/authorization/load',{operationID:id});
  if(Object.keys(record).sort().join()!==['operation','intent','trust'].sort().join()||record.operation?.id!==id)throw Error('Invalid remote authorization');
  const p=record.intent;
  if(!p||p.repositoryID!==record.operation.repositoryID||!['main','master'].includes(p.branch)||`refs/heads/${p.branch}`!==record.operation.targetRef||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(p.repository)||![p.baseSHA,p.commitSHA,p.treeSHA].every(v=>sha.test(v??'')))throw Error('Invalid fixed execution intent');
  await operations.retain(record);
 }
 return record;
}
export function runtimeServices(env,operations,custody,record,operationID,fetcher=fetch) {
 const trust=record.trust;
 const provider=installationCredentials({appID:trust.appID,installationID:trust.installationID,repositoryIDs:trust.repositoryIDs,
  signAppJWT:async claims=>{
   const r=await boundJSON(env.BROKER_SIGNER,'/v1/github/app-jwt',claims);
   if(typeof r.jwt!=='string'||r.jwt.length>16000||r.jwt.split('.').length!==3)throw Error('Invalid remote signer response');return r.jwt;
  },fetcher});
 async function check(path) {
  const result=await boundJSON(env.BROKER_VERIFIER,path,{operationID,operation:record.operation,intent:record.intent});
  if(result.operationID!==operationID||result.verified!==true)throw Error('Independent verification failed');
 }
 const services={
  operations,serialize:async(id,fn)=>{if(id!==operationID)throw Error('Operation mismatch');return fn();},
  jwks:()=>githubJWKS(fetcher),executionIntent:async id=>{if(id!==operationID)throw Error('Operation mismatch');return record.intent;},
  credentials:journaledCredentials(provider,custody,operationID),
  async verifyAuthorization(){
   // Authority must evaluate current accepted policy/enrollment/run, not stale data.
   const current=await boundJSON(env.BROKER_AUTHORITY,'/v1/authorization/check',{operationID,operation:record.operation,intent:record.intent,trust});
   if(current.operationID!==operationID||current.accepted!==true)throw Error('Current authority denied');
   await check('/v1/evidence/authorization');
  },
  observe:{async tip(repositoryID,branch){
   if(repositoryID!==record.intent.repositoryID||branch!==record.intent.branch)throw Error('Read target mismatch');
   // V1 personal profile is public. No writer credential is used for observation.
   const base=`https://api.github.com/repos/${record.intent.repository}`;
   async function get(path){
    const response=await fetcher(base+path,{redirect:'manual',signal:AbortSignal.timeout(10000),headers:{Accept:'application/vnd.github+json','User-Agent':'repoctl-independent-observer','X-GitHub-Api-Version':'2026-03-10'}});
    if(!response.ok)throw Error('GitHub observation failed');const text=await response.text();if(text.length>65536)throw Error('GitHub observation too large');return JSON.parse(text);
   }
   if((await get('')).id!==repositoryID)throw Error('Repository identity changed');
   const result=await get(`/git/ref/heads/${branch}`);if(!sha.test(result.object?.sha??''))throw Error('Invalid observed ref');return result.object.sha;
  }},
  async verifyCompletion(){await check('/v1/evidence/completion');},
  receipts:{async finalize(id,intent){
   const receipt=await boundJSON(env.BROKER_RECEIPTS,'/v1/ledger/finalize',{operationID:id,intent});
   if(receipt.operationID!==id||!hash.test(receipt.digest??''))throw Error('Invalid independent receipt');return receipt;
  }}
 };
 services.complete=async(input,t)=>{
  // Completion authenticates before cleanup. A spoofed caller cannot revoke a run.
  const result=await reconcileExecution(input,services,t);
  const cleanup=await cleanupCredential(operationID,custody,provider);
  return {...result,credentialCleanup:cleanup==='retry'?'pending':cleanup};
 };
 return {services,provider};
}
