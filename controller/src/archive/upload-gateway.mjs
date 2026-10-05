import {digest} from '../ledger.mjs';
import {githubJWKS,verifyExecutorOIDC} from '../authorization/oidc.mjs';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
// This gateway grants no GitHub or storage credentials. Repeated authenticated
// uploads are safe only because the private publisher is conditional/idempotent.
export function recoveryUploadGateway({trust,publisher,jwks=githubJWKS,clock=()=>Math.floor(Date.now()/1000)}){
 if(!trust||!Array.isArray(trust.targetRepositoryIDs)||!trust.targetRepositoryIDs.length||!trust.targetRepositoryIDs.every(x=>Number.isSafeInteger(x)&&x>0)||!Array.isArray(trust.actorIDs)||!trust.actorIDs.length||!trust.actorIDs.every(x=>Number.isSafeInteger(x)&&x>0)||!Array.isArray(trust.eventNames)||!trust.eventNames.length||!trust.eventNames.every(x=>['workflow_dispatch','workflow_call'].includes(x))||! /^[a-f0-9]{40}$/.test(trust.workflowSHA??'')||! /^[a-f0-9]{40}$/.test(trust.jobWorkflowSHA??'')||typeof publisher?.fetch!=='function')throw Error('Invalid recovery workflow trust');
 return {async fetch(request){
  if(request.method!=='POST'||new URL(request.url).pathname!=='/v1/archive/recovery/upload')return Response.json({error:'not_found'},{status:404,headers});
  try{
   const auth=request.headers.get('authorization');if(!auth?.startsWith('Bearer ')||auth.length>20007)throw Error('Missing identity');
   const reader=request.body?.getReader();if(!reader)throw Error('Missing body');let size=0;const chunks=[];
   for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>4*1024*1024){await reader.cancel();throw Error('Oversized upload');}chunks.push(value);}
   const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
   const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
   if(!body||Object.keys(body).sort().join()!==['publication','runID','runAttempt'].sort().join()||!Number.isSafeInteger(body.runID)||body.runID<1||!Number.isSafeInteger(body.runAttempt)||body.runAttempt<1)throw Error('Invalid execution');
   if(!body.publication||Object.keys(body.publication).sort().join()!=='envelope,intent'||!trust.targetRepositoryIDs?.includes(body.publication.intent?.repositoryID))throw Error('Uninstalled target');
   const operationID=await digest(body.publication);
   await verifyExecutorOIDC(auth.slice(7),trust,{operationID,runID:body.runID,runAttempt:body.runAttempt},await jwks(),clock());
   const response=await publisher.fetch(new Request('https://private.invalid/v1/archive/recovery/publish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body.publication)}));
   if(!response.ok)throw Error('Publication refused');
   const result=await response.json();
   return Response.json(result,{headers});
  }catch{return Response.json({error:'recovery_upload_denied'},{status:403,headers});}
 }};
}
