import {WorkerEntrypoint,DurableObject} from 'cloudflare:workers';
import {appVault} from '../enrollment/app-vault.mjs';
import {enrollmentJournal} from '../enrollment/journal.mjs';
import {githubEnrollmentProvider} from '../enrollment/github.mjs';
import {boundJSON} from '../runtime/services.mjs';
async function boundedInput(request){
 if(!request.body)throw Error('Missing request');
 const reader=request.body.getReader(),chunks=[];let size=0;
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>2048){await reader.cancel();throw Error('Oversized request');}chunks.push(value);}
 const raw=new Uint8Array(size);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
}
const headers={'Cache-Control':'no-store','Content-Type':'application/json'};
export class AppSignerCoordinator extends DurableObject {
 constructor(ctx,env){super(ctx,env);this.ctx=ctx;this.env=env;}
 async enroll(request){
  if(this.env.APP_ENROLLMENT_ENABLED!=='true'||typeof this.env.APP_KEYRING_JSON!=='string'||typeof this.env.APP_ENROLLMENT_APPROVAL?.fetch!=='function')return Response.json({error:'enrollment_not_configured'},{status:503,headers});
  try{
   const path=new URL(request.url).pathname;
   if(request.method!=='POST'||!['/v1/enrollment/create','/v1/enrollment/exchange','/v1/enrollment/reconcile','/v1/enrollment/status'].includes(path))throw Error('Invalid enrollment route');
   const input=await boundedInput(request);
   const expected=path.endsWith('/exchange')?['operationID','approvalReference','code']:['operationID','approvalReference'];
   if(!input||Object.keys(input).sort().join()!==expected.sort().join()||![input.operationID,input.approvalReference].every(x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x)))throw Error('Invalid enrollment input');
   const approval=await boundJSON(this.env.APP_ENROLLMENT_APPROVAL,'/v1/enrollment/authorize',{operationID:input.operationID,approvalReference:input.approvalReference,action:path.split('/').pop()});
   if(approval?.accepted!==true||approval.operationID!==input.operationID||approval.approvalReference!==input.approvalReference)throw Error('Enrollment approval denied');
   const vault=await appVault(this.ctx.storage,JSON.parse(this.env.APP_KEYRING_JSON));
   const journal=enrollmentJournal(this.ctx.storage,vault,githubEnrollmentProvider());
   let result;
   if(path.endsWith('/create')){await journal.create(input.operationID,approval.session);result=await journal.status(input.operationID);}
   else {
    const existing=await this.ctx.storage.get(`enrollment:${input.operationID}`);
    if(!existing||JSON.stringify(existing.ownerID)!==JSON.stringify(approval.session?.ownerID)||existing.role!==approval.session?.role||existing.manifestDigest!==approval.session?.manifestDigest)throw Error('Enrollment session changed');
    result=path.endsWith('/exchange')?await journal.exchange(input.operationID,input.code):path.endsWith('/reconcile')?await journal.reconcile(input.operationID):await journal.status(input.operationID);
   }
   return Response.json(result,{headers});
  }catch{return Response.json({error:'enrollment_denied_or_uncertain'},{status:403,headers});}
 }
 async fetch(request){
  if(this.env.APP_SIGNER_ENABLED!=='true'||typeof this.env.APP_KEYRING_JSON!=='string'||! /^[a-f0-9]{64}$/.test(this.env.APP_CREDENTIAL_REFERENCE??''))return Response.json({error:'signer_not_configured'},{status:503,headers});
  if(request.method!=='POST'||new URL(request.url).pathname!=='/v1/github/app-jwt')return Response.json({error:'not_found'},{status:404,headers});
  try{
   const claims=await boundedInput(request);
   const vault=await appVault(this.ctx.storage,JSON.parse(this.env.APP_KEYRING_JSON));
   const jwt=await vault.sign(this.env.APP_CREDENTIAL_REFERENCE,claims);
   return Response.json({jwt},{headers});
  }catch{return Response.json({error:'signing_denied'},{status:403,headers});}
 }
}
export class AppSignerService extends WorkerEntrypoint {
 fetch(request){
  if(!this.env.APP_SIGNER_COORDINATOR)return Response.json({error:'signer_not_configured'},{status:503,headers});
  return this.env.APP_SIGNER_COORDINATOR.get(this.env.APP_SIGNER_COORDINATOR.idFromName('remote-app-custody-v1')).fetch(request);
 }
}
export class AppEnrollmentService extends WorkerEntrypoint {
 fetch(request){
  if(!this.env.APP_SIGNER_COORDINATOR)return Response.json({error:'enrollment_not_configured'},{status:503,headers});
  return this.env.APP_SIGNER_COORDINATOR.get(this.env.APP_SIGNER_COORDINATOR.idFromName('remote-app-custody-v1')).enroll(request);
 }
}
// Only a broker's explicitly configured private service binding can request JWTs.
export default {fetch(){return new Response('Not found',{status:404,headers:{'Cache-Control':'no-store'}});}};
