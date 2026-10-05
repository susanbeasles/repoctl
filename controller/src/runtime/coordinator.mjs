import {executionRequest} from '../execution/http.mjs';
import {durableOperations} from './state.mjs';
import {tokenCustody,cleanupCredential} from './custody.mjs';
import {runtimeReady,loadAuthorization,runtimeServices} from './services.mjs';
const headers={'Cache-Control':'no-store','Content-Type':'application/json','X-Content-Type-Options':'nosniff'};
export class BrokerCoordinator {
 constructor(ctx,env){this.ctx=ctx;this.env=env;this.tail=Promise.resolve();}
 // A promise queue serializes live handlers without holding blockConcurrencyWhile
 // over network I/O. Durable transactional reservations survive object restarts.
 serialize(fn){const work=this.tail.then(fn,fn);this.tail=work.catch(()=>{});return work;}
 async fetch(request){
  if(!runtimeReady(this.env))return Response.json({error:'broker_not_configured'},{status:503,headers});
  return this.serialize(async()=>{
   try{
    // Parse through the existing bounded/schema-validating HTTP handler first.
    const operations=durableOperations(this.ctx.storage);
    const custody=await tokenCustody(this.ctx.storage,JSON.parse(this.env.TOKEN_KEYRING_JSON));
    const pinned={},services={};
    services.serialize=async(id,fn)=>{
     const record=await loadAuthorization(this.env,operations,id);
     Object.assign(pinned,record.trust);
     const runtime=runtimeServices(this.env,operations,custody,record,id);
     const admission=services.serialize;
     Object.assign(services,runtime.services,{serialize:admission});
     return fn();
    };
    return await executionRequest(request,services,pinned);
   }catch{return Response.json({error:'broker_denied_or_reconciliation_required'},{status:403,headers});}
  });
 }
 async alarm(){
  return this.serialize(async()=>{
   if(typeof this.env.TOKEN_KEYRING_JSON!=='string')throw Error('Broker recovery custody unavailable');
   const now=Math.floor(Date.now()/1000),storage=this.ctx.storage;
   const custody=await tokenCustody(storage,JSON.parse(this.env.TOKEN_KEYRING_JSON));
   const operations=durableOperations(storage),leases=await storage.list({prefix:'lease:operation:'});
   let next;
   for(const lease of leases.values()){
    if(lease.expiresAt>now){next=Math.min(next??Infinity,lease.expiresAt*1000);continue;}
    const record=await operations.record(lease.operationID);if(!record)throw Error('Missing recovery authorization');
    const {provider}=runtimeServices(this.env,operations,custody,record,lease.operationID);
    let result;try{result=await cleanupCredential(lease.operationID,custody,provider,now);}catch{result='retry';}
    if(result==='retry')next=Math.min(next??Infinity,(now+60)*1000);
    if(['issuing','issued'].includes(lease.state))await operations.markUncertain(lease.operationID);
    // Unknown provider issuance cannot be revoked without the returned token.
    // Keep its reservation forever; no expiry automatically permits reissuance.
   }
   if(next!==undefined)await storage.setAlarm(next);
  });
 }
}
