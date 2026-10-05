// Private enrollment adapter. Sessions are created only after independently
// authenticated owner approval. Callback codes are never durably retained.
const hash=/^[a-f0-9]{64}$/;
const key=id=>{if(typeof id!=='string'||!hash.test(id))throw Error('Invalid enrollment reference');return `enrollment:${id}`;};
export function enrollmentJournal(storage,vault,provider,clock=()=>Date.now()){
 async function load(id){const r=await storage.get(key(id));if(!r)throw Error('Unknown enrollment');return r;}
 async function transition(id,from,to,extra={}){await storage.transaction(async tx=>{const k=key(id),r=await tx.get(k);if(r?.state!==from)throw Error('Enrollment state changed');await tx.put(k,{...r,...extra,state:to});});}
 const publicState=(id,r)=>({operationID:id,state:r.state,...(r.appID?{appID:r.appID}:{}),role:r.role});
 return {
  async create(id,session){
   if(!session||Object.keys(session).sort().join()!==['ownerID','role','expiresAt','manifestDigest'].sort().join()||!Number.isSafeInteger(session.ownerID)||session.ownerID<=0||!['writer','validator','builder','release'].includes(session.role)||!hash.test(session.manifestDigest??'')||!Number.isSafeInteger(session.expiresAt)||session.expiresAt<=clock()||session.expiresAt>clock()+600000)throw Error('Invalid approved enrollment session');
   await storage.transaction(async tx=>{const k=key(id);if(await tx.get(k))throw Error('Enrollment already exists');await tx.put(k,{...session,state:'ready'});});
  },
  async exchange(id,code){
   if(typeof code!=='string'||! /^[A-Za-z0-9_-]{1,200}$/.test(code))throw Error('Invalid manifest code');
   const session=await load(id);if(session.state!=='ready'||session.expiresAt<=clock())throw Error('Enrollment not exchangeable');
   // Reserve before the one-shot external request. A lost response is uncertain,
   // never permission to retry code conversion.
   await transition(id,'ready','exchanging');
   try{
    const app=await provider.exchangeManifestCode(code);
    await vault.stage(id,{appID:app.id,ownerID:session.ownerID,role:session.role,privateKey:app.pem,webhookSecret:app.webhook_secret,clientSecret:app.client_secret});
    await transition(id,'exchanging','staged',{appID:app.id});
   }catch{throw Error('Enrollment exchange uncertain; reconcile without re-exchanging');}
   return this.reconcile(id);
  },
  async reconcile(id){
   let r=await load(id);if(r.state==='active')return publicState(id,r);
   if(r.state==='exchanging'){
    const retained=await vault.status(id);
    if(!retained||retained.ownerID!==r.ownerID||retained.role!==r.role)throw Error('Provider outcome uncertain; isolated recovery required');
    await transition(id,'exchanging','staged',{appID:retained.appID});r=await load(id);
   }
   if(r.state!=='staged')throw Error('Enrollment not reconcilable');
   const retained=await vault.status(id);
   if(retained?.state==='staged')await vault.activate(id,request=>provider.verifyApp(request,r));
   const active=await vault.status(id);
   if(active?.state!=='active'||active.appID!==r.appID||active.ownerID!==r.ownerID||active.role!==r.role)throw Error('Verified credential unavailable');
   await transition(id,'staged','active');return publicState(id,await load(id));
  },
  async status(id){return publicState(id,await load(id));}
 };
}
