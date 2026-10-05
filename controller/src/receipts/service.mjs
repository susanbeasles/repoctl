import {canonical,digest,signEntry,verifyEntry} from '../ledger.mjs';
const hash=/^[a-f0-9]{64}$/;
const exact=(v,n)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===n.sort().join();
export function receiptService({storage,authority,completion,checkpoint,keyID,privateKey,publicKey,trustedKeys}){
 if(!hash.test(keyID??'')||!privateKey||!publicKey||![authority?.load,completion?.verify,checkpoint?.append,checkpoint?.receipt].every(v=>typeof v==='function'))throw Error('Receipt service not configured');
 const keys=trustedKeys??new Map([[keyID,publicKey]]);if(!(keys instanceof Map)||!keys.has(keyID)||keys.size>10)throw Error('Invalid receipt verification inventory');
 async function retained(id){
  if(!hash.test(id??''))throw Error('Invalid operation');const saved=await storage.get(`receipt:${id}`);
  if(!saved||saved.operationID!==id||saved.entryDigest!==await verifyEntry(saved.entry,keys)||canonical(saved.entry.payload)!==canonical(saved.payload))throw Error('Invalid retained receipt');return saved;
 }
 async function confirmed(saved){
  const r=await checkpoint.receipt({repositoryID:saved.payload.repositoryID,operationID:saved.operationID});
  if(!exact(r,['operationID','repositoryID','sequence','digest','commitSHA'])||r.operationID!==saved.operationID||r.repositoryID!==saved.payload.repositoryID||r.sequence!==saved.payload.sequence||r.digest!==saved.entryDigest||r.commitSHA!==saved.payload.commitSHA)throw Error('Checkpoint receipt differs');return r;
 }
 return {
  async finalize(request){
   if(!exact(request,['operationID','intent'])||!hash.test(request.operationID??''))throw Error('Invalid finalize request');
   const id=request.operationID,view=await authority.load(id);
   if(view.record?.operation?.id!==id||view.recordDigest!==await digest(view.record)||canonical(view.record.intent)!==canonical(request.intent))throw Error('Fixed execution intent differs');
   const payload=view.ledgerPayload;
   if(payload?.repositoryID!==request.intent.repositoryID||payload.baseSHA!==request.intent.baseSHA||payload.commitSHA!==request.intent.commitSHA)throw Error('Retained payload differs');
   const old=await storage.get(`receipt:${id}`);
   if(!old){
    const observation={operationID:id,repositoryID:payload.repositoryID,entryPayloadDigest:await digest(payload),baseSHA:payload.baseSHA,commitSHA:payload.commitSHA};
    const result=await completion.verify(observation);
    if(canonical(result)!==canonical({...observation,promoted:true}))throw Error('Completion denied');
    // Sign and retain inside the same transaction. No provider/network call here.
    // A response outage cannot cause a second ECDSA signature on retry.
    await storage.transaction(async tx=>{
     const previous=await tx.get(`receipt:${id}`);if(previous)return;
     const signed=await signEntry(payload,keyID,privateKey);
     await tx.put(`receipt:${id}`,{operationID:id,intent:request.intent,payload,authorityDigest:await digest(view),entry:signed.envelope,entryDigest:signed.digest,state:'pending'});
    });
   }
   const saved=await retained(id);
   if(canonical(saved.intent)!==canonical(request.intent)||canonical(saved.payload)!==canonical(payload)||saved.authorityDigest!==await digest(view))throw Error('Receipt operation replacement');
   if(saved.state==='completed')return confirmed(saved);
   const response=await checkpoint.append({operationID:id,entry:saved.entry});
   if(response.digest!==saved.entryDigest||response.operationID!==id)throw Error('Checkpoint append response differs');
   const receipt=await confirmed(saved);
   await storage.transaction(async tx=>{const current=await tx.get(`receipt:${id}`);if(current.entryDigest!==saved.entryDigest)throw Error('Receipt reservation changed');await tx.put(`receipt:${id}`,{...current,state:'completed'});});
   return receipt;
  },
  async observe(request){
   if(!exact(request,['operationID','record']))throw Error('Invalid receipt observation');
   const saved=await retained(request.operationID);
   if(request.record?.operation?.id!==request.operationID||canonical(request.record.intent)!==canonical(saved.intent))throw Error('Receipt record differs');
   const view=await authority.load(request.operationID);
   if(canonical(view.record)!==canonical(request.record)||saved.authorityDigest!==await digest(view))throw Error('Retained authority changed');
   const receipt=await confirmed(saved);
   return {operationID:request.operationID,state:'promoted',commitSHA:receipt.commitSHA,receiptDigest:receipt.digest,verified:true};
  }
 };
}
