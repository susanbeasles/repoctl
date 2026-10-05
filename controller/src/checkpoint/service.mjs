import {canonical,digest,verifyEntry,verifyChain,promotionPayload,putArchive} from '../ledger.mjs';
const hash=/^[a-f0-9]{64}$/,sha=/^[a-f0-9]{40}$/;
const exact=(v,n)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===n.sort().join();
export function checkpointService({storage,bucket,bootstrap,trustedKeys,completion,maxEntries=1000}){
 if(!exact(bootstrap,['repositoryID','commitSHA','digest'])||!Number.isSafeInteger(bootstrap.repositoryID)||bootstrap.repositoryID<=0||!sha.test(bootstrap.commitSHA??'')||!hash.test(bootstrap.digest??'')||!(trustedKeys instanceof Map)||!trustedKeys.size||typeof completion?.verify!=='function'||!Number.isSafeInteger(maxEntries)||maxEntries<1||maxEntries>10000)throw Error('Invalid checkpoint configuration');
 const prefix=`ledger/${bootstrap.repositoryID}/`,rootKey='checkpoint-root',tipKey='checkpoint-tip',pendingKey='checkpoint-pending';
 const objectKey=sequence=>`${prefix}entries/${String(sequence).padStart(16,'0')}.json`;
 async function object(key){const found=await bucket.get(key);if(!found)throw Error('Missing retained ledger object');if(found.size>65536)throw Error('Oversized retained ledger object');const text=await found.text();if(text.length>65536)throw Error('Oversized retained ledger object');return JSON.parse(text);}
 async function entryHash(entry){
  if(!exact(entry,['protocol','algorithm','keyID','payload','signature'])||typeof entry.signature!=='string'||entry.signature.length>256||!exact(entry.payload,['kind','repositoryID','sequence','previousDigest','baseSHA','commitSHA','sourceSHA','policyDigest','evidenceDigest','archiveDigests']))throw Error('Invalid ledger envelope');
  const p=entry.payload;
  if(!Array.isArray(p.archiveDigests)||!p.archiveDigests.length||p.archiveDigests.length>100||new Set(p.archiveDigests).size!==p.archiveDigests.length||![p.baseSHA,p.commitSHA,p.sourceSHA].every(v=>sha.test(v??''))||p.commitSHA===p.baseSHA||canonical(p)!==canonical(promotionPayload(p))||p.repositoryID!==bootstrap.repositoryID)throw Error('Invalid promotion payload');
  return verifyEntry(entry,trustedKeys);
 }
 async function read(){
  const root=await storage.get(rootKey),tip=await storage.get(tipKey);
  if(!root||root.state!=='ready'||root.bootstrapDigest!==await digest(bootstrap)||!exact(tip,['sequence','digest','commitSHA'])||!Number.isSafeInteger(tip.sequence)||tip.sequence<0||tip.sequence>maxEntries||!hash.test(tip.digest??'')||!sha.test(tip.commitSHA??''))throw Error('Checkpoint not initialized or altered');
  if(canonical(await object(prefix+'genesis.json'))!==canonical(bootstrap))throw Error('Genesis differs');
  const entries=[];
  for(let sequence=1;sequence<=tip.sequence;sequence++){
   const entry=await object(objectKey(sequence)),fingerprint=await entryHash(entry),index=await storage.get(`checkpoint-index:${sequence}`);
   if(!index||index.digest!==fingerprint||index.sequence!==sequence||entry.payload.sequence!==sequence)throw Error('Retained index differs');entries.push(entry);
  }
  const anchor={repositoryID:bootstrap.repositoryID,startSequence:0,startDigest:bootstrap.digest,startCommit:bootstrap.commitSHA,endSequence:tip.sequence,endDigest:tip.digest,endCommit:tip.commitSHA};
  await verifyChain(entries,trustedKeys,anchor);
  // A known successor means the pointer was rolled back or a commit was incomplete.
  if(await storage.get(`checkpoint-index:${tip.sequence+1}`))throw Error('Checkpoint pointer behind retained index');
  return {anchor,entries};
 }
 return {
  async initialize(){
   const binding=await digest(bootstrap),root=await storage.get(rootKey);
   if(!root&&await bucket.get(prefix+'genesis.json'))throw Error('Lost checkpoint state; explicit recovery required');
   await storage.transaction(async tx=>{
    const saved=await tx.get(rootKey);if(saved){if(saved.bootstrapDigest!==binding)throw Error('Bootstrap changed');return;}
    await tx.put(rootKey,{state:'initializing',bootstrapDigest:binding});
   });
   await putArchive(bucket,prefix+'genesis.json',bootstrap);
   await storage.transaction(async tx=>{
    const saved=await tx.get(rootKey);if(saved.bootstrapDigest!==binding)throw Error('Bootstrap changed');
    if(saved.state==='ready'){if(!await tx.get(tipKey))throw Error('Lost checkpoint pointer');return;}
    await tx.put(tipKey,{sequence:0,digest:bootstrap.digest,commitSHA:bootstrap.commitSHA});await tx.put(rootKey,{...saved,state:'ready'});
   });
   return (await read()).anchor;
  },
  async current({repositoryID}){if(repositoryID!==bootstrap.repositoryID)throw Error('Foreign repository');return (await read()).anchor;},
  async entries({repositoryID,startSequence,endSequence}){
   if(repositoryID!==bootstrap.repositoryID||!Number.isSafeInteger(startSequence)||!Number.isSafeInteger(endSequence)||startSequence<1||endSequence<startSequence-1)throw Error('Invalid ledger range');
   const result=await read();if(endSequence>result.anchor.endSequence||startSequence>result.anchor.endSequence+1)throw Error('Ledger range unavailable');return result.entries.slice(startSequence-1,endSequence);
  },
  async append(request){
   if(!exact(request,['operationID','entry'])||!hash.test(request.operationID??''))throw Error('Invalid append');
   const fingerprint=await entryHash(request.entry),p=request.entry.payload,id=request.operationID;
   const ready=await storage.get(`checkpoint-complete:${id}`);
   if(ready){if(ready.digest!==fingerprint)throw Error('Operation replacement');await read();if(await digest(await object(objectKey(ready.sequence)))!==fingerprint)throw Error('Lost completion object');return ready;}
   const {anchor}=await read();
   if(p.sequence!==anchor.endSequence+1||p.previousDigest!==anchor.endDigest||p.baseSHA!==anchor.endCommit||p.sequence>maxEntries)throw Error('Append does not extend checkpoint');
   const pending={operationID:id,digest:fingerprint,sequence:p.sequence,baseSHA:p.baseSHA,commitSHA:p.commitSHA};
   await storage.transaction(async tx=>{
    const prior=await tx.get(pendingKey),tip=await tx.get(tipKey);
    if(prior&&canonical(prior)!==canonical(pending))throw Error('Unreconciled append blocks another operation');
    if(tip.sequence!==anchor.endSequence||tip.digest!==anchor.endDigest||tip.commitSHA!==anchor.endCommit)throw Error('Checkpoint moved');
    await tx.put(pendingKey,pending);
   });
   const observed=await completion.verify({operationID:id,repositoryID:bootstrap.repositoryID,entryPayloadDigest:await digest(p),baseSHA:p.baseSHA,commitSHA:p.commitSHA});
   if(!exact(observed,['operationID','repositoryID','entryPayloadDigest','baseSHA','commitSHA','promoted'])||observed.promoted!==true||observed.operationID!==id||observed.repositoryID!==bootstrap.repositoryID||observed.entryPayloadDigest!==await digest(p)||observed.baseSHA!==p.baseSHA||observed.commitSHA!==p.commitSHA)throw Error('Independent promotion completion denied');
   await putArchive(bucket,objectKey(p.sequence),request.entry);
   const receipt={operationID:id,repositoryID:bootstrap.repositoryID,sequence:p.sequence,digest:fingerprint,commitSHA:p.commitSHA};
   await storage.transaction(async tx=>{
    const saved=await tx.get(`checkpoint-complete:${id}`);if(saved){if(canonical(saved)!==canonical(receipt))throw Error('Receipt replacement');return;}
    const tip=await tx.get(tipKey);if(canonical(await tx.get(pendingKey))!==canonical(pending)||tip.sequence!==anchor.endSequence||tip.digest!==anchor.endDigest)throw Error('Checkpoint reservation changed');
    await tx.put(`checkpoint-index:${p.sequence}`,receipt);await tx.put(`checkpoint-complete:${id}`,receipt);
    await tx.put(tipKey,{sequence:p.sequence,digest:fingerprint,commitSHA:p.commitSHA});await tx.delete(pendingKey);
   });
   return receipt;
  }
 };
}
