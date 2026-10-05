// One deployment-wide authority object keeps operation and JTI reservations atomic.
// Storage transactions contain no network calls. Never delete replay tombstones.
const hash=/^[a-f0-9]{64}$/;
export function durableOperations(storage,clock=()=>Math.floor(Date.now()/1000)) {
 const key=id=>{if(!hash.test(id))throw Error('Invalid operation');return `operation:${id}`;};
 const leaseKey=id=>`lease:${key(id)}`;
 async function update(id,allowed,state,extra={}) {
  return storage.transaction(async tx=>{
   const k=leaseKey(id),lease=await tx.get(k);
   if(!lease||!allowed.includes(lease.state))throw Error('Invalid lease transition');
   await tx.put(k,{...lease,...extra,state});
  });
 }
 return {
  async retain(record) {
   const id=record?.operation?.id,k=key(id);
   // Admission itself is performed only by the trusted remote authority adapter.
   await storage.transaction(async tx=>{
    const existing=await tx.get(k);
    if(existing&&JSON.stringify(existing)!==JSON.stringify(record))throw Error('Retained operation collision');
    if(!existing)await tx.put(k,record);
   });
  },
  async record(id){return storage.get(key(id));},
  async read(id){return (await storage.get(key(id)))?.operation;},
  readLease:id=>storage.get(leaseKey(id)),
  usedJTI:async jti=>Boolean(await storage.get(`jti:${jti}`)),
  async reserve(lease) {
   if(typeof lease.jti!=='string'||lease.jti.length<8||lease.jti.length>200||lease.state!=='issuing'||lease.expiresAt<=clock())throw Error('Invalid reservation');
   await storage.transaction(async tx=>{
    const record=await tx.get(key(lease.operationID));
    if(!record||record.operation.state!=='authorized'||record.operation.expiresAt<=clock()||record.operation.runID!==Number(lease.runID)||record.operation.runAttempt!==Number(lease.runAttempt))throw Error('Authorization changed');
    const lk=leaseKey(lease.operationID),jk=`jti:${lease.jti}`;
    if(await tx.get(lk)||await tx.get(jk))throw Error('Lease or JTI already reserved');
    await tx.put(lk,lease);await tx.put(jk,{operationID:lease.operationID,expiresAt:lease.expiresAt});
    // Reservation and recovery alarm are committed together before provider I/O.
    const alarm=await tx.getAlarm();const next=lease.expiresAt*1000;
    if(alarm===null||alarm>next)await tx.setAlarm(next);
   });
  },
  async issued(lease){
   await storage.transaction(async tx=>{
    const k=leaseKey(lease.operationID),old=await tx.get(k);
    if(!old||old.state!=='issuing'||old.jti!==lease.jti||old.expiresAt!==lease.expiresAt)throw Error('Invalid issuance transition');
    await tx.put(k,{...old,...lease});
   });
  },
  markUncertain:id=>update(id,['issuing','issued','uncertain'],'uncertain'),
  uncertain:id=>update(id,['issuing','issued','uncertain'],'uncertain'),
  degraded:id=>update(id,['issuing','issued','uncertain','completed','degraded'],'degraded'),
  async completed(id,receipt){
   if(!hash.test(receipt?.digest??''))throw Error('Invalid receipt');
   await storage.transaction(async tx=>{
    const k=leaseKey(id),lease=await tx.get(k);
    if(!lease||lease.state==='degraded')throw Error('No completable lease');
    if(lease.state==='completed'&&lease.receiptDigest!==receipt.digest)throw Error('Receipt collision');
    await tx.put(k,{...lease,state:'completed',receiptDigest:receipt.digest});
   });
  }
 };
}
