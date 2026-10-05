import test from 'node:test';import assert from 'node:assert/strict';
import {receiptService} from '../src/receipts/service.mjs';import {checkpointService} from '../src/checkpoint/service.mjs';
import {digest,promotionPayload} from '../src/ledger.mjs';
const a='a'.repeat(40),b='b'.repeat(40),c='c'.repeat(40),zero='0'.repeat(64),id='a'.repeat(64);
function memory(){const data=new Map();let tail=Promise.resolve();return {data,get:async k=>structuredClone(data.get(k)),put:async(k,v)=>data.set(k,structuredClone(v)),delete:async k=>data.delete(k),transaction(fn){const work=tail.then(async()=>{const backup=structuredClone(data);try{return await fn(this);}catch(e){data.clear();for(const [k,v]of backup)data.set(k,v);throw e;}});tail=work.catch(()=>{});return work;}};}
async function fixture(){
 const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),keyID=zero,storage=memory(),objects=new Map();
 const bucket={get:async k=>objects.has(k)?{text:async()=>objects.get(k),size:objects.get(k).length}:null,put:async(k,v)=>{if(objects.has(k))return null;objects.set(k,new TextDecoder().decode(v));return {};}};
 const intent={repository:'owner/repo',repositoryID:1,branch:'main',baseSHA:a,commitSHA:b,treeSHA:a},record={operation:{id},intent,trust:{}},view={record,recordDigest:await digest(record),ledgerPayload:promotionPayload({repositoryID:1,sequence:1,previousDigest:zero,baseSHA:a,commitSHA:b,sourceSHA:c,policyDigest:zero,evidenceDigest:zero,archiveDigests:[zero]}),approvalDigest:zero,enrollmentProofDigest:zero};
 let promoted=true,loseResponse=false,observations=0;
 const completion={verify:async r=>{observations++;return {...r,promoted};}},checkpoint=checkpointService({storage:memory(),bucket,bootstrap:{repositoryID:1,commitSHA:a,digest:zero},trustedKeys:new Map([[keyID,keys.publicKey]]),completion});await checkpoint.initialize();
 const config={storage,authority:{load:async()=>view},completion,checkpoint:{receipt:r=>checkpoint.receipt(r),append:async r=>{const result=await checkpoint.append(r);if(loseResponse){loseResponse=false;throw Error('Lost successful response');}return result;}},keyID,privateKey:keys.privateKey,publicKey:keys.publicKey};
 return {config,view,intent,record,storage,objects,checkpoint,service:receiptService(config),promoted:v=>{promoted=v;},lose:()=>{loseResponse=true;},observations:()=>observations};
}
test('signed receipt finalizes checkpoint and independent observation confirms authority record',async()=>{
 const f=await fixture(),r=await f.service.finalize({operationID:id,intent:f.intent});assert.equal(r.commitSHA,b);const observed=await f.service.observe({operationID:id,record:f.record});assert.equal(observed.receiptDigest,r.digest);assert.equal(observed.verified,true);assert.deepEqual(await f.service.finalize({operationID:id,intent:f.intent}),r);
});
test('lost append response retains exactly one signature and recovers after restart',async()=>{
 const f=await fixture();f.lose();await assert.rejects(f.service.finalize({operationID:id,intent:f.intent}));const saved=await f.storage.get(`receipt:${id}`);assert.equal(saved.state,'pending');const signature=saved.entry.signature;
 const retry=await receiptService(f.config).finalize({operationID:id,intent:f.intent});assert.equal(retry.digest,saved.entryDigest);assert.equal((await f.storage.get(`receipt:${id}`)).entry.signature,signature);assert.equal(f.observations(),2);
});
test('unpromoted, altered intent and missing retained ledger objects deny receipt success',async()=>{
 const f=await fixture();f.promoted(false);await assert.rejects(f.service.finalize({operationID:id,intent:f.intent}));assert.equal(await f.storage.get(`receipt:${id}`),undefined);f.promoted(true);await f.service.finalize({operationID:id,intent:f.intent});await assert.rejects(f.service.finalize({operationID:id,intent:{...f.intent,commitSHA:c}}));
 const path=[...f.objects.keys()].find(k=>k.includes('/entries/'));f.objects.delete(path);await assert.rejects(f.service.observe({operationID:id,record:f.record}));
});
test('concurrent finalization retains one envelope; receipt replacement is rejected',async()=>{
 const f=await fixture();const results=await Promise.allSettled([f.service.finalize({operationID:id,intent:f.intent}),f.service.finalize({operationID:id,intent:f.intent})]);assert.ok(results.some(r=>r.status==='fulfilled'));const first=await f.service.finalize({operationID:id,intent:f.intent}),saved=await f.storage.get(`receipt:${id}`);saved.entry.payload.commitSHA=c;await f.storage.put(`receipt:${id}`,saved);await assert.rejects(f.service.finalize({operationID:id,intent:f.intent}));assert.equal(first.commitSHA,b);
});

test('signing-key rotation preserves old receipts only with retained public verification key',async()=>{
 const f=await fixture(),first=await f.service.finalize({operationID:id,intent:f.intent}),next=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),nextID='1'.repeat(64);
 const rotated={...f.config,keyID:nextID,privateKey:next.privateKey,publicKey:next.publicKey,trustedKeys:new Map([[f.config.keyID,f.config.publicKey],[nextID,next.publicKey]])};
 assert.deepEqual(await receiptService(rotated).finalize({operationID:id,intent:f.intent}),first);
 rotated.trustedKeys=new Map([[nextID,next.publicKey]]);await assert.rejects(receiptService(rotated).finalize({operationID:id,intent:f.intent}));
});
