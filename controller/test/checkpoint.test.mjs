import test from 'node:test';import assert from 'node:assert/strict';
import {checkpointService} from '../src/checkpoint/service.mjs';
import {signEntry,promotionPayload} from '../src/ledger.mjs';
const a='a'.repeat(40),b='b'.repeat(40),c='c'.repeat(40),zero='0'.repeat(64),op='a'.repeat(64);
function memory(){let data=new Map(),tail=Promise.resolve(),fail=false;const api={data,get:async k=>structuredClone(data.get(k)),put:async(k,v)=>{if(fail&&k.startsWith('checkpoint-index:'))throw Error('State outage');data.set(k,structuredClone(v));},delete:async k=>data.delete(k),transaction(fn){const run=tail.then(async()=>{const prior=structuredClone(data);try{return await fn(api);}catch(e){data.clear();for(const [k,v]of prior)data.set(k,v);throw e;}});tail=run.catch(()=>{});return run;},fail:v=>{fail=v;}};return api;}
function bucket(){const data=new Map();let fail=false;return {data,fail:v=>{fail=v;},get:async k=>data.has(k)?{size:data.get(k).length,text:async()=>data.get(k)}:null,put:async(k,v)=>{if(fail)throw Error('R2 outage');if(data.has(k))return null;data.set(k,new TextDecoder().decode(v));return {etag:'verified-by-readback'};}};}
async function fixture(){
 const key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),storage=memory(),objects=bucket();let approved=true,calls=0;
 const config={storage,bucket:objects,bootstrap:{repositoryID:1,commitSHA:a,digest:zero},trustedKeys:new Map([['ledger',key.publicKey]]),completion:{verify:async request=>{calls++;return {...request,promoted:approved};}}};
 const make=async(sequence=1,previousDigest=zero,baseSHA=a,commitSHA=b)=> (await signEntry(promotionPayload({repositoryID:1,sequence,previousDigest,baseSHA,commitSHA,sourceSHA:c,policyDigest:zero,evidenceDigest:zero,archiveDigests:[zero]}),'ledger',key.privateKey)).envelope;
 const service=checkpointService(config);await service.initialize();return {config,storage,objects,service,make,approve:v=>{approved=v;},calls:()=>calls};
}
test('checkpoint retains signed sequence and exact retry without observing completion twice',async()=>{
 const f=await fixture(),entry=await f.make(),receipt=await f.service.append({operationID:op,entry});
 assert.deepEqual(await f.service.append({operationID:op,entry}),receipt);assert.equal(f.calls(),1);
 const anchor=await f.service.current({repositoryID:1});assert.equal(anchor.endCommit,b);assert.equal(anchor.endDigest,receipt.digest);
 const next=await f.make(2,receipt.digest,b,c);await f.service.append({operationID:'b'.repeat(64),entry:next});assert.equal((await f.service.current({repositoryID:1})).endSequence,2);
});
test('R2 and checkpoint transaction outages retain reservation and recover after restart',async()=>{
 for(const stage of ['r2','state']){
  const f=await fixture(),entry=await f.make();if(stage==='r2')f.objects.fail(true);else f.storage.fail(true);
  await assert.rejects(f.service.append({operationID:op,entry}));assert.equal((await f.service.current({repositoryID:1})).endSequence,0);
  await assert.rejects(f.service.append({operationID:'b'.repeat(64),entry}));
  f.objects.fail(false);f.storage.fail(false);const restarted=checkpointService(f.config);await restarted.append({operationID:op,entry});assert.equal((await restarted.current({repositoryID:1})).endSequence,1);
 }
});
test('checkpoint refuses unconfirmed promotion, altered objects, replaced operation and foreign history',async()=>{
 const f=await fixture(),entry=await f.make();f.approve(false);await assert.rejects(f.service.append({operationID:op,entry}));f.approve(true);await f.service.append({operationID:op,entry});
 await assert.rejects(f.service.append({operationID:op,entry:await f.make(2,'1'.repeat(64),b,c)}));
 await assert.rejects(f.service.current({repositoryID:2}));
 const path=[...f.objects.data.keys()].find(k=>k.includes('/entries/'));f.objects.data.set(path,JSON.stringify({...entry,payload:{...entry.payload,commitSHA:c}}));await assert.rejects(f.service.current({repositoryID:1}));
});
test('checkpoint rejects lost root/pointer, pointer rollback and changed bootstrap',async()=>{
 for(const mutate of [f=>f.storage.data.delete('checkpoint-root'),f=>f.storage.data.delete('checkpoint-tip'),f=>f.storage.data.set('checkpoint-tip',{sequence:0,digest:zero,commitSHA:a}),f=>f.config.bootstrap.commitSHA=c]){
 const f=await fixture();await f.service.append({operationID:op,entry:await f.make()});mutate(f);await assert.rejects(checkpointService(f.config).current({repositoryID:1}));}
 const f=await fixture();f.storage.data.clear();await assert.rejects(checkpointService(f.config).initialize());
});
