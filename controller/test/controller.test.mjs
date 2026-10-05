import {test} from 'node:test';
import assert from 'node:assert/strict';
import {canonical,digest,promotionPayload,signEntry,verifyEntry,verifyChain,putArchive} from '../src/ledger.mjs';
import {verifyWebhook,authorizeEvent} from '../src/webhook.mjs';
const hex=n=>n.repeat(64), sha=n=>n.repeat(40);
async function fixture(){
 const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const p=promotionPayload({repositoryID:7,sequence:1,previousDigest:hex('0'),baseSHA:sha('a'),commitSHA:sha('b'),sourceSHA:sha('c'),policyDigest:hex('d'),evidenceDigest:hex('e'),archiveDigests:[hex('f')]});
 const signed=await signEntry(p,'test-key',keys.privateKey);
 return {...signed,keys,trusted:new Map([['test-key',keys.publicKey]])};
}
test('signature rejects altered entry and unknown signer',async()=>{const f=await fixture();assert.equal(await verifyEntry(f.envelope,f.trusted),f.digest);await assert.rejects(verifyEntry({...f.envelope,payload:{...f.envelope.payload,commitSHA:sha('f')}},f.trusted));await assert.rejects(verifyEntry(f.envelope,new Map()));});
test('chain rejects truncation, wrong repo and broken parent',async()=>{const f=await fixture();const anchor={repositoryID:7,startDigest:hex('0'),startCommit:sha('a'),endSequence:1,endDigest:f.digest,endCommit:sha('b')};await verifyChain([f.envelope],f.trusted,anchor);await assert.rejects(verifyChain([],f.trusted,anchor));await assert.rejects(verifyChain([f.envelope],f.trusted,{...anchor,repositoryID:8}));await assert.rejects(verifyChain([f.envelope],f.trusted,{...anchor,startCommit:sha('c')}));});
test('encoding rejects unsafe numbers and is deterministic',()=>{assert.equal(canonical({b:2,a:1}),canonical({a:1,b:2}));assert.throws(()=>canonical({x:NaN}));assert.throws(()=>canonical({x:undefined}));});
test('webhook signature binds raw bytes',async()=>{const raw=new TextEncoder().encode('{"test":1}');const key=await crypto.subtle.importKey('raw',new TextEncoder().encode('test-secret'),{name:'HMAC',hash:'SHA-256'},false,['sign']);const signature=[...new Uint8Array(await crypto.subtle.sign('HMAC',key,raw))].map(x=>x.toString(16).padStart(2,'0')).join('');assert.equal(await verifyWebhook(raw,'sha256='+signature,'test-secret'),true);assert.equal(await verifyWebhook(new Uint8Array([1]),'sha256='+signature,'test-secret'),false);});
test('outsider, fork and foreign repository rejected',()=>{const policy={repositoryID:7,ownerID:8,actorIDs:[9]};const body={repository:{id:7,owner:{id:8},fork:false},sender:{id:9},pull_request:{head:{repo:{id:7,fork:false}}}};assert.equal(authorizeEvent('pull_request',body,policy),true);assert.equal(authorizeEvent('pull_request',{...body,sender:{id:10}},policy),false);assert.equal(authorizeEvent('pull_request',{...body,pull_request:{head:{repo:{id:70,fork:true}}}},policy),false);assert.equal(authorizeEvent('issue_comment',body,policy),false);});
test('archive retries identical object but rejects replacement',async()=>{const objects=new Map();let writes=0;const bucket={get:async k=>objects.has(k)?{text:async()=>objects.get(k)}:null,put:async(k,b)=>{writes++;objects.set(k,new TextDecoder().decode(b));return {};}};await putArchive(bucket,'test',{a:1});await putArchive(bucket,'test',{a:1});assert.equal(writes,1);await assert.rejects(putArchive(bucket,'test',{a:2}));});
import {RepositoryCoordinator} from '../src/worker.mjs';
test('coordinator retries pending archive and deduplicates delivery',async()=>{
 const state=new Map(),objects=new Map();let fail=true;
 const ctx={storage:{get:async k=>state.get(k),put:async(k,v)=>state.set(k,v)},blockConcurrencyWhile:async f=>f()};
 const env={ARCHIVE:{get:async k=>objects.has(k)?{text:async()=>objects.get(k)}:null,put:async(k,b)=>{if(fail){fail=false;throw new Error('simulated outage');}objects.set(k,new TextDecoder().decode(b));return {};}}};
 const coordinator=new RepositoryCoordinator(ctx,env);
 const record={delivery:'test-delivery',repositoryID:7,event:'push',payloadDigest:hex('a')};
 const request=()=>new Request('https://internal/ingest',{method:'POST',body:JSON.stringify(record)});
 await assert.rejects(coordinator.fetch(request()));
 assert.equal(state.get('delivery:test-delivery').state,'pending');
 assert.equal((await coordinator.fetch(request())).status,202);
 assert.equal((await (await coordinator.fetch(request())).json()).state,'duplicate');
 const conflict=await coordinator.fetch(new Request('https://internal/ingest',{method:'POST',body:JSON.stringify({...record,payloadDigest:hex('b')})}));
 assert.equal(conflict.status,409);
});
