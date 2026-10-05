import test from 'node:test';import assert from 'node:assert/strict';
import {completionObserver} from '../src/observation/completion.mjs';
import {authorityCompletionView,brokerLeaseView} from '../src/observation/retained.mjs';
import {base64,digest,promotionPayload} from '../src/ledger.mjs';
const hash='a'.repeat(64),a='a'.repeat(40),b='b'.repeat(40),c='c'.repeat(40);
async function fixture(){
 const p={repositoryID:1,sequence:1,previousDigest:hash,baseSHA:a,commitSHA:b,sourceSHA:c,treeSHA:a,policyDigest:hash,evidenceDigest:hash,archiveDigests:[hash],nonce:hash,expiresAt:1000000};
 const record={operation:{id:hash,state:'authorized',operation:'promote',repositoryID:1,targetRef:'refs/heads/main',authorizationProvider:'hardware',hardwareEnrollmentVerified:true,policyDigest:hash,runID:5,runAttempt:1,expiresAt:1000},intent:{repository:'owner/repo',repositoryID:1,branch:'main',baseSHA:a,commitSHA:b,treeSHA:a},trust:{}};
 const payload=base64(new TextEncoder().encode(JSON.stringify(p))),bundle={owner:{payload},validator:{payload},executionOwner:{}};
 const saved={record,bundle,bundleDigest:await digest(bundle),enrollmentProofDigest:hash,state:'authorized'};
 const view=await authorityCompletionView(saved,hash),lease={operationID:hash,recordDigest:await digest(record),state:'issued',runID:5,runAttempt:1,expiresAt:900,providerExpiresAt:4000};
 const request={operationID:hash,repositoryID:1,entryPayloadDigest:await digest(promotionPayload(p)),baseSHA:a,commitSHA:b};
 const config={authority:{load:async()=>view},broker:{lease:async()=>lease},github:{tip:async()=>b,commit:async id=>({sha:id,parents:[{sha:a}],tree:{sha:a},verification:{verified:true,reason:'valid'}})}};
 return {p,saved,view,lease,request,config};
}
test('completion binds retained approval and issued lease; expiration does not erase completed work',async()=>{
 const f=await fixture();assert.deepEqual(await completionObserver(f.config).verify(f.request),{...f.request,promoted:true});
 f.lease.state='uncertain';assert.equal((await completionObserver(f.config).verify(f.request)).promoted,true);
});
test('completion rejects changed payload, foreign lease, unissued credentials and altered Git objects',async()=>{
 for(const mutate of [f=>f.request.entryPayloadDigest='b'.repeat(64),f=>f.lease.runAttempt=2,f=>f.lease.state='issuing',f=>delete f.lease.providerExpiresAt,f=>f.lease.recordDigest='b'.repeat(64),f=>f.config.github.tip=async()=>a,f=>f.config.github.commit=async id=>({sha:id,parents:[{sha:a},{sha:c}],tree:{sha:a},verification:{verified:true,reason:'valid'}}),f=>f.view.record.intent.treeSHA=b]){
 const f=await fixture();mutate(f);await assert.rejects(completionObserver(f.config).verify(f.request));}
});
test('retained views expose no token or JTI and reject tampered authority bytes',async()=>{
 const f=await fixture();f.saved.bundle.owner.payload='e30=';await assert.rejects(authorityCompletionView(f.saved,hash));
 const record=(await fixture()).saved.record,lease={operationID:hash,state:'uncertain',runID:'5',runAttempt:'1',expiresAt:900,providerExpiresAt:4000,jti:'private-jti',token:'secret'};
 const data=new Map([[`operation:${hash}`,record],[`lease:operation:${hash}`,lease]]),storage={transaction:fn=>fn({get:async k=>data.get(k)})};
 const view=await brokerLeaseView(storage,hash);assert.equal(JSON.stringify(view).includes('private-jti'),false);assert.equal(JSON.stringify(view).includes('secret'),false);
 delete lease.providerExpiresAt;await assert.rejects(brokerLeaseView(storage,hash));
});
test('moving main or retained approval during observation cannot confirm completion',async()=>{
 const f=await fixture();let n=0;f.config.github.tip=async()=>++n===1?b:a;await assert.rejects(completionObserver(f.config).verify(f.request));
 const g=await fixture();let reads=0;g.config.authority.load=async()=>++reads===1?g.view:{...g.view,approvalDigest:'b'.repeat(64)};await assert.rejects(completionObserver(g.config).verify(g.request));
});

import {brokerVerifier} from '../src/observation/broker-verifier.mjs';
test('broker pre-write verification repeats current authority and exact fast-forward observations',async()=>{
 const f=await fixture();let checks=0;f.config.authority.check=async r=>{checks++;assert.deepEqual(r.record,undefined);return {operationID:hash,accepted:true};};f.config.github.tip=async()=>a;
 const verifier=brokerVerifier({authority:f.config.authority,github:f.config.github,completion:completionObserver(f.config)}),request={operationID:hash,operation:f.view.record.operation,intent:f.view.record.intent};
 assert.equal((await verifier.authorization(request)).verified,true);assert.equal(checks,1);
 f.config.authority.check=async()=>({operationID:hash,accepted:false});await assert.rejects(verifier.authorization(request));
});
test('broker completion verifies retained request and issued lease without minting authority',async()=>{
 const f=await fixture(),verifier=brokerVerifier({authority:f.config.authority,github:f.config.github,completion:completionObserver(f.config)}),request={operationID:hash,operation:f.view.record.operation,intent:f.view.record.intent};
 assert.equal((await verifier.completion(request)).verified,true);await assert.rejects(verifier.completion({...request,intent:{...request.intent,commitSHA:c}}));
 f.lease.state='issuing';await assert.rejects(verifier.completion(request));
});
