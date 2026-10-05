import test from 'node:test';import assert from 'node:assert/strict';
import {signEntry} from '../src/ledger.mjs';import {attestedRecovery} from '../src/archive/attested-recovery.mjs';
test('recovery attestation binds exact report, policy, signer and freshness',async()=>{
 const key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);const h='a'.repeat(64),intent={repositoryID:1,commitSHA:'1'.repeat(40),sourceSHA:'2'.repeat(40),treeSHA:'3'.repeat(40),archiveDigests:[h]};
 const report={protocol:'repoctl-archive-evidence-v1',intent,objects:[intent.commitSHA,intent.sourceSHA,intent.treeSHA].map((id,i)=>({objectID:id,type:i===2?'tree':'commit',archiveDigest:h,bytes:10,contentDigest:h})),recovery:{candidate:intent.commitSHA,source:intent.sourceSHA,tree:intent.treeSHA,reachableHistoryComplete:true,gitlinks:[],totalBytes:30}};
 let envelope=(await signEntry({kind:'archive-recovery',policyDigest:h,verifiedAt:1000,expiresAt:2000,report},'recovery',key.privateKey)).envelope;
 const make=(extra={})=>attestedRecovery({store:{get:async()=>envelope},trustedKeys:new Map([['recovery',key.publicKey]]),policyDigest:h,clock:()=>1500,...extra});
 assert.equal((await make().verify(intent)).recoveryVerified,true);
 await assert.rejects(make().verify({...intent,repositoryID:2}),/binding/);
 await assert.rejects(make({clock:()=>2000}).verify(intent),/lifetime/);
 await assert.rejects(make({policyDigest:'b'.repeat(64)}).verify(intent),/policy/);
 await assert.rejects(make({trustedKeys:new Map([['other',key.publicKey]])}).verify(intent),/signer/);
 envelope=structuredClone(envelope);envelope.payload.report.recovery.totalBytes=31;await assert.rejects(make().verify(intent),/signature/);
});
