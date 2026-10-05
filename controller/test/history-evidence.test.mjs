import test from 'node:test';
import assert from 'node:assert/strict';
import {historyEvidence} from '../src/evidence/history.mjs';
import {signEntry,promotionPayload} from '../src/ledger.mjs';
const a='a'.repeat(40),b='b'.repeat(40),c='c'.repeat(40),zero='0'.repeat(64);
async function fixture(){
 const key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const signed=await signEntry(promotionPayload({repositoryID:1,sequence:1,previousDigest:zero,baseSHA:a,commitSHA:b,sourceSHA:c,policyDigest:zero,evidenceDigest:zero,archiveDigests:[zero]}),'ledger',key.privateKey);
 const anchor={repositoryID:1,startSequence:0,startDigest:zero,startCommit:a,endSequence:1,endDigest:signed.digest,endCommit:b};
 const entries=[signed.envelope];let reads=0;
 const config={repositoryID:1,trustedKeys:new Map([['ledger',key.publicKey]]),checkpoint:{read:async()=>{reads++;return structuredClone(anchor);}},ledger:{read:async()=>entries},github:{tip:async()=>b,commit:async id=>({sha:id,parents:[{sha:id===b?a:b}]})}};
 const intent={repositoryID:1,sequence:2,previousDigest:signed.digest,baseSHA:b,commitSHA:c};
 return {config,intent,entries,anchor};
}
test('history evidence extends independent checkpoint and verifies Git ancestry',async()=>{
 const f=await fixture();assert.equal((await historyEvidence(f.config).verify(f.intent)).historyVerified,true);
});
test('history evidence rejects truncation, signature substitution and self-selected anchors',async()=>{
 for(const mutate of [f=>f.entries.pop(),f=>f.entries[0].payload.commitSHA=c,f=>f.intent.checkpoint=f.anchor,f=>f.intent.previousDigest=zero,f=>f.anchor.repositoryID=2]){
  const f=await fixture();mutate(f);await assert.rejects(historyEvidence(f.config).verify(f.intent));
 }
});
test('history evidence rejects ledger/Git divergence, merges and checkpoint movement',async()=>{
 for(const mutate of [f=>f.config.github.commit=async id=>({sha:id,parents:[{sha:c}]}),f=>f.config.github.commit=async id=>({sha:id,parents:[{sha:a},{sha:b}]}),f=>f.config.github.tip=async()=>a,f=>{let n=0;f.config.checkpoint.read=async()=>({...f.anchor,endDigest:++n===1?f.anchor.endDigest:zero});}]){
  const f=await fixture();mutate(f);await assert.rejects(historyEvidence(f.config).verify(f.intent));
 }
});
