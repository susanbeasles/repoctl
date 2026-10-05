import test from 'node:test';import assert from 'node:assert/strict';
import {archiveEvidenceService} from '../src/archive/service.mjs';
test('archive service denies foreign repositories and bounds retained object reads',async()=>{
 let reads=0;const c={repositoryID:1,policyDigest:'a'.repeat(64),trustedKeys:new Map([['key',{}]])};
 const service=archiveEvidenceService({configurations:[c],bucket:{get:async()=>{reads++;return {size:5000000,arrayBuffer:()=>{throw Error('Must not read');}};}}});
 await assert.rejects(service.verify({repositoryID:2}),/not installed/);assert.equal(reads,0);
 const intent={repositoryID:1,commitSHA:'1'.repeat(40),sourceSHA:'2'.repeat(40),treeSHA:'3'.repeat(40),archiveDigests:['b'.repeat(64)]};
 await assert.rejects(service.verify(intent),/oversized/);assert.equal(reads,1);
 assert.throws(()=>archiveEvidenceService({configurations:[c,c],bucket:{get(){}}}),/configuration/);
});
