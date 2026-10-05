import test from 'node:test';import assert from 'node:assert/strict';import {signEntry} from '../src/ledger.mjs';import {recoveryPublication} from '../src/archive/publication.mjs';
test('publication authenticates before writes and confirms retained evidence',async()=>{
 const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']),h='a'.repeat(64),intent={repositoryID:1,commitSHA:'1'.repeat(40),sourceSHA:'2'.repeat(40),treeSHA:'3'.repeat(40),archiveDigests:[h]};
 const report={protocol:'repoctl-archive-evidence-v1',intent,objects:[intent.commitSHA,intent.sourceSHA,intent.treeSHA].map((id,i)=>({objectID:id,type:i===2?'tree':'commit',archiveDigest:h,bytes:10,contentDigest:h})),recovery:{candidate:intent.commitSHA,source:intent.sourceSHA,tree:intent.treeSHA,reachableHistoryComplete:true,gitlinks:[],totalBytes:30}};
 const envelope=(await signEntry({kind:'archive-recovery',policyDigest:h,verifiedAt:1000,expiresAt:2000,report},'recovery',pair.privateKey)).envelope;
 let data,writes=0;const bucket={get:async()=>data?{size:data.length,arrayBuffer:async()=>data.buffer.slice(data.byteOffset,data.byteOffset+data.byteLength)}:null,put:async(k,b)=>{writes++;data=b;return {};}};
 const service=recoveryPublication({bucket,configurations:[{repositoryID:1,policyDigest:h,trustedKeys:new Map([['recovery',pair.publicKey]])}],clock:()=>1500});
 const altered=structuredClone(envelope);altered.payload.report.recovery.totalBytes=31;await assert.rejects(service.publish({intent,envelope:altered}),/signature/);assert.equal(writes,0);
 assert.equal((await service.publish({intent,envelope})).published,true);await service.publish({intent,envelope});assert.equal(writes,1);
 await assert.rejects(service.publish({intent,envelope,extra:true}));assert.equal(writes,1);
});
