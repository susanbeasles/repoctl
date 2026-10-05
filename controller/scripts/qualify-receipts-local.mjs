import {Miniflare,convertV4MiniflareOptions} from 'miniflare';import {readFile,mkdtemp,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import assert from 'node:assert/strict';
import {base64,digest,promotionPayload} from '../src/ledger.mjs';
const [receiptPath,checkpointPath]=process.argv.slice(2);if(!receiptPath||!checkpointPath)throw Error('Receipt and checkpoint bundles required');
const receiptScript=await readFile(receiptPath,'utf8'),checkpointScript=await readFile(checkpointPath,'utf8'),persist=await mkdtemp(join(tmpdir(),'repoctl-receipts-'));
const a='a'.repeat(40),b='b'.repeat(40),c='c'.repeat(40),zero='0'.repeat(64),id='a'.repeat(64);
const key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),raw=await crypto.subtle.exportKey('raw',key.publicKey),keyID=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),b=>b.toString(16).padStart(2,'0')).join('');
const signing={keyID,privateKeyPKCS8:base64(await crypto.subtle.exportKey('pkcs8',key.privateKey)),publicKeyX963:base64(raw)},bootstrap={repositoryID:1,repository:'owner/repo',branch:'main',commitSHA:a,digest:zero,ledgerKeys:[{keyID,publicKeyX963:base64(raw)}]};
const intent={repository:'owner/repo',repositoryID:1,branch:'main',baseSHA:a,commitSHA:b,treeSHA:a},record={operation:{id},intent,trust:{}},view={record,recordDigest:await digest(record),ledgerPayload:promotionPayload({repositoryID:1,sequence:1,previousDigest:zero,baseSHA:a,commitSHA:b,sourceSHA:c,policyDigest:zero,evidenceDigest:zero,archiveDigests:[zero]}),approvalDigest:zero,enrollmentProofDigest:zero};
let lose=true,checkpointCaller;
function runtime(){return new Miniflare({...convertV4MiniflareOptions({workers:[
 {name:'checkpoint',modules:true,script:checkpointScript,compatibilityDate:'2026-10-04',bindings:{CHECKPOINT_ENABLED:'true',CHECKPOINT_CONFIG_JSON:JSON.stringify([bootstrap])},durableObjects:{CHECKPOINT_COORDINATOR:{className:'CheckpointCoordinator',useSQLite:true}},r2Buckets:['CHECKPOINT_OBJECTS'],serviceBindings:{CHECKPOINT_COMPLETION:async r=>Response.json({...await r.json(),promoted:true})}},
 {name:'checkpoint-caller',modules:true,script:'export default {fetch(r,e){return e.SERVICE.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{SERVICE:{name:'checkpoint',entrypoint:'CheckpointService'}}},
 {name:'receipts',modules:true,script:receiptScript,compatibilityDate:'2026-10-04',bindings:{RECEIPTS_ENABLED:'true',RECEIPT_SIGNING_KEY_JSON:JSON.stringify(signing),RECEIPT_REPOSITORIES_JSON:'[1]'},durableObjects:{LEDGER_RECEIPT_COORDINATOR:{className:'LedgerReceiptCoordinator',useSQLite:true}},serviceBindings:{RECEIPT_AUTHORITY:async()=>Response.json(view),RECEIPT_COMPLETION:async r=>Response.json({...await r.json(),promoted:true}),RECEIPT_CHECKPOINT:async r=>{const response=await checkpointCaller.fetch(r);if(new URL(r.url).pathname.endsWith('/append')&&response.ok&&lose){lose=false;return new Response('Simulated lost append response',{status:503});}return response;}}},
 {name:'caller',modules:true,script:'export default {fetch(r,e){return e.SERVICE.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{SERVICE:{name:'receipts',entrypoint:'LedgerReceiptService'}}}
]}),resourcePersistencePath:persist});}
let mf=runtime();
try{
 checkpointCaller=await mf.getWorker('checkpoint-caller');let caller=await mf.getWorker('caller');
 const call=(route,body)=>caller.fetch('https://internal/v1/ledger/'+route,{method:'POST',body:JSON.stringify(body)});
 assert.equal((await checkpointCaller.fetch('https://internal/v1/checkpoint/initialize',{method:'POST',body:'{"repositoryID":1}'})).status,200);
 assert.equal((await (await mf.getWorker('receipts')).fetch('https://public/v1/ledger/finalize',{method:'POST',body:JSON.stringify({operationID:id,intent})})).status,404);
 assert.equal((await call('finalize',{operationID:id,intent})).status,403);
 const bucket=await mf.getR2Bucket('CHECKPOINT_OBJECTS','checkpoint'),objects=await bucket.list(),entryKey=objects.objects.find(o=>o.key.includes('/entries/')).key,stored=await (await bucket.get(entryKey)).text();
 await mf.dispose();mf=runtime();checkpointCaller=await mf.getWorker('checkpoint-caller');caller=await mf.getWorker('caller');
 const response=await call('finalize',{operationID:id,intent});assert.equal(response.status,200);const receipt=await response.json();assert.equal(receipt.digest,await digest(JSON.parse(stored)));
 const restartedBucket=await mf.getR2Bucket('CHECKPOINT_OBJECTS','checkpoint');assert.equal(await (await restartedBucket.get(entryKey)).text(),stored);
 assert.deepEqual(await (await call('finalize',{operationID:id,intent})).json(),receipt);assert.equal((await (await call('observe',{operationID:id,record})).json()).receiptDigest,receipt.digest);
 assert.equal((await call('finalize',{operationID:id,intent:{...intent,commitSHA:c}})).status,403);
 console.log('PASS: real workerd private receipt signing, SQLite/R2 checkpoint, lost append response survives restart without signature replacement');
}finally{await mf.dispose();await rm(persist,{recursive:true,force:true});}
