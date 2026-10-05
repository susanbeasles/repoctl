import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {readFile,mkdtemp,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import assert from 'node:assert/strict';
import {base64,signEntry,promotionPayload} from '../src/ledger.mjs';
const path=process.argv[2];if(!path)throw Error('Bundle required');const script=await readFile(path,'utf8'),persist=await mkdtemp(join(tmpdir(),'repoctl-checkpoint-'));
const a='a'.repeat(40),b='b'.repeat(40),c='c'.repeat(40),zero='0'.repeat(64),op='a'.repeat(64);
const key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),raw=await crypto.subtle.exportKey('raw',key.publicKey),keyID=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),b=>b.toString(16).padStart(2,'0')).join('');
const config={repositoryID:1,repository:'owner/repo',branch:'main',commitSHA:a,digest:zero,ledgerKeys:[{keyID,publicKeyX963:base64(raw)}]};
const entry=(await signEntry(promotionPayload({repositoryID:1,sequence:1,previousDigest:zero,baseSHA:a,commitSHA:b,sourceSHA:c,policyDigest:zero,evidenceDigest:zero,archiveDigests:[zero]}),keyID,key.privateKey)).envelope;
let approved=false;
function runtime(){return new Miniflare({...convertV4MiniflareOptions({workers:[
 {name:'checkpoint',modules:true,script,compatibilityDate:'2026-10-04',bindings:{CHECKPOINT_ENABLED:'true',CHECKPOINT_CONFIG_JSON:JSON.stringify([config])},durableObjects:{CHECKPOINT_COORDINATOR:{className:'CheckpointCoordinator',useSQLite:true}},r2Buckets:['CHECKPOINT_OBJECTS'],serviceBindings:{CHECKPOINT_COMPLETION:async request=>Response.json({...await request.json(),promoted:approved})}},
 {name:'caller',modules:true,script:'export default {fetch(r,e){return e.CHECKPOINT.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{CHECKPOINT:{name:'checkpoint',entrypoint:'CheckpointService'}}}
]}),resourcePersistencePath:persist});}
let mf=runtime();
try{
 let caller=await mf.getWorker('caller');const call=(route,body)=>caller.fetch('https://internal/v1/checkpoint/'+route,{method:'POST',body:JSON.stringify(body)});
 assert.equal((await (await mf.getWorker('checkpoint')).fetch('https://public/v1/checkpoint/initialize',{method:'POST',body:'{"repositoryID":1}'})).status,404);
 assert.equal((await call('current',{repositoryID:1})).status,403);assert.equal((await call('initialize',{repositoryID:1})).status,200);
 assert.equal((await call('append',{operationID:op,entry})).status,403);
 await mf.dispose();mf=runtime();caller=await mf.getWorker('caller');approved=true;
 assert.equal((await call('append',{operationID:'b'.repeat(64),entry})).status,403);
 const response=await call('append',{operationID:op,entry});assert.equal(response.status,200);const receipt=await response.json();
 assert.deepEqual(await (await call('append',{operationID:op,entry})).json(),receipt);
 assert.equal((await (await call('current',{repositoryID:1})).json()).endCommit,b);
 const bucket=await mf.getR2Bucket('CHECKPOINT_OBJECTS','checkpoint');const listed=await bucket.list();const object=listed.objects.find(o=>o.key.includes('/entries/'));assert.ok(object);assert.equal(JSON.parse(await (await bucket.get(object.key)).text()).payload.commitSHA,b);
 console.log('PASS: real workerd SQLite/R2 checkpoint, public ingress closed, signed append, failed-confirmation reservation survives restart and exact retry');
}finally{await mf.dispose();await rm(persist,{recursive:true,force:true});}
