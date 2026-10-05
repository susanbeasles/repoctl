import test from 'node:test';import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';import {recoveryJob,recoverySigner} from '../src/archive/recovery-job.mjs';
const object=(type,body)=>{const bytes=Buffer.concat([Buffer.from(type+' '+Buffer.byteLength(body)+'\0'),Buffer.from(body)]);return {bytes,id:createHash('sha1').update(bytes).digest('hex')};};
test('recovery job verifies before signing, reads publication back and always cleans restore',async()=>{
 const tree=object('tree',''),commit=object('commit','tree '+tree.id+'\nauthor test\ncommitter test\n\nmessage\n'),h='a'.repeat(64),intent={repositoryID:1,commitSHA:commit.id,sourceSHA:commit.id,treeSHA:tree.id,archiveDigests:[h]};
 const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);let clean=0,creates=0,stored;
 const options={policyDigest:h,clock:()=>1000,restore:{run:async()=>({cleanup:async()=>{clean++;}})},readerFor:async()=>({object:async({objectID})=>({archiveDigest:h,bytes:objectID===tree.id?tree.bytes:commit.bytes})}),signer:recoverySigner({keyID:'recovery',privateKey:pair.privateKey,publicKey:pair.publicKey}),publisher:{create:async(k,v)=>{creates++;stored=v;},get:async()=>stored}};
 assert.equal((await recoveryJob(options).run(intent)).published,true);assert.equal(clean,1);assert.equal(creates,1);
 await assert.rejects(recoveryJob({...options,publisher:{create:async()=>{},get:async()=>({})}}).run(intent),/readback/);assert.equal(clean,2);
 await assert.rejects(recoveryJob({...options,readerFor:async()=>({object:async()=>{throw Error('missing archive');}})}).run(intent),/missing archive/);assert.equal(clean,3);assert.equal(creates,1);
 await assert.rejects(recoveryJob(options).run({...intent,repositoryID:0}));assert.equal(clean,3);
});
