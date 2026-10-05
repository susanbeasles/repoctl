import {test} from 'node:test';import assert from 'node:assert/strict';import {mkdtemp,realpath,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {createHash} from 'node:crypto';
import {recoveryJournal} from '../src/archive/recovery-journal.mjs';import {recoveryJob,recoverySigner} from '../src/archive/recovery-job.mjs';
test('restart reuses durably retained signed recovery report after lost upload response',async()=>{
 const dir=await realpath(await mkdtemp(join(tmpdir(),'recovery-journal-')));try{
 const object=(t,b)=>{const bytes=Buffer.from(t+' '+Buffer.byteLength(b)+'\0'+b);return {bytes,id:createHash('sha1').update(bytes).digest('hex')};},tree=object('tree',''),commit=object('commit','tree '+tree.id+'\nauthor test\ncommitter test\n\nmessage\n'),h='a'.repeat(64),intent={repositoryID:7,commitSHA:commit.id,sourceSHA:commit.id,treeSHA:tree.id,archiveDigests:[h]},pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);let restores=0,signatures=0,retained,fail=true;
 const signer=recoverySigner({keyID:'recovery',privateKey:pair.privateKey,publicKey:pair.publicKey}),original=signer.sign;signer.sign=async p=>{signatures++;return original(p);};
 const options={policyDigest:h,clock:()=>1000,signer,restore:{run:async()=>{restores++;return {cleanup:async()=>{}};}},readerFor:async()=>({object:async({objectID})=>({archiveDigest:h,bytes:objectID===tree.id?tree.bytes:commit.bytes})}),publisher:{create:async(k,e)=>{if(retained)assert.deepEqual(e,retained);retained=e;if(fail)throw Error('lost response');},get:async()=>retained}};
 await assert.rejects(recoveryJob({...options,journal:await recoveryJournal(dir)}).run(intent),/lost response/);fail=false;
 assert.equal((await recoveryJob({...options,journal:await recoveryJournal(dir)}).run(intent)).published,true);assert.equal(restores,1);assert.equal(signatures,1);
 await assert.rejects(recoveryJob({...options,clock:()=>999999,journal:await recoveryJournal(dir)}).run(intent));assert.equal(signatures,1);
 const j=await recoveryJournal(dir),id='b'.repeat(64);const results=await Promise.all([j.retain(id,{value:1}),j.retain(id,{value:2})]);assert.deepEqual(results[0],results[1]);
 }finally{await rm(dir,{recursive:true,force:true});}
});
