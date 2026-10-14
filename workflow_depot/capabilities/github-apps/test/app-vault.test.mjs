import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {appVault} from '../src/enrollment/app-vault.mjs';
const id='a'.repeat(64),other='b'.repeat(64);
const ring={active:'one',keys:{one:Buffer.alloc(32,1).toString('base64')}};
function storage(){const records=new Map();return {records,get:async k=>structuredClone(records.get(k)),put:async(k,v)=>records.set(k,structuredClone(v)),transaction:async fn=>fn({get:async k=>structuredClone(records.get(k)),put:async(k,v)=>records.set(k,structuredClone(v))})};}
const credential=()=>({appID:12,ownerID:34,role:'writer',privateKey:generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({type:'pkcs1',format:'pem'}),webhookSecret:'sensitive-hook',clientSecret:'sensitive-client'});
const verified=async r=>({verified:true,appID:r.appID,ownerID:r.ownerID,role:r.role,digest:'c'.repeat(64)});
const claims={appID:12,issuedAt:940,expiresAt:1300};
test('App vault persists ciphertext only; staged and revoked keys cannot sign',async()=>{
 const s=storage(),v=await appVault(s,ring),c=credential();await v.stage(id,c);
 const serialized=JSON.stringify([...s.records]);for(const secret of [c.privateKey,c.webhookSecret,c.clientSecret])assert.equal(serialized.includes(secret),false);
 await assert.rejects(v.sign(id,claims,()=>1000));await assert.rejects(v.stage(id,c));
 await v.activate(id,verified);assert.equal((await v.sign(id,claims,()=>1000)).split('.').length,3);
 await v.revoke(id);await assert.rejects(v.sign(id,claims,()=>1000));assert.equal(JSON.stringify([...s.records]).includes('ciphertext'),false);
});
test('App vault binds ciphertext to reference and identity and rejects unverified activation',async()=>{
 const s=storage(),v=await appVault(s,ring);await v.stage(id,credential());await assert.rejects(v.activate(id,async()=>({verified:true})));
 s.records.set(`app-vault:${other}`,structuredClone(s.records.get(`app-vault:${id}`)));await assert.rejects(v.activate(other,verified));
 s.records.get(`app-vault:${id}`).ownerID=35;await assert.rejects(v.activate(id,verified));
});
test('App vault rotates wrapping keys and retirement wins a concurrent verification',async()=>{
 const s=storage(),v=await appVault(s,ring);await v.stage(id,credential());await v.activate(id,verified);
 const next={active:'two',keys:{...ring.keys,two:Buffer.alloc(32,2).toString('base64')}},rotated=await appVault(s,next);await rotated.reencrypt(id);
 const current=await appVault(s,{active:'two',keys:{two:next.keys.two}});await current.sign(id,claims,()=>1000);await assert.rejects(v.sign(id,claims,()=>1000));
 await current.stage(other,credential());await assert.rejects(current.activate(other,async r=>{await current.revoke(other);return verified(r);}));assert.equal((await current.status(other)).state,'revoked');
});
