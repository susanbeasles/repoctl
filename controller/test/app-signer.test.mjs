import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {importAppPrivateKey,appJWTSigner} from '../src/runtime/app-signer.mjs';
for(const type of ['pkcs1','pkcs8'])test(`remote signer imports ${type} without extraction and constructs fixed JWT claims`,async()=>{
 const pair=generateKeyPairSync('rsa',{modulusLength:2048});
 const key=await importAppPrivateKey(pair.privateKey.export({type,format:'pem'}));assert.equal(key.extractable,false);await assert.rejects(crypto.subtle.exportKey('pkcs8',key));
 const sign=appJWTSigner({appID:12,key,clock:()=>1000});const token=await sign({appID:12,issuedAt:940,expiresAt:1300});const parts=token.split('.');assert.deepEqual(JSON.parse(Buffer.from(parts[1],'base64url')),{iss:'12',iat:940,exp:1300});
 const publicKey=await crypto.subtle.importKey('spki',pair.publicKey.export({type:'spki',format:'der'}),{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);assert.equal(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',publicKey,Buffer.from(parts[2],'base64url'),Buffer.from(parts.slice(0,2).join('.'))),true);
 await assert.rejects(sign({appID:13,issuedAt:940,expiresAt:1300}));await assert.rejects(sign({appID:12,issuedAt:940,expiresAt:9000}));await assert.rejects(sign({appID:12,issuedAt:940,expiresAt:1300,payload:'arbitrary'}));
});
