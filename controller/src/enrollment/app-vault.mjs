import {importAppPrivateKey,appJWTSigner} from '../runtime/app-signer.mjs';
const enc=new TextEncoder(),dec=new TextDecoder('utf-8',{fatal:true});
const b64=x=>BufferlessEncode(new Uint8Array(x));
function BufferlessEncode(x){return btoa(String.fromCharCode(...x));}
const bytes=x=>Uint8Array.from(atob(x),c=>c.charCodeAt(0));
const positive=x=>Number.isSafeInteger(x)&&x>0;
const reference=x=>{if(typeof x!=='string'||! /^[a-f0-9]{64}$/.test(x))throw Error('Invalid credential reference');return `app-vault:${x}`;};
// Private service only. KEKs arrive through remote bindings, never request bodies.
export async function appVault(storage,keyring){
 if(!keyring?.keys?.[keyring.active])throw Error('Remote App custody unavailable');
 const keys=new Map();
 for(const [id,value] of Object.entries(keyring.keys)){
  if(!/^[A-Za-z0-9_-]{1,80}$/.test(id)||typeof value!=='string'||bytes(value).length!==32)throw Error('Invalid remote wrapping key');
  keys.set(id,await crypto.subtle.importKey('raw',bytes(value),'AES-GCM',false,['encrypt','decrypt']));
 }
 const aad=(id,r)=>enc.encode(JSON.stringify(['repoctl-app-vault-v1',id,r.appID,r.ownerID,r.role]));
 async function decrypt(id,r){
  if(r.version!==1||!keys.has(r.keyID))throw Error('App wrapping key unavailable');
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(r.iv),additionalData:aad(id,r)},keys.get(r.keyID),bytes(r.ciphertext))));
 }
 return {
  async stage(id,{appID,ownerID,role,privateKey,webhookSecret,clientSecret}){
   const k=reference(id);
   if(!positive(appID)||!positive(ownerID)||!['writer','validator','builder','release'].includes(role)||typeof privateKey!=='string'||privateKey.length>12000||typeof webhookSecret!=='string'||webhookSecret.length>4096||typeof clientSecret!=='string'||clientSecret.length>4096)throw Error('Invalid remote App credential');
   const r={version:1,appID,ownerID,role,keyID:keyring.active,state:'staged'};
   const iv=crypto.getRandomValues(new Uint8Array(12));
   r.iv=b64(iv);r.ciphertext=b64(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(id,r)},keys.get(r.keyID),enc.encode(JSON.stringify({privateKey,webhookSecret,clientSecret}))));
   await storage.transaction(async tx=>{if(await tx.get(k))throw Error('App credential already retained');await tx.put(k,r);});
   return {reference:id,appID,ownerID,role,state:r.state};
  },
  async activate(id,verify){
   const k=reference(id),r=await storage.get(k);if(!r||r.state!=='staged')throw Error('App credential not staged');
   const secret=await decrypt(id,r),key=await importAppPrivateKey(secret.privateKey);
   // Verifier is a trusted server adapter, never a caller supplied approval flag.
   const evidence=await verify({appID:r.appID,ownerID:r.ownerID,role:r.role,key});
   if(evidence?.verified!==true||evidence.appID!==r.appID||evidence.ownerID!==r.ownerID||evidence.role!==r.role||! /^[a-f0-9]{64}$/.test(evidence.digest))throw Error('App verification rejected');
   await storage.transaction(async tx=>{const current=await tx.get(k);if(JSON.stringify(current)!==JSON.stringify(r))throw Error('App credential changed during verification');await tx.put(k,{...r,state:'active',verificationDigest:evidence.digest});});
  },
  async sign(id,claims,clock){
   const k=reference(id),r=await storage.get(k);if(!r||r.state!=='active')throw Error('App credential not active');
   const secret=await decrypt(id,r),key=await importAppPrivateKey(secret.privateKey);
   const jwt=await appJWTSigner({appID:r.appID,key,clock})(claims);
   // Do not release a signature if retirement/rotation occurred during signing.
   if(JSON.stringify(await storage.get(k))!==JSON.stringify(r))throw Error('App credential changed during signing');
   return jwt;
  },
  async revoke(id){const k=reference(id);await storage.transaction(async tx=>{const r=await tx.get(k);if(!r)throw Error('Unknown App credential');await tx.put(k,{version:1,appID:r.appID,ownerID:r.ownerID,role:r.role,state:'revoked'});});},
  async status(id){const r=await storage.get(reference(id));return r?{reference:id,appID:r.appID,ownerID:r.ownerID,role:r.role,state:r.state}:undefined;},
  async reencrypt(id){
   const k=reference(id),r=await storage.get(k);if(!r||!['staged','active'].includes(r.state))throw Error('App credential unavailable');
   const secret=await decrypt(id,r),iv=crypto.getRandomValues(new Uint8Array(12));
   const next={...r,keyID:keyring.active,iv:b64(iv),ciphertext:b64(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(id,r)},keys.get(keyring.active),enc.encode(JSON.stringify(secret))))};
   await storage.transaction(async tx=>{if(JSON.stringify(await tx.get(k))!==JSON.stringify(r))throw Error('App credential changed during rotation');await tx.put(k,next);});
  }
 };
}
