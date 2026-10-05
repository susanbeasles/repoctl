// Encrypted remote token journal. KEKs are remote secret bindings, never requests.
// No plaintext token enters durable storage; AAD binds ciphertext to its operation.
const encoder=new TextEncoder(),hash=/^[a-f0-9]{64}$/;
const b64=b=>btoa(String.fromCharCode(...b));
const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
export async function tokenCustody(storage,keyring) {
 if(!keyring||typeof keyring.active!=='string'||!keyring.keys?.[keyring.active])throw Error('Remote custody unavailable');
 const keys=new Map();
 for(const [id,value] of Object.entries(keyring.keys)){
  if(!/^[A-Za-z0-9_-]{1,80}$/.test(id)||typeof value!=='string')throw Error('Invalid custody keyring');
  const raw=decode(value);if(raw.length!==32)throw Error('AES-256 custody key required');
  keys.set(id,await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']));
 }
 const key=id=>{if(!hash.test(id))throw Error('Invalid custody operation');return `custody:${id}`;};
 const aad=id=>encoder.encode(`repoctl-installation-token-v1\n${id}`);
 return {
  async stage(id,token,expiresAt){
   if(typeof token!=='string'||!token.length||token.length>4096||!Number.isSafeInteger(expiresAt))throw Error('Invalid custody value');
   const iv=crypto.getRandomValues(new Uint8Array(12));
   const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(id)},keys.get(keyring.active),encoder.encode(token));
   await storage.transaction(async tx=>{
    const k=key(id);if(await tx.get(k))throw Error('Credential already retained');
    await tx.put(k,{version:1,keyID:keyring.active,iv:b64(iv),ciphertext:b64(new Uint8Array(ciphertext)),expiresAt,state:'retained',attempts:0});
   });
  },
  metadata:id=>storage.get(key(id)),
  async read(id){
   const record=await storage.get(key(id));if(!record||record.state!=='retained')return undefined;
   if(record.version!==1||!keys.has(record.keyID))throw Error('Custody key unavailable');
   const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(record.iv),additionalData:aad(id)},keys.get(record.keyID),decode(record.ciphertext));
   return {token:new TextDecoder('utf-8',{fatal:true}).decode(raw),expiresAt:record.expiresAt};
  },
  async retired(id,state){
   if(!['revoked','provider_expired'].includes(state))throw Error('Invalid retirement');
   await storage.transaction(async tx=>{const k=key(id),r=await tx.get(k);if(r)await tx.put(k,{version:r.version,keyID:r.keyID,expiresAt:r.expiresAt,state});});
  },
  async failed(id){await storage.transaction(async tx=>{const k=key(id),r=await tx.get(k);if(r?.state==='retained')await tx.put(k,{...r,attempts:r.attempts+1});});},
  async reencrypt(id){
   const plain=await this.read(id);if(!plain)return;
   const iv=crypto.getRandomValues(new Uint8Array(12));
   const ciphertext=b64(new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(id)},keys.get(keyring.active),encoder.encode(plain.token))));
   await storage.transaction(async tx=>{
    const k=key(id),r=await tx.get(k);if(r?.state!=='retained')return;
    await tx.put(k,{...r,keyID:keyring.active,iv:b64(iv),ciphertext});
   });
  }
 };
}
export function journaledCredentials(provider,custody,operationID) {
 return {
  async issueInstallationToken(request){
   const credential=await provider.issueInstallationToken(request);
   try{await custody.stage(operationID,credential.token,credential.expiresAt);}
   catch{await provider.revoke(credential.token).catch(()=>{});throw Error('Remote credential journal failed');}
   return credential;
  },
  revoke:token=>provider.revoke(token)
 };
}
// Only alarms or authenticated completion call this, never caller-supplied tokens.
export async function cleanupCredential(id,custody,provider,now=Math.floor(Date.now()/1000)) {
 const metadata=await custody.metadata(id);if(!metadata||metadata.state!=='retained')return 'absent';
 if(metadata.expiresAt<=now){await custody.retired(id,'provider_expired');return 'provider_expired';}
 const record=await custody.read(id);
 try{await provider.revoke(record.token);await custody.retired(id,'revoked');return 'revoked';}
 catch{await custody.failed(id);return 'retry';}
}
