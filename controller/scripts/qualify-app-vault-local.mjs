// Synthetic credentials only. Runs AES-GCM, RSA imports and custody transitions
// inside actual workerd with SQLite Durable Object storage.
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {build} from 'esbuild';
import {generateKeyPairSync} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
const root=fileURLToPath(new URL('../',import.meta.url));
const pem=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({type:'pkcs1',format:'pem'});
const source=`import {appVault} from './src/enrollment/app-vault.mjs';
export class TestVault {
 constructor(ctx,env){this.ctx=ctx;this.env=env;}
 async fetch(){
 const id='a'.repeat(64),ring={active:'one',keys:{one:btoa(String.fromCharCode(...new Uint8Array(32).fill(1)))}};
 const v=await appVault(this.ctx.storage,ring);
 await v.stage(id,{appID:12,ownerID:34,role:'writer',privateKey:this.env.TEST_PEM,webhookSecret:'test-hook',clientSecret:'test-client'});
 const stored=JSON.stringify([...await this.ctx.storage.list()]);
 if(stored.includes('PRIVATE KEY')||stored.includes('test-hook'))throw Error('Plaintext persisted');
 let denied=false;try{await v.sign(id,{appID:12,issuedAt:940,expiresAt:1300},()=>1000);}catch{denied=true;}if(!denied)throw Error('Staged key signed');
 await v.activate(id,async r=>({verified:true,appID:r.appID,ownerID:r.ownerID,role:r.role,digest:'c'.repeat(64)}));
 const jwt=await v.sign(id,{appID:12,issuedAt:940,expiresAt:1300},()=>1000);if(jwt.split('.').length!==3)throw Error('Invalid JWT');
 await v.revoke(id);denied=false;try{await v.sign(id,{appID:12,issuedAt:940,expiresAt:1300},()=>1000);}catch{denied=true;}if(!denied)throw Error('Revoked key signed');
 return Response.json({passed:true,state:(await v.status(id)).state});
 }}
 export default {fetch(request,env){return env.VAULT.get(env.VAULT.idFromName('qualification')).fetch(request);}};`;
const compiled=await build({stdin:{contents:source,resolveDir:root,sourcefile:'qualification.mjs'},bundle:true,write:false,format:'esm',platform:'browser',target:'es2022'});
const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:compiled.outputFiles[0].text,compatibilityDate:'2026-10-04',bindings:{TEST_PEM:pem},durableObjects:{VAULT:{className:'TestVault',useSQLite:true}}}));
try{const response=await mf.dispatchFetch('https://local/');assert.equal(response.status,200);assert.deepEqual(await response.json(),{passed:true,state:'revoked'});console.log('PASS: real workerd SQLite App vault encrypts, activates, signs and retires synthetic credentials');}finally{await mf.dispose();}
