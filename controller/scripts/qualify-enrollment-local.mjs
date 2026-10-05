import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';
import {generateKeyPairSync,verify} from 'node:crypto';import assert from 'node:assert/strict';
const bundle=process.argv[2];if(!bundle)throw Error('Usage: node scripts/qualify-enrollment-local.mjs DRY_RUN/entrypoint.js');
const script=await readFile(bundle,'utf8'),persist=await mkdtemp(join(tmpdir(),'repoctl-enrollment-test-'));
const pair=generateKeyPairSync('rsa',{modulusLength:2048}),pem=pair.privateKey.export({type:'pkcs1',format:'pem'});
const id='a'.repeat(64),approvalReference='b'.repeat(64),session={ownerID:34,role:'writer',expiresAt:Date.now()+300000,manifestDigest:'c'.repeat(64)};
let conversions=0,allowVerification=false,allowApproval=true;
const provider=async request=>{
 const u=new URL(request.url);assert.equal(u.origin,'https://api.github.com');
 if(u.pathname==='/app-manifests/synthetic-code/conversions'){conversions++;return Response.json({id:12,pem,webhook_secret:'synthetic-hook',client_secret:'synthetic-client'});}
 if(u.pathname==='/app'){assert.match(request.headers.get('Authorization'),/^Bearer /);return allowVerification?Response.json({id:12,owner:{id:34},permissions:{metadata:'read',contents:'write'},events:[]}):new Response('Denied',{status:403});}
 throw Error('Unexpected provider route');
};
const options=()=>({...convertV4MiniflareOptions({workers:[
 {name:'signer',modules:true,script,compatibilityDate:'2026-10-04',bindings:{APP_SIGNER_ENABLED:'true',APP_ENROLLMENT_ENABLED:'true',APP_CREDENTIAL_REFERENCE:id,APP_KEYRING_JSON:JSON.stringify({active:'test',keys:{test:Buffer.alloc(32,1).toString('base64')}})},durableObjects:{APP_SIGNER_COORDINATOR:{className:'AppSignerCoordinator',useSQLite:true}},serviceBindings:{APP_ENROLLMENT_APPROVAL:async request=>{const input=await request.json();return Response.json({...input,accepted:allowApproval,session});}},outboundService:provider},
 {name:'enrollment-caller',modules:true,script:`export default {fetch(request,env){return env.ENROLL.fetch(request);}};`,compatibilityDate:'2026-10-04',serviceBindings:{ENROLL:{name:'signer',entrypoint:'AppEnrollmentService'}}},
 {name:'broker-caller',modules:true,script:`export default {fetch(request,env){return env.SIGNER.fetch(request);}};`,compatibilityDate:'2026-10-04',serviceBindings:{SIGNER:{name:'signer',entrypoint:'AppSignerService'}}}
]}),resourcePersistencePath:persist});
let mf=new Miniflare(options());
async function call(worker,path,body){return (await mf.getWorker(worker)).fetch(`https://internal${path}`,{method:'POST',body:JSON.stringify(body)});}
const input={operationID:id,approvalReference};
try{
 assert.equal((await call('signer','/v1/enrollment/create',input)).status,404);
 assert.equal((await call('broker-caller','/v1/enrollment/create',input)).status,404);
 allowApproval=false;assert.equal((await call('enrollment-caller','/v1/enrollment/create',input)).status,403);allowApproval=true;
 assert.equal((await call('enrollment-caller','/v1/enrollment/create',input)).status,200);
 const callbacks=await Promise.all([call('enrollment-caller','/v1/enrollment/exchange',{...input,code:'synthetic-code'}),call('enrollment-caller','/v1/enrollment/exchange',{...input,code:'synthetic-code'})]);
 assert.equal(conversions,1);assert(callbacks.every(r=>r.status===403));
 const state=await call('enrollment-caller','/v1/enrollment/status',input);assert.equal((await state.json()).state,'staged');
 await mf.dispose();mf=new Miniflare(options());allowVerification=true;
 const recovered=await call('enrollment-caller','/v1/enrollment/reconcile',input);assert.equal(recovered.status,200);assert.equal((await recovered.json()).state,'active');assert.equal(conversions,1);
 const now=Math.floor(Date.now()/1000),signed=await call('broker-caller','/v1/github/app-jwt',{appID:12,issuedAt:now-60,expiresAt:now+300});assert.equal(signed.status,200);const {jwt}=await signed.json(),parts=jwt.split('.');assert(verify('RSA-SHA256',Buffer.from(parts.slice(0,2).join('.')),pair.publicKey,Buffer.from(parts[2],'base64url')));
 assert.equal((await call('enrollment-caller','/v1/github/app-jwt',{appID:12,issuedAt:now-60,expiresAt:now+300})).status,403);
 console.log('PASS: real workerd isolated entrypoints, single concurrent exchange, staged restart recovery and broker JWT signature');
}finally{await mf.dispose();await rm(persist,{recursive:true,force:true});}
