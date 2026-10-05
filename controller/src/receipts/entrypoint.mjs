import {WorkerEntrypoint,DurableObject} from 'cloudflare:workers';
import {receiptService} from './service.mjs';
import {boundJSON} from '../runtime/services.mjs';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const ready=env=>env.RECEIPTS_ENABLED==='true'&&typeof env.RECEIPT_SIGNING_KEY_JSON==='string'&&typeof env.RECEIPT_REPOSITORIES_JSON==='string'&&['RECEIPT_AUTHORITY','RECEIPT_COMPLETION','RECEIPT_CHECKPOINT'].every(n=>typeof env[n]?.fetch==='function');
async function input(request){const reader=request.body?.getReader();if(!reader)throw Error('Missing input');let n=0;const chunks=[];for(;;){const {done,value}=await reader.read();if(done)break;n+=value.length;if(n>70000){await reader.cancel();throw Error('Oversized input');}chunks.push(value);}const bytes=new Uint8Array(n);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
async function signer(env){
 const config=JSON.parse(env.RECEIPT_SIGNING_KEY_JSON);if(Object.keys(config).sort().join()!==['keyID','privateKeyPKCS8','publicKeyX963'].sort().join()||typeof config.privateKeyPKCS8!=='string'||config.privateKeyPKCS8.length>5000||typeof config.publicKeyX963!=='string'||config.publicKeyX963.length>100)throw Error('Invalid remote signer');
 const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0)),raw=decode(config.publicKeyX963),keyID=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),b=>b.toString(16).padStart(2,'0')).join('');if(keyID!==config.keyID)throw Error('Ledger signer fingerprint differs');
 const privateKey=await crypto.subtle.importKey('pkcs8',decode(config.privateKeyPKCS8),{name:'ECDSA',namedCurve:'P-256'},false,['sign']),publicKey=await crypto.subtle.importKey('raw',raw,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 const probe=new TextEncoder().encode('repoctl-ledger-key-check-v1');if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},publicKey,await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,probe),probe))throw Error('Ledger key pair differs');
 const trustedKeys=new Map([[keyID,publicKey]]),inventory=env.RECEIPT_VERIFICATION_KEYS_JSON?JSON.parse(env.RECEIPT_VERIFICATION_KEYS_JSON):[];
 if(!Array.isArray(inventory)||inventory.length>9)throw Error('Invalid historical ledger keys');
 for(const entry of inventory){if(Object.keys(entry).sort().join()!==['keyID','publicKeyX963'].sort().join()||typeof entry.publicKeyX963!=='string'||entry.publicKeyX963.length>100||trustedKeys.has(entry.keyID))throw Error('Invalid historical key');const bytes=decode(entry.publicKeyX963),fingerprint=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');if(fingerprint!==entry.keyID)throw Error('Historical key fingerprint differs');trustedKeys.set(entry.keyID,await crypto.subtle.importKey('raw',bytes,{name:'ECDSA',namedCurve:'P-256'},false,['verify']));}
 return {keyID,privateKey,publicKey,trustedKeys};
}
function target(env,body){const ids=JSON.parse(env.RECEIPT_REPOSITORIES_JSON),id=body.intent?.repositoryID??body.record?.intent?.repositoryID;if(!Array.isArray(ids)||!ids.length||ids.length>100||!ids.every(v=>Number.isSafeInteger(v)&&v>0)||!ids.includes(id))throw Error('Receipt target not configured');}
export class LedgerReceiptCoordinator extends DurableObject{
 constructor(ctx,env){super(ctx,env);this.ctx=ctx;this.env=env;}
 async fetch(request){
  if(!ready(this.env))return Response.json({error:'receipts_not_configured'},{status:503,headers});
  try{
   const body=await input(request);target(this.env,body);const env=this.env;
   const service=receiptService({storage:this.ctx.storage,...await signer(env),authority:{load:operationID=>boundJSON(env.RECEIPT_AUTHORITY,'/v1/authorization/completion-record',{operationID})},completion:{verify:r=>boundJSON(env.RECEIPT_COMPLETION,'/v1/ledger/promotion-observation',r)},checkpoint:{append:r=>boundJSON(env.RECEIPT_CHECKPOINT,'/v1/checkpoint/append',r),receipt:r=>boundJSON(env.RECEIPT_CHECKPOINT,'/v1/checkpoint/receipt',r)}});
   const path=new URL(request.url).pathname;if(request.method!=='POST')throw Error('Invalid method');
   if(path==='/v1/ledger/finalize')return Response.json(await service.finalize(body),{headers});
   if(path==='/v1/ledger/observe')return Response.json(await service.observe(body),{headers});throw Error('Unknown route');
  }catch{return Response.json({error:'receipt_denied_or_reconciliation_required'},{status:403,headers});}
 }
}
export class LedgerReceiptService extends WorkerEntrypoint{
 async fetch(request){
  if(!ready(this.env)||!this.env.LEDGER_RECEIPT_COORDINATOR)return Response.json({error:'receipts_not_configured'},{status:503,headers});
  try{const body=await input(request);if(!/^[a-f0-9]{64}$/.test(body.operationID??''))throw Error('Invalid operation');target(this.env,body);return this.env.LEDGER_RECEIPT_COORDINATOR.get(this.env.LEDGER_RECEIPT_COORDINATOR.idFromName(body.operationID)).fetch(new Request(request.url,{method:request.method,body:JSON.stringify(body)}));}catch{return Response.json({error:'receipt_denied'},{status:403,headers});}
 }
}
export default {fetch(){return new Response('Not found',{status:404,headers});}};
