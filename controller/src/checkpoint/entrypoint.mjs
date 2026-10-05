import {WorkerEntrypoint,DurableObject} from 'cloudflare:workers';
import {checkpointService} from './service.mjs';
import {historyEvidence} from '../evidence/history.mjs';
import {githubObserver} from '../evidence/github-observer.mjs';
import {boundJSON} from '../runtime/services.mjs';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
async function input(request){
 const reader=request.body?.getReader();if(!reader)throw Error('Missing input');let n=0;const chunks=[];
 for(;;){const {done,value}=await reader.read();if(done)break;n+=value.length;if(n>70000){await reader.cancel();throw Error('Oversized input');}chunks.push(value);}
 const bytes=new Uint8Array(n);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
function configFor(env,id){
 const configs=JSON.parse(env.CHECKPOINT_CONFIG_JSON);if(!Array.isArray(configs)||configs.length>100)throw Error('Invalid checkpoint inventory');
 const found=configs.filter(c=>c.repositoryID===id);if(found.length!==1)throw Error('Unknown repository');const c=found[0];
 if(Object.keys(c).sort().join()!==['repositoryID','repository','branch','commitSHA','digest','ledgerKeys'].sort().join()||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(c.repository)||!['main','master'].includes(c.branch)||!Array.isArray(c.ledgerKeys)||!c.ledgerKeys.length||c.ledgerKeys.length>10)throw Error('Invalid checkpoint configuration');return c;
}
async function keysFor(config){
 const keys=new Map();for(const entry of config.ledgerKeys){
  if(Object.keys(entry).sort().join()!==['keyID','publicKeyX963'].sort().join()||keys.has(entry.keyID)||typeof entry.publicKeyX963!=='string'||entry.publicKeyX963.length>100)throw Error('Invalid ledger key');
  const bytes=Uint8Array.from(atob(entry.publicKeyX963),c=>c.charCodeAt(0)),id=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
  if(id!==entry.keyID)throw Error('Ledger key fingerprint differs');keys.set(id,await crypto.subtle.importKey('raw',bytes,{name:'ECDSA',namedCurve:'P-256'},false,['verify']));
 }return keys;
}
const ready=env=>env.CHECKPOINT_ENABLED==='true'&&typeof env.CHECKPOINT_CONFIG_JSON==='string'&&env.CHECKPOINT_OBJECTS&&typeof env.CHECKPOINT_COMPLETION?.fetch==='function';
export class CheckpointCoordinator extends DurableObject{
 constructor(ctx,env){super(ctx,env);this.ctx=ctx;this.env=env;}
 async fetch(request){
  if(!ready(this.env))return Response.json({error:'checkpoint_not_configured'},{status:503,headers});
  try{
   const body=await input(request),id=body.repositoryID??body.intent?.repositoryID??body.entry?.payload?.repositoryID,config=configFor(this.env,id),trustedKeys=await keysFor(config);
   const service=checkpointService({storage:this.ctx.storage,bucket:this.env.CHECKPOINT_OBJECTS,bootstrap:{repositoryID:id,commitSHA:config.commitSHA,digest:config.digest},trustedKeys,completion:{verify:r=>boundJSON(this.env.CHECKPOINT_COMPLETION,'/v1/ledger/promotion-observation',r)}});
   const path=new URL(request.url).pathname;let result;
   if(request.method!=='POST')throw Error('Invalid method');
   if(path==='/v1/checkpoint/initialize'){if(Object.keys(body).join()!=='repositoryID')throw Error('Unexpected fields');result=await service.initialize();}
   else if(path==='/v1/checkpoint/current'){if(Object.keys(body).join()!=='repositoryID')throw Error('Unexpected fields');result=await service.current(body);}
   else if(path==='/v1/checkpoint/entries'){if(Object.keys(body).sort().join()!==['repositoryID','startSequence','endSequence'].sort().join())throw Error('Unexpected fields');result=await service.entries(body);}
   else if(path==='/v1/checkpoint/receipt'){if(Object.keys(body).sort().join()!==['repositoryID','operationID'].sort().join())throw Error('Unexpected fields');result=await service.receipt(body);}
   else if(path==='/v1/checkpoint/append')result=await service.append(body);
   else if(path==='/v1/evidence/history'){
    if(Object.keys(body).join()!=='intent')throw Error('Unexpected fields');
    const verifier=historyEvidence({repositoryID:id,trustedKeys,checkpoint:{read:repositoryID=>service.current({repositoryID})},ledger:{read:r=>service.entries(r)},github:githubObserver({repository:config.repository,repositoryID:id,branch:config.branch})});result=await verifier.verify(body.intent);
   }else throw Error('Unknown route');
   return Response.json(result,{headers});
  }catch{return Response.json({error:'checkpoint_denied_or_recovery_required'},{status:403,headers});}
 }
}
export class CheckpointService extends WorkerEntrypoint{
 async fetch(request){
  if(!ready(this.env)||!this.env.CHECKPOINT_COORDINATOR)return Response.json({error:'checkpoint_not_configured'},{status:503,headers});
  try{
   const raw=await input(request),id=raw.repositoryID??raw.intent?.repositoryID??raw.entry?.payload?.repositoryID;
   if(!Number.isSafeInteger(id)||id<=0)throw Error('Invalid repository');configFor(this.env,id);
   return this.env.CHECKPOINT_COORDINATOR.get(this.env.CHECKPOINT_COORDINATOR.idFromName(`repository:${id}`)).fetch(new Request(request.url,{method:request.method,headers:{'Content-Type':'application/json'},body:JSON.stringify(raw)}));
  }catch{return Response.json({error:'checkpoint_denied'},{status:403,headers});}
 }
}
export default {fetch(){return new Response('Not found',{status:404,headers});}};
