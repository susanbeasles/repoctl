// Local workerd/SQLite qualification. No GitHub/Cloudflare account or credentials.
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
const state=await readFile(new URL('../src/runtime/state.mjs',import.meta.url),'utf8');
const script=state+`
export class Probe {
 constructor(ctx){this.ctx=ctx;}
 async fetch(request){
  const id='a'.repeat(64),operations=durableOperations(this.ctx.storage);
  if(new URL(request.url).pathname==='/reserve'){
   const now=Math.floor(Date.now()/1000);
   await operations.retain({operation:{id,state:'authorized',expiresAt:now+200,runID:60,runAttempt:1},intent:{},trust:{}});
   await operations.reserve({operationID:id,jti:'local-sqlite-replay',runID:'60',runAttempt:'1',state:'issuing',expiresAt:now+100});
   return Response.json({state:(await operations.readLease(id)).state,alarm:await this.ctx.storage.getAlarm()});
  }
  let blocked=false;
  try{await operations.reserve({operationID:id,jti:'local-sqlite-replay',runID:'60',runAttempt:'1',state:'issuing',expiresAt:Math.floor(Date.now()/1000)+100});}catch{blocked=true;}
  return Response.json({blocked});
 }
 async alarm(){}
}
export default {fetch(request,env){return env.STATE.get(env.STATE.idFromName('test')).fetch(request);}};
`;
const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script,compatibilityDate:'2026-10-04',durableObjects:{STATE:{className:'Probe',useSQLite:true}}}));
try{
 const first=await mf.dispatchFetch('https://local/reserve');assert.equal(first.status,200);const body=await first.json();assert.equal(body.state,'issuing');assert.ok(body.alarm>Date.now());
 const second=await mf.dispatchFetch('https://local/replay');assert.equal((await second.json()).blocked,true);
 console.log('PASS: real workerd SQLite transaction, atomic alarm and replay reservation');
}finally{await mf.dispose();}
