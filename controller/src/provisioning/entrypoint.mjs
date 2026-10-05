import {WorkerEntrypoint,DurableObject} from 'cloudflare:workers';
import {registrationSessions} from './registration.mjs';
import {boundJSON} from '../runtime/services.mjs';
const headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'};
const esc=s=>s.replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;').replaceAll('>','&gt;');
async function input(request){const reader=request.body?.getReader();if(!reader)throw Error('Missing body');let size=0,chunks=[];for(;;){const r=await reader.read();if(r.done)break;size+=r.value.length;if(size>16384){await reader.cancel();throw Error('Oversized input');}chunks.push(r.value);}const raw=new Uint8Array(size);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}
export class RegistrationCoordinator extends DurableObject {
 constructor(ctx,env){super(ctx,env);this.ctx=ctx;this.env=env;}
 sessions(){
  const e=this.env,origin=new URL(e.REGISTRATION_ORIGIN);
  if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw Error('Invalid origin');
  return registrationSessions(this.ctx.storage,{
   create:async({operationID,approvalReference,reviewed})=>{
    const a=await boundJSON(e.APP_ENROLLMENT_APPROVAL,'/v1/enrollment/authorize',{operationID,approvalReference,action:'create'});
    if(a.accepted!==true||a.operationID!==operationID||a.approvalReference!==approvalReference||a.session?.ownerID!==Number(e.REGISTRATION_OWNER_ID)||a.session?.role!==reviewed.role||a.session?.manifestDigest!==reviewed.manifestDigest||reviewed.owner!==e.REGISTRATION_OWNER)throw Error('Reviewed plan not approved');
    return boundJSON(e.APP_ENROLLMENT,'/v1/enrollment/create',{operationID,approvalReference});
   },
   exchange:r=>boundJSON(e.APP_ENROLLMENT,'/v1/enrollment/exchange',r)
  },`${origin.origin}/github/callback`);
 }
 ready(){return this.env.REGISTRATION_ENABLED==='true'&&['APP_ENROLLMENT','APP_ENROLLMENT_APPROVAL'].every(k=>typeof this.env[k]?.fetch==='function')&&/^[1-9][0-9]*$/.test(this.env.REGISTRATION_OWNER_ID??'');}
 async control(request){
  if(!this.ready())return Response.json({error:'registration_not_configured'},{status:503,headers});
  try{
   const path=new URL(request.url).pathname;
   if(request.method!=='POST'||!['/v1/registration/create','/v1/registration/status','/v1/registration/reconcile'].includes(path))throw Error('Invalid route');
   const r=await input(request);
   if(path!=='/v1/registration/create'){
    if(!r||Object.keys(r).sort().join()!=='approvalReference,operationID'||![r.operationID,r.approvalReference].every(v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)))throw Error('Invalid recovery input');
    const retained=await this.ctx.storage.get(`registration:${r.operationID}`);if(!retained)throw Error('Unknown registration');
    const approved=await boundJSON(this.env.APP_ENROLLMENT_APPROVAL,'/v1/enrollment/authorize',{...r,action:path.split('/').pop()});
    if(approved.accepted!==true||approved.operationID!==r.operationID||approved.approvalReference!==r.approvalReference||approved.session?.ownerID!==Number(this.env.REGISTRATION_OWNER_ID)||approved.session?.manifestDigest!==retained.manifestDigest)throw Error('Recovery approval denied');
    const result=await boundJSON(this.env.APP_ENROLLMENT,`/v1/enrollment/${path.split('/').pop()}`,r);
    if(result.operationID!==r.operationID||!['ready','exchanging','staged','active'].includes(result.state))throw Error('Invalid recovery result');
    return Response.json({operationID:r.operationID,state:result.state,...(Number.isSafeInteger(result.appID)?{appID:result.appID}:{})},{headers});
   }
   if(!r||Object.keys(r).sort().join()!=='approvalReference,expiresAt,operationID,plan')throw Error('Invalid fields');
   return Response.json(await this.sessions().create(r.operationID,r.plan,r.approvalReference,r.expiresAt),{headers});
  }catch{return Response.json({error:'registration_denied_or_uncertain'},{status:403,headers});}
 }
 async fetch(request){
  if(!this.ready())return new Response('Not found',{status:404,headers});
  try{
   const u=new URL(request.url);if(request.method!=='GET'||u.origin!==new URL(this.env.REGISTRATION_ORIGIN).origin)throw Error('Invalid route');
   const s=this.sessions(),state=u.searchParams.get('state');
   if(u.pathname==='/github/register'){
    if([...u.searchParams.keys()].sort().join()!=='state')throw Error('Invalid fields');
    const id=await s.resolve(state),r=await s.launch(id,state);
    const manifest=new TextDecoder().decode(Uint8Array.from(atob(r.manifestBytes),c=>c.charCodeAt(0)));
    return new Response(`<!doctype html><meta charset="utf-8"><title>Register reviewed App</title><form action="https://github.com/settings/apps/new?state=${state}" method="post"><input type="hidden" name="manifest" value="${esc(manifest)}"><button>Register reviewed GitHub App</button></form>`,{headers:{...headers,'Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'none'; form-action https://github.com; frame-ancestors 'none'; base-uri 'none'"}});
   }
   if(u.pathname==='/github/callback'){
    if([...u.searchParams.keys()].sort().join()!=='code,state')throw Error('Invalid fields');
    await s.complete(await s.resolve(state),state,u.searchParams.get('code'));
    return new Response('GitHub App registered. Credentials retained by remote custody. Installation is a separate step.',{headers:{...headers,'Content-Type':'text/plain; charset=utf-8'}});
   }
   throw Error('Invalid route');
  }catch{return new Response('Registration denied or outcome uncertain. Use private custody reconciliation; do not retry registration.',{status:403,headers});}
 }
}
export class RegistrationControlService extends WorkerEntrypoint {
 fetch(request){if(!this.env.REGISTRATION_COORDINATOR)return new Response('Not configured',{status:503,headers});return this.env.REGISTRATION_COORDINATOR.get(this.env.REGISTRATION_COORDINATOR.idFromName('registration-v1')).control(request);}
}
export default {fetch(request,env){if(!env.REGISTRATION_COORDINATOR)return new Response('Not found',{status:404,headers});return env.REGISTRATION_COORDINATOR.get(env.REGISTRATION_COORDINATOR.idFromName('registration-v1')).fetch(request);}};
