import {WorkerEntrypoint,DurableObject} from 'cloudflare:workers';
import {acceptedPolicyService} from './service.mjs';
import {boundJSON} from '../runtime/services.mjs';
const headers={'Cache-Control':'no-store'};
export class AcceptedPolicyCoordinator extends DurableObject{
 constructor(ctx,env){super(ctx,env);this.ctx=ctx;this.env=env;}
 async fetch(request){
  if(this.env.ACCEPTED_POLICY_ENABLED!=='true'||typeof this.env.POLICY_BOOTSTRAP_JSON!=='string'||typeof this.env.POLICY_HARDWARE?.fetch!=='function')return Response.json({error:'policy_not_configured'},{status:503,headers});
  try{
   const path=new URL(request.url).pathname;if(request.method!=='POST'||!['/v1/policy/admit','/v1/policy/current'].includes(path))throw Error('Invalid route');
   const reader=request.body?.getReader();if(!reader)throw Error('Missing input');let n=0,chunks=[];for(;;){const r=await reader.read();if(r.done)break;n+=r.value.length;if(n>70000){await reader.cancel();throw Error('Oversized input');}chunks.push(r.value);}const bytes=new Uint8Array(n);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
   const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
   const service=acceptedPolicyService({storage:this.ctx.storage,bootstrap:JSON.parse(this.env.POLICY_BOOTSTRAP_JSON),hardware:{verify:r=>boundJSON(this.env.POLICY_HARDWARE,'/v1/enrollment/verify',r)}});
   return Response.json(await (path.endsWith('/admit')?service.admit(body):service.current(body)),{headers});
  }catch{return Response.json({error:'policy_denied'},{status:403,headers});}
 }
}
export class AcceptedPolicyService extends WorkerEntrypoint{
 fetch(request){if(!this.env.ACCEPTED_POLICY_COORDINATOR)return Response.json({error:'policy_not_configured'},{status:503,headers});return this.env.ACCEPTED_POLICY_COORDINATOR.get(this.env.ACCEPTED_POLICY_COORDINATOR.idFromName('accepted-policy-v1')).fetch(request);}
}
export default {fetch(){return new Response('Not found',{status:404,headers});}};
