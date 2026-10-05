import {WorkerEntrypoint} from 'cloudflare:workers';
import {enrollmentApprovalService} from './service.mjs';
import {boundJSON} from '../runtime/services.mjs';
const headers={'Cache-Control':'no-store'};
export class EnrollmentApprovalCoordinator {
 constructor(ctx,env){this.ctx=ctx;this.env=env;}
 async fetch(request){
  if(this.env.ENROLLMENT_APPROVAL_ENABLED!=='true'||!['ENROLLMENT_TRUST','ENROLLMENT_HARDWARE'].every(k=>typeof this.env[k]?.fetch==='function'))return Response.json({error:'approval_not_configured'},{status:503,headers});
  try{
   const path=new URL(request.url).pathname;if(request.method!=='POST'||!['/v1/enrollment/admit','/v1/enrollment/authorize','/v1/enrollment/renew'].includes(path))throw Error('Invalid route');
   const reader=request.body?.getReader();if(!reader)throw Error('Missing body');let size=0;const chunks=[];while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>8192){await reader.cancel();throw Error('Oversized request');}chunks.push(value);}
   const raw=new Uint8Array(size);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}const input=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
   const service=enrollmentApprovalService({storage:this.ctx.storage,trust:{current:keyID=>boundJSON(this.env.ENROLLMENT_TRUST,'/v1/enrollment/trust',{keyID})},hardware:{verify:body=>boundJSON(this.env.ENROLLMENT_HARDWARE,'/v1/enrollment/verify',body)}});
   return Response.json(await (path.endsWith('/admit')?service.admit(input):path.endsWith('/renew')?service.renew(input):service.authorize(input)),{headers});
  }catch{return Response.json({error:'enrollment_approval_denied'},{status:403,headers});}
 }
}
export class EnrollmentApprovalService extends WorkerEntrypoint {
 fetch(request){if(!this.env.ENROLLMENT_APPROVAL_COORDINATOR)return Response.json({error:'approval_not_configured'},{status:503,headers});return this.env.ENROLLMENT_APPROVAL_COORDINATOR.get(this.env.ENROLLMENT_APPROVAL_COORDINATOR.idFromName('enrollment-approval-v1')).fetch(request);}
}
export default {fetch(){return new Response('Not found',{status:404,headers});}};
