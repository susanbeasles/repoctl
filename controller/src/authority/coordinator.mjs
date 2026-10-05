import {authorityRequest} from './service.mjs';
import {boundJSON} from '../runtime/services.mjs';
export class AuthorizationCoordinator {
 constructor(ctx,env){this.ctx=ctx;this.env=env;this.tail=Promise.resolve();}
 async fetch(request){
  const required=['ACCEPTED_POLICY','HARDWARE_ENROLLMENT_VERIFIER','AUTHORIZATION_EVIDENCE','AUTHORIZATION_RECEIPTS'];
  if(this.env.AUTHORIZATION_ENABLED!=='true'||!required.every(name=>typeof this.env[name]?.fetch==='function'))return Response.json({error:'authority_not_configured'},{status:503,headers:{'Cache-Control':'no-store'}});
  const env=this.env,services={storage:this.ctx.storage,
   policy:{current:repositoryID=>boundJSON(env.ACCEPTED_POLICY,'/v1/policy/current',{repositoryID})},
   hardware:{verify:request=>boundJSON(env.HARDWARE_ENROLLMENT_VERIFIER,'/v1/enrollment/verify',request)},
   evidence:{verify:request=>boundJSON(env.AUTHORIZATION_EVIDENCE,'/v1/evidence/admission',request)},
   reconciliation:{observe:request=>boundJSON(env.AUTHORIZATION_RECEIPTS,'/v1/ledger/observe',request)}};
  const work=this.tail.then(()=>authorityRequest(request,services));this.tail=work.catch(()=>{});return work;
 }
}
