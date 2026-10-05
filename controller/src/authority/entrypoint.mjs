import {WorkerEntrypoint} from 'cloudflare:workers';
export {AuthorizationCoordinator} from './coordinator.mjs';
export class AuthorizationService extends WorkerEntrypoint {
 async fetch(request){
  if(!this.env.AUTHORIZATION_COORDINATOR)return Response.json({error:'authority_not_configured'},{status:503,headers:{'Cache-Control':'no-store'}});
  const id=this.env.AUTHORIZATION_COORDINATOR.idFromName('authority-admission-v1');
  return this.env.AUTHORIZATION_COORDINATOR.get(id).fetch(request);
 }
}
// Public ingress stays closed. Only explicitly configured private entrypoint
// service bindings can invoke AuthorizationService.
export default {fetch(){return new Response('Not found',{status:404});}};
