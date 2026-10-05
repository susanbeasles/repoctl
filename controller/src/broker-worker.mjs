import {WorkerEntrypoint} from 'cloudflare:workers';
export {default,RepositoryCoordinator,BrokerCoordinator} from './worker.mjs';

// Read-only private capability. Public routing above never forwards this path.
export class BrokerObservationService extends WorkerEntrypoint {
 async fetch(request){
  const headers={'Cache-Control':'no-store'};
  if(request.method!=='POST'||new URL(request.url).pathname!=='/v1/broker/lease-observation')return Response.json({error:'not_found'},{status:404,headers});
  if(!this.env.BROKER_COORDINATOR)return Response.json({error:'broker_not_configured'},{status:503,headers});
  return this.env.BROKER_COORDINATOR.get(this.env.BROKER_COORDINATOR.idFromName('authority-v1')).fetch(new Request('https://internal/v1/private/lease-observation',{method:'POST',body:request.body,duplex:'half'}));
 }
}
