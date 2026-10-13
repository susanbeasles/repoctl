import {runtimeReady} from './runtime/services.mjs';
export {BrokerCoordinator} from './runtime/coordinator.mjs';
import {verifyWebhook, authorizeEvent} from './webhook.mjs';
import {digest, putArchive} from './ledger.mjs';

export default {
  async fetch(request, env) {
    const path=new URL(request.url).pathname;
    if(['/v1/execution/lease','/v1/execution/check','/v1/execution/complete'].includes(path)){
      const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
      if(request.method!=='POST')return Response.json({error:'method_not_allowed'},{status:405,headers});
      if(!runtimeReady(env)||!env.BROKER_COORDINATOR)return Response.json({error:'broker_not_configured'},{status:503,headers});
      // One namespace object spans all repositories to reserve JWT IDs globally.
      const id=env.BROKER_COORDINATOR.idFromName('authority-v1');
      return env.BROKER_COORDINATOR.get(id).fetch(request);
    }
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/github/webhook') return new Response('Not found',{status:404});
    if (!env.GITHUB_WEBHOOK_SECRET || !env.REPOSITORIES_JSON) return new Response('Controller not configured',{status:503});
    const limit = 1024*1024;
    if (Number(request.headers.get('content-length')) > limit) return new Response('Too large',{status:413});
    const reader = request.body?.getReader();
    if (!reader) return new Response('Missing body',{status:400});
    let length = 0; const parts=[];
    while (true) { const {done,value}=await reader.read(); if(done)break; length+=value.length; if(length>limit){await reader.cancel();return new Response('Too large',{status:413});}parts.push(value); }
    const raw = new Uint8Array(length); let offset=0; for(const part of parts){raw.set(part,offset);offset+=part.length;}
    if (!await verifyWebhook(raw, request.headers.get('x-hub-signature-256'), env.GITHUB_WEBHOOK_SECRET)) return new Response('Invalid signature',{status:401});
    const delivery = request.headers.get('x-github-delivery');
    if (!/^[a-f0-9-]{36}$/i.test(delivery ?? '')) return new Response('Invalid delivery ID',{status:400});
    let body, policies;
    try {body=JSON.parse(new TextDecoder().decode(raw));policies=JSON.parse(env.REPOSITORIES_JSON);}catch{return new Response('Invalid JSON/configuration',{status:400});}
    const policy=policies.find(p=>p.repositoryID===body.repository?.id);
    const event=request.headers.get('x-github-event');
    if (!policy || !authorizeEvent(event,body,policy)) return new Response('Ignored',{status:202});
    const id=env.REPOSITORY_COORDINATOR.idFromName(String(policy.repositoryID));
    return env.REPOSITORY_COORDINATOR.get(id).fetch('https://internal/ingest',{method:'POST',body:JSON.stringify({delivery,event,repositoryID:policy.repositoryID,payloadDigest:await digest(body)})});
  }
};

export class RepositoryCoordinator {
  constructor(ctx,env){this.ctx=ctx;this.env=env;}
  async fetch(request){
    if(new URL(request.url).pathname!=='/ingest')return new Response('Not found',{status:404});
    const record=await request.json();
    // One repository's event bookkeeping is serialized. No GitHub writes yet.
    return this.ctx.blockConcurrencyWhile(async()=>{
      const key=`delivery:${record.delivery}`;
      const previous=await this.ctx.storage.get(key);
      if(previous && previous.payloadDigest!==record.payloadDigest)return new Response('Delivery collision',{status:409});
      if(previous?.state==='archived')return Response.json({state:'duplicate',promotion:'disabled'});
      await this.ctx.storage.put(key,{...record,state:'pending'});
      await putArchive(this.env.ARCHIVE,`events/${record.repositoryID}/${record.delivery}.json`,record);
      await this.ctx.storage.put(key,{...record,state:'archived'});
      return Response.json({state:'archived',promotion:'disabled'}, {status:202});
    });
  }
}
