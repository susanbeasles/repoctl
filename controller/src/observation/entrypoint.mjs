import {WorkerEntrypoint} from 'cloudflare:workers';
import {completionObserver} from './completion.mjs';
import {githubObserver} from '../evidence/github-observer.mjs';
import {boundJSON} from '../runtime/services.mjs';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
export class CompletionObservationService extends WorkerEntrypoint{
 async fetch(request){
  if(this.env.OBSERVATION_ENABLED!=='true'||typeof this.env.OBSERVATION_CONFIG_JSON!=='string'||!['OBSERVATION_AUTHORITY','OBSERVATION_BROKER'].every(n=>typeof this.env[n]?.fetch==='function'))return Response.json({error:'observation_not_configured'},{status:503,headers});
  if(request.method!=='POST'||new URL(request.url).pathname!=='/v1/ledger/promotion-observation')return Response.json({error:'not_found'},{status:404,headers});
  try{
   const reader=request.body?.getReader();if(!reader)throw Error('Missing input');let size=0;const chunks=[];for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>2048){await reader.cancel();throw Error('Oversized input');}chunks.push(value);}
   const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
   const configs=JSON.parse(this.env.OBSERVATION_CONFIG_JSON);if(!Array.isArray(configs)||configs.length>100)throw Error('Invalid observation inventory');
   const matches=configs.filter(c=>c.repositoryID===body.repositoryID);if(matches.length!==1)throw Error('Repository not configured');const config=matches[0];
   if(Object.keys(config).sort().join()!==['repositoryID','repository','branch'].sort().join())throw Error('Unexpected configuration');
   const observer=completionObserver({
    authority:{load:async operationID=>{const view=await boundJSON(this.env.OBSERVATION_AUTHORITY,'/v1/authorization/completion-record',{operationID});
     if(view.record?.intent?.repository!==config.repository||view.record.intent.repositoryID!==config.repositoryID||view.record.intent.branch!==config.branch||view.record.operation?.targetRef!==`refs/heads/${config.branch}`)throw Error('Observed repository differs');return view;}},
    broker:{lease:operationID=>boundJSON(this.env.OBSERVATION_BROKER,'/v1/broker/lease-observation',{operationID})},github:githubObserver(config)});
   return Response.json(await observer.verify(body),{headers});
  }catch{return Response.json({error:'promotion_observation_denied'},{status:403,headers});}
 }
}
export default {fetch(){return new Response('Not found',{status:404,headers});}};
