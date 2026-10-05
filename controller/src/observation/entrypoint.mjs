import {WorkerEntrypoint} from 'cloudflare:workers';
import {brokerVerifier} from './broker-verifier.mjs';
import {completionObserver} from './completion.mjs';
import {githubObserver} from '../evidence/github-observer.mjs';
import {boundJSON} from '../runtime/services.mjs';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
async function observationRequest(env,request,brokerMode=false){
  if(env.OBSERVATION_ENABLED!=='true'||typeof env.OBSERVATION_CONFIG_JSON!=='string'||!['OBSERVATION_AUTHORITY','OBSERVATION_BROKER'].every(n=>typeof env[n]?.fetch==='function'))return Response.json({error:'observation_not_configured'},{status:503,headers});
  const route=new URL(request.url).pathname;
  if(request.method!=='POST'||!(brokerMode?['/v1/evidence/authorization','/v1/evidence/completion']:['/v1/ledger/promotion-observation']).includes(route))return Response.json({error:'not_found'},{status:404,headers});
  try{
   const reader=request.body?.getReader();if(!reader)throw Error('Missing input');let size=0;const chunks=[];for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>8192){await reader.cancel();throw Error('Oversized input');}chunks.push(value);}
   const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
   const configs=JSON.parse(env.OBSERVATION_CONFIG_JSON);if(!Array.isArray(configs)||configs.length>100)throw Error('Invalid observation inventory');
   const matches=configs.filter(c=>c.repositoryID===(body.repositoryID??body.operation?.repositoryID));if(matches.length!==1)throw Error('Repository not configured');const config=matches[0];
   if(Object.keys(config).sort().join()!==['repositoryID','repository','branch'].sort().join())throw Error('Unexpected configuration');
   const authority={load:async operationID=>{const view=await boundJSON(env.OBSERVATION_AUTHORITY,'/v1/authorization/completion-record',{operationID});
     if(view.record?.intent?.repository!==config.repository||view.record.intent.repositoryID!==config.repositoryID||view.record.intent.branch!==config.branch||view.record.operation?.targetRef!==`refs/heads/${config.branch}`)throw Error('Observed repository differs');return view;},check:r=>boundJSON(env.OBSERVATION_AUTHORITY,'/v1/authorization/check',r)};
   const github=githubObserver(config);
   const observer=completionObserver({authority,broker:{lease:operationID=>boundJSON(env.OBSERVATION_BROKER,'/v1/broker/lease-observation',{operationID})},github});
   if(brokerMode){const verifier=brokerVerifier({authority,completion:observer,github});return Response.json(await (route.endsWith('/authorization')?verifier.authorization(body):verifier.completion(body)),{headers});}
   return Response.json(await observer.verify(body),{headers});
  }catch{return Response.json({error:'promotion_observation_denied'},{status:403,headers});}
}
export class CompletionObservationService extends WorkerEntrypoint{fetch(request){return observationRequest(this.env,request);}}
export class BrokerVerificationService extends WorkerEntrypoint{fetch(request){return observationRequest(this.env,request,true);}}
export default {fetch(){return new Response('Not found',{status:404,headers});}};
