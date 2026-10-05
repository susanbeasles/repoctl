import {WorkerEntrypoint} from 'cloudflare:workers';
import {admissionEvidence} from './admission.mjs';
import {candidateEvidence} from './candidate.mjs';
import {githubObserver} from './github-observer.mjs';
import {boundJSON} from '../runtime/services.mjs';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
async function read(request){
 const reader=request.body?.getReader();if(!reader)throw Error('Missing input');let n=0;const chunks=[];
 for(;;){const {done,value}=await reader.read();if(done)break;n+=value.length;if(n>80000){await reader.cancel();throw Error('Oversized input');}chunks.push(value);}
 const bytes=new Uint8Array(n);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
export class AdmissionEvidenceService extends WorkerEntrypoint {
 async fetch(request){
  if(this.env.EVIDENCE_ENABLED!=='true'||typeof this.env.EVIDENCE_CONFIG_JSON!=='string'||!['EVIDENCE_POLICY','EVIDENCE_HISTORY','EVIDENCE_ARCHIVES'].every(n=>typeof this.env[n]?.fetch==='function'))return Response.json({error:'evidence_not_configured'},{status:503,headers});
  if(request.method!=='POST'||new URL(request.url).pathname!=='/v1/evidence/admission')return Response.json({error:'not_found'},{status:404,headers});
  try{
   const body=await read(request),configs=JSON.parse(this.env.EVIDENCE_CONFIG_JSON);
   if(!Array.isArray(configs)||configs.length>100)throw Error('Invalid configuration');
   const matches=configs.filter(c=>c.repositoryID===body.repositoryID);if(matches.length!==1)throw Error('Repository not configured');const config=matches[0];
   if(Object.keys(config).sort().join()!==['repositoryID','repository','targetRef','policyDigest','requiredChecks','actorIDs'].sort().join())throw Error('Unexpected configuration');
   const policy={current:async repositoryID=>{
    const accepted=await boundJSON(this.env.EVIDENCE_POLICY,'/v1/policy/current',{repositoryID});
    if(accepted.repositoryID!==config.repositoryID||accepted.repository!==config.repository||accepted.targetRef!==config.targetRef||accepted.digest!==config.policyDigest)throw Error('Evidence configuration differs from accepted policy');return accepted;
   }};
   if(!['refs/heads/main','refs/heads/master'].includes(config.targetRef))throw Error('Invalid target');
   const github=candidateEvidence({github:githubObserver({repository:config.repository,repositoryID:config.repositoryID,branch:config.targetRef.slice(11)}),requiredChecks:config.requiredChecks,actorIDs:config.actorIDs});
   const verifier=admissionEvidence({policy,github,
    history:{verify:intent=>boundJSON(this.env.EVIDENCE_HISTORY,'/v1/evidence/history',{intent})},
    archives:{verify:intent=>boundJSON(this.env.EVIDENCE_ARCHIVES,'/v1/evidence/archive',{intent})}});
   return Response.json(await verifier.verify(body),{headers});
  }catch{return Response.json({error:'evidence_denied'},{status:403,headers});}
 }
}
export default {fetch(){return new Response('Not found',{status:404,headers});}};
