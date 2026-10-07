import {WorkerEntrypoint} from 'cloudflare:workers';
import {admissionEvidence} from './admission.mjs';
import {candidateEvidence} from './candidate.ts';
import {githubObserver} from './github-observer.mjs';
import {boundJSON} from '../runtime/services.mjs';
import type {CheckRule} from './candidate.ts';
interface Bindings {
 EVIDENCE_ENABLED?:string; EVIDENCE_CONFIG_JSON?:string;
 EVIDENCE_POLICY:Fetcher; EVIDENCE_HISTORY:Fetcher; EVIDENCE_ARCHIVES:Fetcher; EVIDENCE_SIGNATURES:Fetcher; EVIDENCE_BASELINE:Fetcher;
}
interface Configuration {
 repositoryID:number; repository:string; targetRef:string; policyDigest:string;
 requiredChecks:CheckRule[]; actorIDs:number[];
}
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
async function read(request:Request):Promise<unknown>{
 const reader=request.body?.getReader();if(!reader)throw Error('Missing input');let n=0;const chunks=[];
 for(;;){const {done,value}=await reader.read();if(done)break;n+=value.length;if(n>80000){await reader.cancel();throw Error('Oversized input');}chunks.push(value);}
 const bytes=new Uint8Array(n);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
 return JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:false}).decode(bytes));
}
export class AdmissionEvidenceService extends WorkerEntrypoint<Bindings> {
 async fetch(request:Request):Promise<Response>{
  if(this.env.EVIDENCE_ENABLED!=='true'||typeof this.env.EVIDENCE_CONFIG_JSON!=='string'||!(['EVIDENCE_POLICY','EVIDENCE_HISTORY','EVIDENCE_ARCHIVES','EVIDENCE_SIGNATURES','EVIDENCE_BASELINE'] as const).every(n=>typeof this.env[n]?.fetch==='function'))return Response.json({error:'evidence_not_configured'},{status:503,headers});
  if(request.method!=='POST'||new URL(request.url).pathname!=='/v1/evidence/admission')return Response.json({error:'not_found'},{status:404,headers});
  try{
   const body=await read(request),configs:unknown=JSON.parse(this.env.EVIDENCE_CONFIG_JSON);
   if(!body||typeof body!=='object'||!('repositoryID' in body))throw Error('Invalid repository request');
   if(!Array.isArray(configs)||configs.length>100)throw Error('Invalid configuration');
   const matches=configs.filter((c):c is Configuration=>!!c&&typeof c==='object'&&c.repositoryID===body.repositoryID);if(matches.length!==1)throw Error('Repository not configured');const config=matches[0];
   if(Object.keys(config).sort().join()!==['repositoryID','repository','targetRef','policyDigest','requiredChecks','actorIDs'].sort().join())throw Error('Unexpected configuration');
   const policy={current:async (repositoryID:number)=>{
    const accepted=await boundJSON(this.env.EVIDENCE_POLICY,'/v1/policy/current',{repositoryID});
    if(accepted.repositoryID!==config.repositoryID||accepted.repository!==config.repository||accepted.targetRef!==config.targetRef||accepted.digest!==config.policyDigest)throw Error('Evidence configuration differs from accepted policy');return accepted;
   }};
   if(!['refs/heads/main','refs/heads/master'].includes(config.targetRef))throw Error('Invalid target');
   const github=candidateEvidence({repositoryID:config.repositoryID,signatures:{verify:candidate=>boundJSON(this.env.EVIDENCE_SIGNATURES,'/v1/candidate/verify',{candidate})},github:githubObserver({repository:config.repository,repositoryID:config.repositoryID,branch:config.targetRef.slice(11)}),requiredChecks:config.requiredChecks,actorIDs:config.actorIDs});
   const verifier=admissionEvidence({policy,github,baseline:{verify:(binding:unknown)=>boundJSON(this.env.EVIDENCE_BASELINE,'/v1/baseline/verify',{binding})},
    history:{verify:(intent:unknown)=>boundJSON(this.env.EVIDENCE_HISTORY,'/v1/evidence/history',{intent})},
    archives:{verify:(intent:unknown)=>boundJSON(this.env.EVIDENCE_ARCHIVES,'/v1/evidence/archive',{intent})}});
   return Response.json(await verifier.verify(body),{headers});
  }catch{return Response.json({error:'evidence_denied'},{status:403,headers});}
 }
}
export default {fetch(){return new Response('Not found',{status:404,headers});}};
