import {WorkerEntrypoint} from 'cloudflare:workers';
import {archiveEvidenceService} from './service.mjs';
import {recoveryPublication} from './publication.mjs';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
async function configurations(raw){
 const list=JSON.parse(raw);if(!Array.isArray(list)||!list.length||list.length>100)throw Error('Invalid archive configuration');
 return await Promise.all(list.map(async c=>{
  if(Object.keys(c).sort().join()!==['repositoryID','policyDigest','keys'].sort().join()||!Array.isArray(c.keys)||!c.keys.length||c.keys.length>10)throw Error('Invalid archive trust');
  const trustedKeys=new Map();for(const k of c.keys){
   if(Object.keys(k).sort().join()!==['keyID','publicKeyX963'].sort().join()||!/^[a-f0-9]{64}$/.test(k.keyID??'')||trustedKeys.has(k.keyID))throw Error('Invalid recovery key');
   const bytes=Uint8Array.from(atob(k.publicKeyX963),x=>x.charCodeAt(0));if(bytes.length!==65||bytes[0]!==4)throw Error('Invalid recovery public key');
   const id=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join('');if(id!==k.keyID)throw Error('Recovery fingerprint differs');
   trustedKeys.set(id,await crypto.subtle.importKey('raw',bytes,{name:'ECDSA',namedCurve:'P-256'},false,['verify']));
  }return {repositoryID:c.repositoryID,policyDigest:c.policyDigest,trustedKeys};
 }));
}
export class ArchiveEvidenceService extends WorkerEntrypoint{
 async fetch(request){
  if(request.method!=='POST'||new URL(request.url).pathname!=='/v1/evidence/archive')return Response.json({error:'not_found'},{status:404,headers});
  if(this.env.ARCHIVE_EVIDENCE_ENABLED!=='true'||typeof this.env.ARCHIVE_EVIDENCE_CONFIG_JSON!=='string'||typeof this.env.RECOVERY_REPORTS?.get!=='function')return Response.json({error:'archive_not_configured'},{status:503,headers});
  try{
   const reader=request.body?.getReader();if(!reader)throw Error('Missing body');let size=0;const chunks=[];
   for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>16000){await reader.cancel();throw Error('Oversized intent');}chunks.push(value);}
   const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
   const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));if(Object.keys(body).join()!=='intent')throw Error('Unexpected input');
   const service=archiveEvidenceService({bucket:this.env.RECOVERY_REPORTS,configurations:await configurations(this.env.ARCHIVE_EVIDENCE_CONFIG_JSON)});
   return Response.json(await service.verify(body.intent),{headers});
  }catch{return Response.json({error:'archive_evidence_denied'},{status:403,headers});}
 }
}
export default {fetch(){return new Response('Not found',{status:404,headers});}};

// Separate named entrypoint: bind only to the trusted recovery upload gateway.
export class RecoveryPublicationService extends WorkerEntrypoint {
 async fetch(request){
  if(request.method!=='POST'||new URL(request.url).pathname!=='/v1/archive/recovery/publish')return Response.json({error:'not_found'},{status:404,headers});
  if(this.env.RECOVERY_PUBLICATION_ENABLED!=='true'||typeof this.env.ARCHIVE_EVIDENCE_CONFIG_JSON!=='string'||typeof this.env.RECOVERY_REPORTS?.put!=='function')return Response.json({error:'publication_not_configured'},{status:503,headers});
  try{
   const reader=request.body?.getReader();if(!reader)throw Error('Missing body');const chunks=[];let size=0;
   for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>4*1024*1024){await reader.cancel();throw Error('Oversized publication');}chunks.push(value);}
   const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
   const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
   return Response.json(await recoveryPublication({bucket:this.env.RECOVERY_REPORTS,configurations:await configurations(this.env.ARCHIVE_EVIDENCE_CONFIG_JSON)}).publish(body),{headers});
  }catch{return Response.json({error:'recovery_publication_denied'},{status:403,headers});}
 }
}
