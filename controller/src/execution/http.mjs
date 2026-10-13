import {issueAuthority} from '../authorization/broker.mjs';
import {checkExecution} from './check.ts';
const headers={'Cache-Control':'no-store','Content-Type':'application/json','X-Content-Type-Options':'nosniff'};
export async function executionRequest(request,services,trust){
 if(request.method!=='POST')return new Response('{"error":"method_not_allowed"}',{status:405,headers});
 const path=new URL(request.url).pathname;
 if(!['/v1/execution/lease','/v1/execution/check','/v1/execution/complete'].includes(path))return new Response('{"error":"not_found"}',{status:404,headers});
 try{
  const reader=request.body?.getReader();if(!reader)throw Error('body');let size=0;const chunks=[];
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>24000){await reader.cancel();throw Error('size');}chunks.push(value);}
  const raw=new Uint8Array(size);let offset=0;for(const chunk of chunks){raw.set(chunk,offset);offset+=chunk.length;}
  const input=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  const fields=!path.endsWith('/complete')?['operationID','oidcToken']:['operationID','oidcToken','outcome'];
  if(Object.keys(input).sort().join()!==fields.sort().join()||!/^[a-f0-9]{64}$/.test(input.operationID??''))throw Error('schema');
  return await services.serialize(input.operationID,async()=>{
   if(path.endsWith('/check'))return Response.json(await checkExecution(input,services,trust),{headers});
   if(path.endsWith('/complete')){
    if(!['updated','failed','uncertain'].includes(input.outcome))throw Error('outcome');
    // Completion adapter independently authenticates fresh OIDC, reads GitHub
    // main, reconciles pending intent, and appends receipt. Never trust outcome.
    const result=await services.complete(input,trust);
    return Response.json(result,{headers});
   }
   const intent=await services.executionIntent(input.operationID);
   const retained=await services.operations.read(input.operationID);
   if(!intent||intent.repositoryID!==retained?.repositoryID||`refs/heads/${intent.branch}`!==retained?.targetRef||!['main','master'].includes(intent.branch)||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(intent.repository)||![intent.baseSHA,intent.commitSHA,intent.treeSHA].every(s=>/^[a-f0-9]{40}$/.test(s)))throw Error('intent');
   const grant=await issueAuthority(input,services,trust);
   // Return only fixed operation data from the retained controller intent.
   const safe={repository:intent.repository,repositoryID:intent.repositoryID,branch:intent.branch,baseSHA:intent.baseSHA,commitSHA:intent.commitSHA,treeSHA:intent.treeSHA};
   return Response.json({...grant,intent:safe},{headers});
  });
 }catch{return new Response('{"error":"execution_denied_or_reconciliation_required"}',{status:403,headers});}
}
