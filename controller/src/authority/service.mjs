import {authorize,importPolicy} from './authorize.mjs';
import {canonical,digest} from '../ledger.mjs';
const headers={'Cache-Control':'no-store','Content-Type':'application/json','X-Content-Type-Options':'nosniff'};
const hash=/^[a-f0-9]{64}$/;
async function input(request){
 const reader=request.body?.getReader();if(!reader)throw Error('Missing body');let size=0;const chunks=[];
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>80000){await reader.cancel();throw Error('Body too large');}chunks.push(value);}
 const raw=new Uint8Array(size);let offset=0;for(const chunk of chunks){raw.set(chunk,offset);offset+=chunk.length;}
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
}
// Only the private Worker service entrypoint delegates to this object. The public
// Worker fetch router never forwards authorization/admission/policy requests.
export async function authorityRequest(request,services,now=Math.floor(Date.now()/1000)){
 if(request.method!=='POST')return Response.json({error:'method_not_allowed'},{status:405,headers});
 const path=new URL(request.url).pathname;
 if(!['/v1/authorization/admit','/v1/authorization/load','/v1/authorization/check','/v1/authorization/reconcile'].includes(path))return Response.json({error:'not_found'},{status:404,headers});
 try{
  const body=await input(request);
  if(path.endsWith('/admit'))return Response.json(await authorize(body,services,now),{headers});
  if(!hash.test(body?.operationID??''))throw Error('Invalid operation');
  const saved=await services.storage.get(`authority:${body.operationID}`);
  if(!saved)throw Error('Unknown operation');
  const record=saved.record;
  if(path.endsWith('/reconcile')){
   if(Object.keys(body).join()!=='operationID')throw Error('Unexpected fields');
   const receipt=await services.reconciliation.observe({operationID:body.operationID,record});
   if(receipt.operationID!==body.operationID||receipt.state!=='promoted'||receipt.commitSHA!==record.intent.commitSHA||!hash.test(receipt.receiptDigest??'')||receipt.verified!==true)throw Error('No independent completion');
   await services.storage.transaction(async tx=>{
    const key=`authority:${body.operationID}`,current=await tx.get(key);
    if(current.state==='completed'&&current.receiptDigest!==receipt.receiptDigest)throw Error('Completion collision');
    await tx.put(key,{...current,state:'completed',receiptDigest:receipt.receiptDigest});
    const pending=`pending-repository:${record.operation.repositoryID}`;
    if(await tx.get(pending)===body.operationID)await tx.delete(pending);
   });
   return Response.json({operationID:body.operationID,state:'completed',receiptDigest:receipt.receiptDigest},{headers});
  }
  if(path.endsWith('/load')){
   if(Object.keys(body).join()!=='operationID')throw Error('Unexpected fields');
   // Readback remains available after expiry for completion reconciliation. This
   // response alone cannot issue credentials; /check and broker enforce freshness.
   return Response.json(record,{headers});
  }
  if(saved.state!=='authorized')throw Error('Operation no longer authorized');
  if(Object.keys(body).sort().join()!==['operationID','operation','intent','trust'].sort().join()||canonical({operation:body.operation,intent:body.intent,trust:body.trust})!==canonical(record))throw Error('Retained record differs');
  // Re-evaluate signatures, current policy, hardware revocation and evidence.
  await authorize(saved.bundle,services,now);
  const policy=await importPolicy(await services.policy.current(record.operation.repositoryID));
  if(policy.digest!==record.operation.policyDigest||policy.revision!==record.operation.policyRevision||await digest(policy.executorTrust)!==await digest(record.trust))throw Error('Policy changed during verification');
  return Response.json({operationID:body.operationID,accepted:true},{headers});
 }catch{return Response.json({error:'authorization_denied_or_reconciliation_required'},{status:403,headers});}
}
