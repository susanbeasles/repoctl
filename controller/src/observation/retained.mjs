import {digest,promotionPayload} from '../ledger.mjs';
const hash=/^[a-f0-9]{64}$/;
export async function authorityCompletionView(saved,operationID){
 if(!saved||!['authorized','completed'].includes(saved.state)||!hash.test(operationID??'')||saved.record?.operation?.id!==operationID||saved.record.operation.authorizationProvider!=='hardware'||saved.record.operation.hardwareEnrollmentVerified!==true||!hash.test(saved.enrollmentProofDigest??'')||saved.bundleDigest!==await digest(saved.bundle))throw Error('Invalid retained authority record');
 const raw=saved.bundle?.owner?.payload;if(typeof raw!=='string'||raw.length>24000||raw!==saved.bundle?.validator?.payload)throw Error('Invalid retained approval');
 const p=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(raw),c=>c.charCodeAt(0)))),record=saved.record;
 if(p.nonce!==operationID||p.repositoryID!==record.operation.repositoryID||p.policyDigest!==record.operation.policyDigest||p.baseSHA!==record.intent.baseSHA||p.commitSHA!==record.intent.commitSHA||p.treeSHA!==record.intent.treeSHA||p.repositoryID!==record.intent.repositoryID||`refs/heads/${record.intent.branch}`!==record.operation.targetRef)throw Error('Retained approval differs from execution');
 const payload=promotionPayload(p);
 return {record,recordDigest:await digest(record),ledgerPayload:payload,approvalDigest:await digest({owner:saved.bundle.owner,validator:saved.bundle.validator}),enrollmentProofDigest:saved.enrollmentProofDigest};
}
export async function brokerLeaseView(storage,operationID){
 if(!hash.test(operationID??''))throw Error('Invalid operation');
 return storage.transaction(async tx=>{
  const record=await tx.get(`operation:${operationID}`),lease=await tx.get(`lease:operation:${operationID}`);
  if(!record||!lease||record.operation.id!==operationID||lease.operationID!==operationID||!['issued','uncertain','completed'].includes(lease.state)||!Number.isSafeInteger(lease.providerExpiresAt)||lease.providerExpiresAt<=0||Number(lease.runID)!==record.operation.runID||Number(lease.runAttempt)!==record.operation.runAttempt||!Number.isSafeInteger(lease.expiresAt))throw Error('No successfully issued retained lease');
  return {operationID,recordDigest:await digest(record),state:lease.state,runID:Number(lease.runID),runAttempt:Number(lease.runAttempt),expiresAt:lease.expiresAt,providerExpiresAt:lease.providerExpiresAt};
 });
}
