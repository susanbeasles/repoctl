import {verifyExecutorOIDC} from '../authorization/oidc.mjs';
// Called inside the durable serialized operation boundary. Outcome is telemetry,
// not proof. Ref and receipt services are independent of executor assertions.
export async function reconcileExecution(input,services,trust,now=Math.floor(Date.now()/1000)){
 const op=await services.operations.read(input.operationID);
 const lease=await services.operations.readLease(input.operationID);
 if(!op||!lease||lease.operationID!==input.operationID||!['issued','issuing','uncertain','completed'].includes(lease.state))throw Error('No retained execution lease');
 await verifyExecutorOIDC(input.oidcToken,trust,{operationID:input.operationID,runID:op.runID,runAttempt:op.runAttempt},await services.jwks(),now);
 const intent=await services.executionIntent(input.operationID);
 const tip=await services.observe.tip(intent.repositoryID,intent.branch);
 if(tip!==intent.baseSHA&&tip!==intent.commitSHA){await services.operations.degraded(input.operationID);throw Error('Unexpected protected ref; investigation required');}
 if(tip===intent.baseSHA){await services.operations.uncertain(input.operationID);return {operationID:input.operationID,state:'not_promoted_requires_reconciliation'};}
 // Re-check candidate and journal, not expired owner authorization: finishing a
 // previously authorized successful ref update after expiry is reconciliation.
 await services.verifyCompletion(op,intent,lease);
 const receipt=await services.receipts.finalize(input.operationID,intent); // signed + idempotent
 await services.operations.completed(input.operationID,receipt);
 return {operationID:input.operationID,state:'promoted',commitSHA:intent.commitSHA,receiptDigest:receipt.digest};
}
