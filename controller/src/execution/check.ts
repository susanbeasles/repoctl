import {verifyExecutorOIDC} from '../authorization/oidc.mjs';
interface Operation {
 id: string; state: string; operation: string; expiresAt: number;
 authorizationProvider: string; hardwareEnrollmentVerified: boolean;
 policyRevision: number; policyDigest: string; targetRef: string;
 repositoryID: number; runID: number; runAttempt: number;
}
interface Lease {operationID: string;state: string;expiresAt: number;providerExpiresAt: number;runID: string|number;runAttempt: string|number}
interface Intent {repository: string; repositoryID: number; branch: string; baseSHA: string; commitSHA: string; treeSHA: string}
interface Services {
 operations: {read(id: string): Promise<Operation|undefined>;readLease(id: string): Promise<Lease|undefined>};
 jwks(): Promise<unknown>;executionIntent(id: string): Promise<Intent>;
 verifyAuthorization(operation: Operation): Promise<void>;
}
interface Trust {acceptedPolicyRevision: number;acceptedPolicyDigest: string;targetRef: string;repositoryIDs: number[];[key: string]: unknown}
export async function checkExecution(input: {operationID: string;oidcToken: string},services: Services,trust: Trust,clock=()=>Math.floor(Date.now()/1000)) {
 const id=input.operationID;
 if(typeof id!=='string'||!/^[a-f0-9]{64}$/.test(id))throw Error('Invalid execution check');
 const saved=await services.operations.read(id),retained=await services.operations.readLease(id);
 const op=saved&&Object.freeze({...saved}),lease=retained&&Object.freeze({...retained});
 const now=clock();
 if(!op||op.id!==id||op.state!=='authorized'||op.operation!=='promote'||op.authorizationProvider!=='hardware'||op.hardwareEnrollmentVerified!==true||op.policyRevision!==trust.acceptedPolicyRevision||op.policyDigest!==trust.acceptedPolicyDigest||op.targetRef!==trust.targetRef||!trust.repositoryIDs?.includes(op.repositoryID)||!Number.isSafeInteger(op.expiresAt)||op.expiresAt<=now||op.expiresAt>now+300)throw Error('Current execution authorization denied');
 if(!lease||lease.operationID!==id||lease.state!=='issued'||![lease.expiresAt,lease.providerExpiresAt].every(v=>Number.isSafeInteger(v)&&v>now)||Number(lease.runID)!==op.runID||Number(lease.runAttempt)!==op.runAttempt)throw Error('No live issued execution lease');
 await verifyExecutorOIDC(input.oidcToken,trust,{operationID:id,runID:op.runID,runAttempt:op.runAttempt},await services.jwks(),now);
 const intent=Object.freeze({...await services.executionIntent(id)});
 if(Object.keys(intent).sort().join()!=='baseSHA,branch,commitSHA,repository,repositoryID,treeSHA'||intent.repositoryID!==op.repositoryID||!['main','master'].includes(intent.branch)||'refs/heads/'+intent.branch!==op.targetRef||typeof intent.repository!=='string'||!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(intent.repository)||![intent.baseSHA,intent.commitSHA,intent.treeSHA].every(v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v)))throw Error('Execution intent differs');
 // No issuance, replay reservation, ref write or credential response. Current
 // authority and independently verified baseline/fast-forward are rechecked.
 await services.verifyAuthorization(op);
 const current=await services.operations.read(id),issued=await services.operations.readLease(id);
 if(JSON.stringify(current)!==JSON.stringify(op)||!issued||issued.state!=='issued'||issued.operationID!==id||issued.expiresAt!==lease.expiresAt||issued.providerExpiresAt!==lease.providerExpiresAt||Number(issued.runID)!==op.runID||Number(issued.runAttempt)!==op.runAttempt||Math.min(op.expiresAt,lease.expiresAt,lease.providerExpiresAt)<=clock())throw Error('Execution authority changed or expired during check');
 return {operationID:id,verified:true,operationExpiresAt:Math.min(op.expiresAt,lease.expiresAt),intent};
}
