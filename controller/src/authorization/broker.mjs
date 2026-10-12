import {verifyExecutorOIDC} from './oidc.mjs';
const reject=message=>{throw new Error(message);};
// Execute under a per-operation serialized coordinator. Provider tokens are not
// ref-scoped: the central executor must stay isolated from application code.
async function retainedAuthorization(operationID,services,trust,now){
 if(!Number.isSafeInteger(trust.acceptedPolicyRevision)||trust.acceptedPolicyRevision<1||!/^[a-f0-9]{64}$/.test(trust.acceptedPolicyDigest??'')||!Number.isSafeInteger(trust.installationID)||trust.installationID<1||!Array.isArray(trust.repositoryIDs)||!trust.repositoryIDs.length||!trust.repositoryIDs.every(id=>Number.isSafeInteger(id)&&id>0)||!/^refs\/heads\/[A-Za-z0-9_./-]+$/.test(trust.targetRef??''))reject('Invalid remotely accepted broker policy');
 if(!/^[a-f0-9]{64}$/.test(operationID??''))reject('Invalid operation identity');
 const op=await services.operations.read(operationID);
 const fields=['id','state','operation','expiresAt','authorizationProvider','hardwareEnrollmentVerified','policyRevision','policyDigest','targetRef','repositoryID','runID','runAttempt'];
 if(!op||Object.keys(op).sort().join()!==fields.sort().join())reject('Invalid retained authorization schema');
 if(!op||op.id!==operationID||op.state!=='authorized'||op.operation!=='promote'||!Number.isSafeInteger(op.expiresAt)||op.expiresAt<=now||op.expiresAt>now+300)reject('No live remotely retained promotion authorization');
 if(op.authorizationProvider!=='hardware'||op.hardwareEnrollmentVerified!==true)reject('Production promotion requires verified hardware enrollment');
 if(op.policyRevision!==trust.acceptedPolicyRevision||op.policyDigest!==trust.acceptedPolicyDigest)reject('Accepted policy changed');
 if(op.targetRef!==trust.targetRef||!Number.isSafeInteger(op.repositoryID)||!trust.repositoryIDs.includes(op.repositoryID))reject('Unauthorized target repository/ref');
 if(!Number.isSafeInteger(op.runID)||op.runID<=0||!Number.isSafeInteger(op.runAttempt)||op.runAttempt<=0)reject('Missing enrolled executor run');
 return op;
}
export async function issueAuthority({operationID,oidcToken},services,trust,now=Math.floor(Date.now()/1000)){
 const op=await retainedAuthorization(operationID,services,trust,now);
 const identity=await verifyExecutorOIDC(oidcToken,trust,{operationID,runID:op.runID,runAttempt:op.runAttempt},await services.jwks(),now);
 const old=await services.operations.readLease(operationID);
 if(old)reject('Authority already issued or issuance uncertain; reconcile before retry');
 if(await services.operations.usedJTI(identity.jti))reject('OIDC token replay');
 // Drift/evidence/intent checks are central and are repeated at issuance.
 await services.verifyAuthorization(op);
 const lease={operationID,jti:identity.jti,runID:identity.runID,runAttempt:identity.runAttempt,state:'issuing',expiresAt:Math.min(op.expiresAt,identity.expiresAt)};
 await services.operations.reserve(lease); // atomic operation/JTI reservation
 let credential;
 try{
  credential=await services.credentials.issueInstallationToken({installationID:trust.installationID,repositoryIDs:[op.repositoryID],permissions:{contents:'write'}});
  if(!credential||typeof credential.token!=='string'||!credential.token.length||!Number.isSafeInteger(credential.expiresAt)||credential.expiresAt<=now||credential.expiresAt>now+3660)reject('Invalid provider credential response');
  if(credential.repositoryIDs?.length!==1||credential.repositoryIDs[0]!==op.repositoryID||credential.permissions?.contents!=='write'||Object.entries(credential.permissions).some(([k,v])=>!['contents','metadata'].includes(k)||!['read','write'].includes(v))||credential.permissions?.metadata==='write')reject('Provider granted broader credential scope');
  await services.operations.issued({...lease,state:'issued',providerExpiresAt:credential.expiresAt});
 }catch(error){
  if(credential?.token)await services.credentials.revoke(credential.token).catch(()=>{});
  await services.operations.markUncertain(operationID);
  // Never propagate provider error bodies, tokens, JWTs or PEMs.
  reject('Credential issuance failed; operation requires reconciliation');
 }
 // Only the authenticated central executor transport receives this value.
 // Handler must use Cache-Control:no-store and must never persist/log response.
 return {token:credential.token,providerExpiresAt:credential.expiresAt,operationExpiresAt:lease.expiresAt,operationID};
}

// Runs under the same serialized coordinator as issuance and completion. This
// verifies existing authority; it cannot mint a token or renew a lease.
export async function checkAuthority({operationID,oidcToken},services,trust,clock=()=>Math.floor(Date.now()/1000)){
 const now=clock(),op=await retainedAuthorization(operationID,services,trust,now);
 const lease=await services.operations.readLease(operationID);
 if(!lease||lease.operationID!==operationID||lease.state!=='issued'||lease.runID!==String(op.runID)||lease.runAttempt!==String(op.runAttempt)||typeof lease.jti!=='string'||!Number.isSafeInteger(lease.expiresAt)||lease.expiresAt<=now||lease.expiresAt>op.expiresAt||!Number.isSafeInteger(lease.providerExpiresAt)||lease.providerExpiresAt<=now)reject('No live issued execution lease');
 const identity=await verifyExecutorOIDC(oidcToken,trust,{operationID,runID:op.runID,runAttempt:op.runAttempt},await services.jwks(),clock());
 if(identity.jti===lease.jti||await services.operations.usedJTI(identity.jti))reject('OIDC token replay');
 await services.verifyAuthorization(op);
 const expiresAt=Math.min(op.expiresAt,lease.expiresAt,lease.providerExpiresAt,identity.expiresAt);
 if(expiresAt<=clock())reject('Execution authority expired during verification');
 await services.operations.consumeCheck({operationID,jti:identity.jti,leaseJTI:lease.jti,runID:lease.runID,runAttempt:lease.runAttempt,expiresAt:lease.expiresAt});
 if(expiresAt<=clock())reject('Execution authority expired during reservation');
 return {operationID,verified:true,operationExpiresAt:lease.expiresAt};
}
