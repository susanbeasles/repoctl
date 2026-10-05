import {canonical,digest} from '../ledger.mjs';
const hash=/^[a-f0-9]{64}$/;
const exact=(v,n)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===n.sort().join();
export function completionObserver({authority,broker,github}){
 if(![authority?.load,broker?.lease,github?.tip,github?.commit].every(v=>typeof v==='function'))throw Error('Missing independent observation adapter');
 return {async verify(request){
  if(!exact(request,['operationID','repositoryID','entryPayloadDigest','baseSHA','commitSHA'])||![request.operationID,request.entryPayloadDigest].every(v=>hash.test(v??'')))throw Error('Invalid completion request');
  const [view,lease]=await Promise.all([authority.load(request.operationID),broker.lease(request.operationID)]);
  if(!exact(view,['record','recordDigest','ledgerPayload','approvalDigest','enrollmentProofDigest'])||!exact(lease,['operationID','recordDigest','state','runID','runAttempt','expiresAt','providerExpiresAt']))throw Error('Invalid retained observation');
  const record=view.record,p=view.ledgerPayload,op=record?.operation,intent=record?.intent;
  if(!op||!intent||op.id!==request.operationID||op.operation!=='promote'||op.authorizationProvider!=='hardware'||op.hardwareEnrollmentVerified!==true||op.repositoryID!==request.repositoryID||intent.repositoryID!==request.repositoryID||p.repositoryID!==request.repositoryID||p.baseSHA!==request.baseSHA||p.commitSHA!==request.commitSHA||intent.baseSHA!==p.baseSHA||intent.commitSHA!==p.commitSHA||p.policyDigest!==op.policyDigest||op.targetRef!==`refs/heads/${intent.branch}`||await digest(p)!==request.entryPayloadDigest||![view.approvalDigest,view.enrollmentProofDigest].every(v=>hash.test(v??''))||view.recordDigest!==await digest(record))throw Error('Retained approval binding denied');
  if(lease.operationID!==request.operationID||lease.recordDigest!==view.recordDigest||!['issued','uncertain','completed'].includes(lease.state)||lease.runID!==op.runID||lease.runAttempt!==op.runAttempt||![lease.runID,lease.runAttempt,lease.expiresAt,lease.providerExpiresAt].every(v=>Number.isSafeInteger(v)&&v>0)||lease.expiresAt>op.expiresAt)throw Error('Execution lease differs from retained approval');
  // Reconciliation may occur after approval/token expiration. It confirms an
  // already issued operation; it never reopens issuance or grants new authority.
  if(await github.tip()!==p.commitSHA)throw Error('Promotion not observed');
  const [candidate,source]=await Promise.all([github.commit(p.commitSHA),github.commit(p.sourceSHA)]);
  if(candidate.sha!==p.commitSHA||candidate.parents?.length!==1||candidate.parents[0].sha!==p.baseSHA||candidate.tree?.sha!==intent.treeSHA||candidate.verification?.verified!==true||candidate.verification.reason!=='valid'||source.sha!==p.sourceSHA)throw Error('Promoted Git objects differ from approval');
  const second=await authority.load(request.operationID);
  if(canonical(second)!==canonical(view)||await github.tip()!==p.commitSHA)throw Error('Promotion observation changed');
  return {...request,promoted:true};
 }};
}
