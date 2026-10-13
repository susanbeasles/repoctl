import {canonical,digest} from '../ledger.mjs';
import {baselineEvidence} from './baseline.ts';
import {importPolicy} from '../authority/authorize.mjs';
import {validateIntent,verifyApproval} from '../promotion.mjs';
const hash=/^[a-f0-9]{64}$/;
const exact=(v,n)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===n.sort().join();
// Adapters are installed verifier capabilities, never caller URLs or booleans.
// Archive verification must perform recovery against immutable retained objects.
export function admissionEvidence({policy,github,history,archives,baseline,timeoutMS=10000,clock=()=>Date.now()}) {
 if(![policy?.current,github?.verify,history?.verify,archives?.verify].every(v=>typeof v==='function'))throw Error('Missing mandatory evidence adapter');
 const baselines=baselineEvidence(baseline,timeoutMS);
 return {async verify(request){
  if(!exact(request,['operationID','repositoryID','intent','owner','validator'])||!hash.test(request.operationID??'')||!Number.isSafeInteger(request.repositoryID)||request.repositoryID<=0)throw Error('Invalid evidence admission');
  const accepted=await importPolicy(await policy.current(request.repositoryID));
  const a=await verifyApproval(request.owner,'owner',accepted.ownerKeys),b=await verifyApproval(request.validator,'validator',accepted.validatorKeys);
  if(a.payload!==b.payload||canonical(a.intent)!==canonical(request.intent))throw Error('Evidence approvals differ from intent');
  const p=validateIntent(a.intent,accepted,clock());
  if(p.nonce!==request.operationID||p.repositoryID!==request.repositoryID)throw Error('Evidence operation differs');
  const bi={repositoryID:p.repositoryID,policyRevision:accepted.revision,policyDigest:accepted.digest,targetRef:accepted.targetRef,baseSHA:p.baseSHA};
  await baselines.verify(bi);
  const gi={baseSHA:p.baseSHA,commitSHA:p.commitSHA,sourceSHA:p.sourceSHA,treeSHA:p.treeSHA};
  const hi={repositoryID:p.repositoryID,sequence:p.sequence,previousDigest:p.previousDigest,baseSHA:p.baseSHA,commitSHA:p.commitSHA};
  const ai={repositoryID:p.repositoryID,commitSHA:p.commitSHA,sourceSHA:p.sourceSHA,treeSHA:p.treeSHA,archiveDigests:p.archiveDigests};
  const [g,h,r]=await Promise.all([github.verify(gi),history.verify(hi),archives.verify(ai)]);
  if(g?.githubVerified!==true||!hash.test(g.digest??'')||canonical(g.intent)!==canonical(gi))throw Error('GitHub evidence binding denied');
  if(h?.historyVerified!==true||!hash.test(h.digest??'')||canonical(h.intent)!==canonical(hi))throw Error('History evidence binding denied');
  if(r?.archiveVerified!==true||r.recoveryVerified!==true||!hash.test(r.digest??'')||canonical(r.intent)!==canonical(ai))throw Error('Recoverable archive evidence binding denied');
  // Digests are recomputed from the documented component bodies; an adapter's
  // arbitrary digest string cannot be mistaken for the evidence reviewed earlier.
  const gb={protocol:g.protocol,intent:g.intent,checks:g.checks};
  const hb={protocol:h.protocol,repositoryID:h.repositoryID,checkpoint:h.checkpoint,tip:h.tip,intent:h.intent};
  const rb={protocol:r.protocol,intent:r.intent,objects:r.objects,recovery:r.recovery};
  if(g.protocol!=='repoctl-github-evidence-v1'||h.protocol!=='repoctl-history-evidence-v1'||r.protocol!=='repoctl-archive-evidence-v1'||g.digest!==await digest(gb)||h.digest!==await digest(hb)||r.digest!==await digest(rb))throw Error('Evidence body digest differs');
  // Stable proposal evidence excludes nonce/expiry and the evidenceDigest itself,
  // allowing it to be computed before the owner signs the final intent.
  const report={protocol:'repoctl-admission-evidence-v1',repositoryID:p.repositoryID,policyDigest:p.policyDigest,githubDigest:g.digest,historyDigest:h.digest,archiveDigest:r.digest};
  const evidenceDigest=await digest(report);
  if(evidenceDigest!==p.evidenceDigest)throw Error('Evidence differs from approved digest');
  const current=await importPolicy(await policy.current(p.repositoryID));
  if(canonical(current.executorTrust)!==canonical(accepted.executorTrust)||current.digest!==accepted.digest||current.revision!==accepted.revision||canonical([...current.ownerKeys.keys()])!==canonical([...accepted.ownerKeys.keys()])||canonical([...current.validatorKeys.keys()])!==canonical([...accepted.validatorKeys.keys()]))throw Error('Accepted policy changed during evidence verification');
  validateIntent(p,current,clock());
  await baselines.verify(bi);
  return {operationID:request.operationID,verified:true,intentDigest:await digest(p),evidenceDigest,report};
 }};
}
