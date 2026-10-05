import {digest,verifyChain} from '../ledger.mjs';
const hash=/^[a-f0-9]{64}$/;
const sha=/^[a-f0-9]{40}$/;
const exact=(v,n)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===n.sort().join();
// All adapters and trust roots are installed configuration. No request may select
// its own checkpoint, signing keys, repository or ledger storage location.
export function historyEvidence({repositoryID,trustedKeys,checkpoint,ledger,github,maxEntries=10000}) {
 if(!Number.isSafeInteger(repositoryID)||repositoryID<=0||!(trustedKeys instanceof Map)||!trustedKeys.size||!Number.isSafeInteger(maxEntries)||maxEntries<1||maxEntries>10000)throw Error('Invalid history verification configuration');
 function validateAnchor(a){
  if(!exact(a,['repositoryID','startSequence','startDigest','startCommit','endSequence','endDigest','endCommit'])||a.repositoryID!==repositoryID||![a.startSequence,a.endSequence].every(v=>Number.isSafeInteger(v)&&v>=0)||a.endSequence<a.startSequence||a.endSequence-a.startSequence>maxEntries||![a.startDigest,a.endDigest].every(v=>hash.test(v??''))||![a.startCommit,a.endCommit].every(v=>sha.test(v??'')))throw Error('Invalid independent checkpoint');
 }
 return {async verify(intent){
  if(!exact(intent,['repositoryID','sequence','previousDigest','baseSHA','commitSHA'])||intent.repositoryID!==repositoryID||!Number.isSafeInteger(intent.sequence)||intent.sequence<1||!hash.test(intent.previousDigest??'')||![intent.baseSHA,intent.commitSHA].every(v=>sha.test(v??''))||intent.baseSHA===intent.commitSHA)throw Error('Invalid history intent');
  const anchor=await checkpoint.read(repositoryID);validateAnchor(anchor);
  if(intent.sequence!==anchor.endSequence+1||intent.previousDigest!==anchor.endDigest||intent.baseSHA!==anchor.endCommit)throw Error('Proposal does not extend independent checkpoint');
  const entries=await ledger.read({repositoryID,startSequence:anchor.startSequence+1,endSequence:anchor.endSequence});
  if(!Array.isArray(entries)||entries.length!==anchor.endSequence-anchor.startSequence)throw Error('Missing or excessive ledger entries');
  const verified=await verifyChain(entries,trustedKeys,anchor);
  // Confirm that every retained promotion is still present in the proposed Git
  // ancestry. A signed receipt by itself does not establish Git parentage.
  let parent=anchor.startCommit;
  for(const entry of entries){
   const p=entry.payload;if(!sha.test(p.commitSHA??'')||!sha.test(p.baseSHA??''))throw Error('Unsupported Git object format');
   const commit=await github.commit(p.commitSHA);
   if(commit.sha!==p.commitSHA||commit.parents?.length!==1||commit.parents[0].sha!==parent)throw Error('Retained Git history differs from ledger');
   parent=p.commitSHA;
  }
  const candidate=await github.commit(intent.commitSHA);
  if(candidate.sha!==intent.commitSHA||candidate.parents?.length!==1||candidate.parents[0].sha!==intent.baseSHA||await github.tip()!==intent.baseSHA)throw Error('Candidate cannot fast forward anchored main');
  const latest=await checkpoint.read(repositoryID);validateAnchor(latest);
  if(await digest(latest)!==await digest(anchor))throw Error('Checkpoint moved during verification');
  const report={protocol:'repoctl-history-evidence-v1',repositoryID,checkpoint:anchor,tip:verified,intent};
  return {...report,historyVerified:true,digest:await digest(report)};
 }};
}
