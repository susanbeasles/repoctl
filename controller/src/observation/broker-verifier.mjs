import {canonical,digest} from '../ledger.mjs';
import {baselineEvidence} from '../evidence/baseline.ts';
const exact=(v,n)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===n.sort().join();
export function brokerVerifier({authority,completion,github,baseline,timeoutMS=10000}){
 async function retained(request){
  if(!exact(request,['operationID','operation','intent'])||!/^[a-f0-9]{64}$/.test(request.operationID??''))throw Error('Invalid broker verification');
  const view=await authority.load(request.operationID);
  if(view.recordDigest!==await digest(view.record)||view.record?.operation?.id!==request.operationID||canonical(view.record.operation)!==canonical(request.operation)||canonical(view.record.intent)!==canonical(request.intent))throw Error('Broker intent differs from authority');return view;
 }
 return {
  async authorization(request){
   const view=await retained(request),p=view.record.intent;
   const accepted=await authority.check({operationID:request.operationID,...view.record});
   if(accepted.operationID!==request.operationID||accepted.accepted!==true)throw Error('Current authority denied');
   const baselines=baselineEvidence(baseline,timeoutMS);
   const binding={repositoryID:p.repositoryID,policyRevision:view.record.operation.policyRevision,policyDigest:view.record.operation.policyDigest,targetRef:view.record.operation.targetRef,baseSHA:p.baseSHA};
   await baselines.verify(binding);
   if(await github.tip()!==p.baseSHA)throw Error('Protected ref moved');
   const candidate=await github.commit(p.commitSHA);
   if(candidate.sha!==p.commitSHA||candidate.parents?.length!==1||candidate.parents[0].sha!==p.baseSHA||candidate.tree?.sha!==p.treeSHA||candidate.verification?.verified!==true||candidate.verification.reason!=='valid'||await github.tip()!==p.baseSHA)throw Error('Candidate cannot fast forward approved main');
   const latest=await retained(request);if(canonical(latest)!==canonical(view))throw Error('Retained authorization changed');
   await baselines.verify(binding);
   return {operationID:request.operationID,verified:true};
  },
  async completion(request){
   const view=await retained(request),p=view.ledgerPayload;
   const expected={operationID:request.operationID,repositoryID:p.repositoryID,entryPayloadDigest:await digest(p),baseSHA:p.baseSHA,commitSHA:p.commitSHA};
   const result=await completion.verify(expected);if(canonical(result)!==canonical({...expected,promoted:true}))throw Error('Independent completion denied');
   return {operationID:request.operationID,verified:true};
  }
 };
}
