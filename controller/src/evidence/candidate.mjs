import {digest} from '../ledger.mjs';
const sha=/^[a-f0-9]{40}$/;
const fields=(v,n)=>v&&Object.keys(v).sort().join()===n.sort().join();
// GitHub evidence only. This is not sufficient promotion authorization: archive,
// ledger anchoring and independent approvals remain separate mandatory checks.
export function candidateEvidence({github,requiredChecks,actorIDs,branchPrefix='int/'}){
 if(!Array.isArray(requiredChecks)||!requiredChecks.length||requiredChecks.length>20||!Array.isArray(actorIDs)||!actorIDs.length||!actorIDs.every(v=>Number.isSafeInteger(v)&&v>0)||typeof branchPrefix!=='string'||! /^[-A-Za-z0-9_./]+\/$/.test(branchPrefix))throw Error('Invalid CI verification policy');
 const names=new Set();
 for(const r of requiredChecks){if(!fields(r,['name','appID','workflowID','workflowPath','workflowDigest'])||typeof r.name!=='string'||!r.name.length||names.has(r.name)||![r.appID,r.workflowID].every(v=>Number.isSafeInteger(v)&&v>0)||typeof r.workflowDigest!=='string'||! /^[a-f0-9]{64}$/.test(r.workflowDigest)||typeof r.workflowPath!=='string'||!/^\.github\/workflows\/[-A-Za-z0-9_.]+\.ya?ml$/.test(r.workflowPath))throw Error('Invalid required check');names.add(r.name);}
 return {
  async verify(intent){
   if(!fields(intent,['baseSHA','commitSHA','sourceSHA','treeSHA'])||!Object.values(intent).every(v=>sha.test(v??'')))throw Error('Invalid GitHub evidence intent');
   const [tip,candidate,source,checks]=await Promise.all([github.tip(),github.commit(intent.commitSHA),github.commit(intent.sourceSHA),github.checks(intent.commitSHA)]);
   if(tip!==intent.baseSHA||candidate.sha!==intent.commitSHA||candidate.parents?.length!==1||candidate.parents[0].sha!==intent.baseSHA||candidate.tree?.sha!==intent.treeSHA||candidate.verification?.verified!==true||candidate.verification.reason!=='valid'||source.sha!==intent.sourceSHA)throw Error('Candidate history/tree/signature rejected');
   const runs=new Map(),workflows=new Map(),evidence=[];
   for(const rule of requiredChecks){
    const matches=checks.filter(c=>c.name===rule.name);if(matches.length!==1)throw Error('Missing or ambiguous required check');const check=matches[0];
    if(check.head_sha!==intent.commitSHA||check.status!=='completed'||check.conclusion!=='success'||check.app?.id!==rule.appID||!Number.isSafeInteger(check.id)||check.id<=0||!Number.isSafeInteger(check.check_suite?.id)||check.check_suite.id<=0)throw Error('Required check not trusted/successful');
    const suiteID=check.check_suite.id;if(!runs.has(suiteID))runs.set(suiteID,await github.runForSuite(suiteID));const run=runs.get(suiteID);
    if(run.head_sha!==intent.commitSHA||run.check_suite_id!==suiteID||run.workflow_id!==rule.workflowID||run.path!==rule.workflowPath||run.status!=='completed'||run.conclusion!=='success'||run.event!=='push'||typeof run.head_branch!=='string'||!run.head_branch.startsWith(branchPrefix)||run.head_branch.length===branchPrefix.length||!actorIDs.includes(run.actor?.id)||!actorIDs.includes(run.triggering_actor?.id)||!Number.isSafeInteger(run.id)||run.id<=0||!Number.isSafeInteger(run.run_attempt)||run.run_attempt<=0)throw Error('Workflow execution identity rejected');
    if(!workflows.has(rule.workflowPath)){const bytes=await github.workflowBytes(rule.workflowPath,intent.commitSHA);const fingerprint=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');workflows.set(rule.workflowPath,fingerprint);}
    if(workflows.get(rule.workflowPath)!==rule.workflowDigest)throw Error('Candidate workflow differs from trusted recipe');
    evidence.push({workflowDigest:rule.workflowDigest,name:rule.name,checkID:check.id,suiteID,runID:run.id,runAttempt:run.run_attempt,appID:rule.appID,workflowID:rule.workflowID});
   }
   // An observation changing during verification must not produce usable evidence.
   if(await github.tip()!==intent.baseSHA)throw Error('Main moved during evidence verification');
   const report={protocol:'repoctl-github-evidence-v1',intent,checks:evidence};
   return {...report,githubVerified:true,digest:await digest(report)};
  }
 };
}
