import {digest} from '../ledger.mjs';

export interface Intent {
 readonly baseSHA:string; readonly commitSHA:string; readonly sourceSHA:string; readonly treeSHA:string;
}
export interface Candidate {
 readonly repositoryID:number; readonly baseSHA:string; readonly commitSHA:string; readonly treeSHA:string;
}
export interface Signatures {
 verify(candidate:Candidate,options:{signal:AbortSignal}):Promise<unknown>;
}
export interface CheckRule {
 readonly name:string; readonly appID:number; readonly workflowID:number;
 readonly workflowPath:string; readonly workflowDigest:string;
}
interface Commit {
 sha?:string; parents?:{sha?:string}[]; tree?:{sha?:string}; verification?:{verified?:boolean;reason?:string};
}
interface Check {
 name?:string; id?:number; head_sha?:string; status?:string; conclusion?:string;
 app?:{id?:number}; check_suite?:{id?:number};
}
interface Run {
 id?:number; check_suite_id?:number; head_sha?:string; workflow_id?:number; path?:string;
 status?:string; conclusion?:string; event?:string; head_branch?:string;
 actor?:{id?:number}; triggering_actor?:{id?:number}; run_attempt?:number;
}
interface GitHub {
 tip():Promise<string>; commit(sha:string):Promise<Commit>; checks(sha:string):Promise<Check[]>;
 runForSuite(id:number):Promise<Run>; workflowBytes(path:string,sha:string):Promise<Uint8Array>;
}
interface Configuration {
 github:GitHub; repositoryID:number; signatures:Signatures; requiredChecks:readonly CheckRule[];
 actorIDs:readonly number[]; branchPrefix?:string; timeoutMS?:number;
}
const sha=/^[a-f0-9]{40}$/;
const positive=(value:unknown):value is number=>Number.isSafeInteger(value)&&typeof value==='number'&&value>0;
const fields=(value:unknown,names:string[]):value is Record<string,unknown>=>!!value&&typeof value==='object'&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join()===names.slice().sort().join();

// Installed verifier capability; project data cannot select a key or endpoint.
export function candidateEvidence({github,repositoryID,signatures,requiredChecks,actorIDs,branchPrefix='int/',timeoutMS=10000}:Configuration){
 if(!positive(repositoryID)||typeof signatures?.verify!=='function')throw Error('Missing designated candidate signature verifier');
 if(!Number.isSafeInteger(timeoutMS)||timeoutMS<100||timeoutMS>10000||!Array.isArray(requiredChecks)||!requiredChecks.length||requiredChecks.length>20||!Array.isArray(actorIDs)||!actorIDs.length||!actorIDs.every(positive)||typeof branchPrefix!=='string'||!/^[-A-Za-z0-9_./]+\/$/.test(branchPrefix))throw Error('Invalid CI verification policy');
 const names=new Set<string>();
 for(const rule of requiredChecks){
  if(!fields(rule,['name','appID','workflowID','workflowPath','workflowDigest'])||typeof rule.name!=='string'||!rule.name.length||names.has(rule.name)||![rule.appID,rule.workflowID].every(positive)||typeof rule.workflowDigest!=='string'||! /^[a-f0-9]{64}$/.test(rule.workflowDigest)||typeof rule.workflowPath!=='string'||!/^\.github\/workflows\/[-A-Za-z0-9_.]+\.ya?ml$/.test(rule.workflowPath))throw Error('Invalid required check');
  names.add(rule.name);
 }
 const rules=requiredChecks.map(rule=>Object.freeze({...rule})),actors=new Set(actorIDs);
 async function signature(candidate:Candidate){
  const control=new AbortController();let timer:ReturnType<typeof setTimeout>|undefined;
  let proof:unknown;
  try{
   proof=await Promise.race([Promise.resolve().then(()=>signatures.verify(candidate,{signal:control.signal})),new Promise<never>((_,reject)=>{timer=setTimeout(()=>{control.abort();reject(Error('Signature verifier timeout'));},timeoutMS);})]);
  }catch{throw Error('Designated candidate signature unavailable');}
  finally{if(timer!==undefined)clearTimeout(timer);}
  if(!proof||typeof proof!=='object'||!('verified' in proof)||proof.verified!==true||Object.entries(candidate).some(([key,value])=>!(key in proof)||Reflect.get(proof,key)!==value))throw Error('Designated candidate signature rejected');
 }
 return {async verify(request:Intent){
  if(!fields(request,['baseSHA','commitSHA','sourceSHA','treeSHA']))throw Error('Invalid GitHub evidence intent');
  const intent=Object.freeze({...request});
  if(!Object.values(intent).every(value=>typeof value==='string'&&sha.test(value)))throw Error('Invalid GitHub evidence intent');
  const candidate=Object.freeze({repositoryID,baseSHA:intent.baseSHA,commitSHA:intent.commitSHA,treeSHA:intent.treeSHA});
  await signature(candidate);
  const [tip,commit,source,checks]=await Promise.all([github.tip(),github.commit(intent.commitSHA),github.commit(intent.sourceSHA),github.checks(intent.commitSHA)]);
  if(tip!==intent.baseSHA||commit.sha!==intent.commitSHA||commit.parents?.length!==1||commit.parents[0].sha!==intent.baseSHA||commit.tree?.sha!==intent.treeSHA||commit.verification?.verified!==true||commit.verification.reason!=='valid'||source.sha!==intent.sourceSHA)throw Error('Candidate history/tree/signature rejected');
  const runs=new Map<number,Run>(),workflows=new Map<string,string>();
  const evidence:{workflowDigest:string;name:string;checkID:number;suiteID:number;runID:number;runAttempt:number;appID:number;workflowID:number}[]=[];
  for(const rule of rules){
   const matches=checks.filter(check=>check.name===rule.name);
   if(matches.length!==1)throw Error('Missing or ambiguous required check');const check=matches[0];
   if(check.head_sha!==intent.commitSHA||check.status!=='completed'||check.conclusion!=='success'||check.app?.id!==rule.appID||!positive(check.id)||!positive(check.check_suite?.id))throw Error('Required check not trusted/successful');
   const suiteID=check.check_suite.id;
   let run=runs.get(suiteID);if(!run){run=await github.runForSuite(suiteID);runs.set(suiteID,run);}
   if(run.head_sha!==intent.commitSHA||run.check_suite_id!==suiteID||run.workflow_id!==rule.workflowID||run.path!==rule.workflowPath||run.status!=='completed'||run.conclusion!=='success'||run.event!=='push'||typeof run.head_branch!=='string'||!run.head_branch.startsWith(branchPrefix)||run.head_branch.length===branchPrefix.length||!positive(run.actor?.id)||!actors.has(run.actor.id)||!positive(run.triggering_actor?.id)||!actors.has(run.triggering_actor.id)||!positive(run.id)||!positive(run.run_attempt))throw Error('Workflow execution identity rejected');
   if(!workflows.has(rule.workflowPath)){
    const bytes=await github.workflowBytes(rule.workflowPath,intent.commitSHA);
    const fingerprint=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),byte=>byte.toString(16).padStart(2,'0')).join('');workflows.set(rule.workflowPath,fingerprint);
   }
   if(workflows.get(rule.workflowPath)!==rule.workflowDigest)throw Error('Candidate workflow differs from trusted recipe');
   evidence.push({workflowDigest:rule.workflowDigest,name:rule.name,checkID:check.id,suiteID,runID:run.id,runAttempt:run.run_attempt,appID:rule.appID,workflowID:rule.workflowID});
  }
  if(await github.tip()!==intent.baseSHA)throw Error('Main moved during evidence verification');
  await signature(candidate); // Revocation or role changes during CI block evidence.
  const report={protocol:'repoctl-github-evidence-v1',intent,checks:evidence};
  return {...report,githubVerified:true,digest:await digest(report)};
 }};
}
