import {canonical,digest,base64} from '../ledger.mjs';
import {verifyApproval,validateIntent} from '../promotion.mjs';
import {verifyExecutionApproval} from './approval.mjs';
const hash=/^[a-f0-9]{64}$/;
const fields=(value,names)=>value&&Object.keys(value).sort().join()===names.sort().join();
export async function importPolicy(raw){
 if(!fields(raw,['repositoryID','repository','targetRef','revision','digest','maxIntentTTL','ownerKeys','validatorKeys','executorTrust'])||!Number.isSafeInteger(raw.repositoryID)||raw.repositoryID<=0||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(raw.repository)||!['refs/heads/main','refs/heads/master'].includes(raw.targetRef)||!Number.isSafeInteger(raw.revision)||raw.revision<1||!hash.test(raw.digest??'')||!Number.isSafeInteger(raw.maxIntentTTL)||raw.maxIntentTTL<1||raw.maxIntentTTL>300)throw Error('Invalid accepted policy');
 async function inventory(entries){
  if(!Array.isArray(entries)||!entries.length||entries.length>10)throw Error('Invalid signer inventory');const keys=new Map();
  for(const entry of entries){
   if(!fields(entry,['keyID','publicKeyX963'])||!hash.test(entry.keyID??'')||keys.has(entry.keyID))throw Error('Invalid signer');
   const bytes=Uint8Array.from(atob(entry.publicKeyX963),c=>c.charCodeAt(0));
   const fingerprint=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
   if(fingerprint!==entry.keyID)throw Error('Signer fingerprint mismatch');
   keys.set(entry.keyID,await crypto.subtle.importKey('raw',bytes,{name:'ECDSA',namedCurve:'P-256'},true,['verify']));
  }return keys;
 }
 const ownerKeys=await inventory(raw.ownerKeys),validatorKeys=await inventory(raw.validatorKeys);
 const owners=new Set(await Promise.all([...ownerKeys.values()].map(async key=>base64(await crypto.subtle.exportKey('raw',key)))));
 for(const key of validatorKeys.values())if(owners.has(base64(await crypto.subtle.exportKey('raw',key))))throw Error('Owner and validator must be independent');
 const t=raw.executorTrust;
 const trustFields=['appID','installationID','repositoryIDs','acceptedPolicyRevision','acceptedPolicyDigest','targetRef','audiencePrefix','repository','repositoryID','ownerID','ref','workflowRef','workflowSHA','jobWorkflowRef','jobWorkflowSHA','eventNames','actorIDs'];
 if(!fields(t,trustFields)||t.acceptedPolicyRevision!==raw.revision||t.acceptedPolicyDigest!==raw.digest||t.targetRef!==raw.targetRef||!Array.isArray(t.repositoryIDs)||t.repositoryIDs.length!==1||t.repositoryIDs[0]!==raw.repositoryID)throw Error('Executor policy binding differs');
 for(const name of ['appID','installationID','repositoryID','ownerID'])if(!Number.isSafeInteger(t[name])||t[name]<=0)throw Error('Invalid executor identity');
 if(!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(t.repository)||t.ref!=='refs/heads/main'||![t.workflowSHA,t.jobWorkflowSHA].every(v=>/^[a-f0-9]{40}$/.test(v??''))||t.workflowSHA!==t.jobWorkflowSHA||typeof t.audiencePrefix!=='string'||!t.audiencePrefix.length||t.audiencePrefix.length>200)throw Error('Invalid executor revision');
 if(t.workflowRef!==`${t.repository}/.github/workflows/promote.yml@${t.ref}`||t.jobWorkflowRef!==`${t.repository}/.github/workflows/executor.yml@${t.ref}`||JSON.stringify(t.eventNames)!==JSON.stringify(['workflow_dispatch'])||!Array.isArray(t.actorIDs)||!t.actorIDs.length||!t.actorIDs.every(v=>Number.isSafeInteger(v)&&v>0))throw Error('Invalid executor workflow/event policy');
 return {...raw,policyDigest:raw.digest,ownerKeys,validatorKeys};
}
export async function authorize(bundle,services,now=Math.floor(Date.now()/1000)){
 if(!fields(bundle,['owner','validator','executionOwner']))throw Error('Unexpected authorization fields');
 const executionRaw=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(bundle.executionOwner?.payload??''),c=>c.charCodeAt(0))));
 if(!Number.isSafeInteger(executionRaw.repositoryID)||executionRaw.repositoryID<=0)throw Error('Invalid target');
 const raw=await services.policy.current(executionRaw.repositoryID),policy=await importPolicy(raw);
 const a=await verifyApproval(bundle.owner,'owner',policy.ownerKeys),b=await verifyApproval(bundle.validator,'validator',policy.validatorKeys);
 if(a.payload!==b.payload||bundle.owner.keyID!==bundle.executionOwner.keyID)throw Error('Approvals differ');
 const p=validateIntent(a.intent,policy,now*1000);
 const run=await verifyExecutionApproval(bundle.executionOwner,policy.ownerKeys);
 if(!fields(run,['operationID','approvalDigest','repositoryID','repository','targetRef','policyRevision','policyDigest','executorTrustDigest','runID','runAttempt','expiresAt'])||run.operationID!==p.nonce||run.repositoryID!==policy.repositoryID||run.repository!==policy.repository||run.targetRef!==policy.targetRef||run.policyRevision!==policy.revision||run.policyDigest!==policy.digest||run.executorTrustDigest!==await digest(policy.executorTrust)||run.approvalDigest!==await digest({owner:bundle.owner,validator:bundle.validator})||!Number.isSafeInteger(run.expiresAt)||run.expiresAt<=now||run.expiresAt>now+300||run.expiresAt*1000>p.expiresAt||![run.runID,run.runAttempt].every(v=>Number.isSafeInteger(v)&&v>0))throw Error('Execution approval binding differs');
 const enrollment=await services.hardware.verify({repositoryID:policy.repositoryID,keyID:bundle.owner.keyID,policyRevision:policy.revision,policyDigest:policy.digest});
 if(!enrollment||enrollment.keyID!==bundle.owner.keyID||!hash.test(enrollment.proofDigest??'')||enrollment.hardwareVerified!==true||enrollment.revoked!==false||!Number.isSafeInteger(enrollment.validUntil)||enrollment.validUntil<=now)throw Error('No verified live hardware enrollment');
 const evidence=await services.evidence.verify({operationID:run.operationID,repositoryID:policy.repositoryID,intent:p,owner:bundle.owner,validator:bundle.validator});
 if(!evidence||evidence.operationID!==run.operationID||evidence.verified!==true||evidence.intentDigest!==await digest(p))throw Error('Independent evidence denied');
 const operation={id:run.operationID,state:'authorized',operation:'promote',expiresAt:run.expiresAt,authorizationProvider:'hardware',hardwareEnrollmentVerified:true,policyRevision:policy.revision,policyDigest:policy.digest,targetRef:policy.targetRef,repositoryID:policy.repositoryID,runID:run.runID,runAttempt:run.runAttempt};
 const intent={repository:policy.repository,repositoryID:policy.repositoryID,branch:policy.targetRef.slice('refs/heads/'.length),baseSHA:p.baseSHA,commitSHA:p.commitSHA,treeSHA:p.treeSHA};
 const record={operation,intent,trust:policy.executorTrust};
 const bundleDigest=await digest(bundle);
 await services.storage.transaction(async tx=>{
  const previous=await tx.get(`authority:${run.operationID}`);
  if(previous){if(previous.state!=='authorized')throw Error('Operation already reconciled');if(previous.bundleDigest!==bundleDigest||canonical(previous.record)!==canonical(record))throw Error('Operation collision');return;}
  if(await tx.get(`pending-repository:${policy.repositoryID}`))throw Error('Unreconciled repository operation');
  await tx.put(`authority:${run.operationID}`,{record,bundle,bundleDigest,enrollmentProofDigest:enrollment.proofDigest,state:'authorized'});
  await tx.put(`pending-repository:${policy.repositoryID}`,run.operationID);
 });
 return {operationID:run.operationID,state:'authorized',repositoryID:policy.repositoryID,runID:run.runID,runAttempt:run.runAttempt,expiresAt:run.expiresAt};
}
