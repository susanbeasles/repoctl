// Standalone, isolated source producer. Never import into a privileged CI job.
import {createHash} from 'node:crypto';
import {canonical} from '../ledger.mjs';
import {verifyApproval} from '../promotion.mjs';
import {validateScanEvidence} from './scans.mjs';

const SHA=/^[a-f0-9]{40}$/,HASH=/^[a-f0-9]{64}$/;
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.slice().sort().join();
const positive=v=>Number.isSafeInteger(v)&&v>0;
const fingerprint=v=>typeof v==='string'&&/^SHA256:[A-Za-z0-9+/]{43}$/.test(v);
const repository=v=>typeof v==='string'&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(v);
const ref=v=>typeof v==='string'&&/^refs\/heads\/[A-Za-z0-9_/-]+$/.test(v)&&!v.includes('//')&&!v.endsWith('/');
const clone=structuredClone;
export const sha256=value=>createHash('sha256').update(value).digest('hex');
export function gitObjectID(type,payload){requireValue(['commit','tag','tree','blob'].includes(type),'Invalid Git object type');const bytes=Buffer.from(payload);return createHash('sha1').update(`${type} ${bytes.length}\0`).update(bytes).digest('hex');}
function identity(value){requireValue(typeof value==='string'&&value.length<=300&&/^[^<>\r\n\x00-\x1f]+ <[^<>\s]+> [0-9]{1,12} [+-][0-9]{4}$/.test(value),'Invalid Git identity');return value;}
function signedCommit(payload,signature){const boundary=payload.indexOf('\n\n');requireValue(boundary>0,'Invalid unsigned commit');return payload.slice(0,boundary)+'\ngpgsig '+signature.trimEnd().replaceAll('\n','\n ')+'\n'+payload.slice(boundary+1);}
function signedTag(payload,signature){return payload+signature.trimEnd()+'\n';}
function checkSignature(signature){requireValue(typeof signature==='string'&&signature.length>0&&signature.length<=16384&&!signature.includes('\0')&&!signature.includes('\r'),'Invalid Git signature response');}

// Reuses repoctl's enrolled owner P256 key and existing owner approval domain.
// currentPolicy/currentHardware are installed workflow_depot trust capabilities.
export function ownerApprovalVerifier({currentPolicy,currentHardware,clock=()=>Math.floor(Date.now()/1000)}){
 requireValue(typeof currentPolicy==='function'&&typeof currentHardware?.verify==='function','Existing policy and hardware trust required');
 return {async verify(envelope,expected,{repositoryID}={}){
  const policy=await currentPolicy({repositoryID});
  requireValue(policy?.authority==='workflow_depot'&&policy.repositoryID===repositoryID&&Array.isArray(policy.ownerKeys),'Owner authority unavailable');
  const entry=policy.ownerKeys.find(k=>k.keyID===envelope?.keyID);requireValue(entry&&HASH.test(entry.keyID),'Owner is not independently enrolled');
  const raw=Buffer.from(entry.publicKeyX963,'base64');requireValue(raw.length===65&&raw[0]===4&&sha256(raw)===entry.keyID,'Owner key fingerprint differs');
  const publicKey=await crypto.subtle.importKey('raw',raw,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const verified=await verifyApproval(envelope,'owner',new Map([[entry.keyID,publicKey]]));
  requireValue(Buffer.from(verified.payload,'base64').toString('utf8')===canonical(expected),'Owner approval bytes differ');
  const proof=await currentHardware.verify({repositoryID,keyID:entry.keyID});
  requireValue(proof?.keyID===entry.keyID&&proof.hardwareVerified===true&&proof.revoked===false&&HASH.test(proof.proofDigest)&&positive(proof.validUntil)&&proof.validUntil>clock(),'Current hardware approval unavailable');
  return {ownerKeyID:entry.keyID,hardwareVerified:true,proofDigest:proof.proofDigest,validUntil:proof.validUntil};
 }};
}

export function validateReviewReceipt(receipt,expected,policy,now){
 const fields=['schema','repositoryID','sourcePRNumber','sourceSHA','baseSHA','commitSHA','treeSHA','policyDigest','styleGuideDigest','styleGuideRevision','styleGuidePath','reviewerAppID','reviewerInstallationID','reviewerActorID','methods','verdict','findings','humanReviewVerified','expiresAt'];
 requireValue(exact(receipt,fields)&&receipt.schema==='repoctl-source-review/v1','Invalid review receipt');
 for(const key of ['repositoryID','sourcePRNumber','sourceSHA','baseSHA','commitSHA','treeSHA','policyDigest'])requireValue(receipt[key]===expected[key],'Review generation differs');
 requireValue(receipt.styleGuideDigest===policy.styleGuideDigest&&HASH.test(receipt.styleGuideDigest)&&receipt.styleGuideRevision===policy.styleGuideRevision&&SHA.test(receipt.styleGuideRevision)&&receipt.styleGuidePath===policy.styleGuidePath&&typeof receipt.styleGuidePath==='string'&&receipt.styleGuidePath.length>0,'Review style guide differs');
 requireValue(positive(policy.reviewerAppID)&&positive(policy.reviewerInstallationID)&&positive(policy.reviewerActorID)&&receipt.reviewerAppID===policy.reviewerAppID&&receipt.reviewerInstallationID===policy.reviewerInstallationID&&receipt.reviewerActorID===policy.reviewerActorID,'Reviewer identity differs');
 requireValue(Array.isArray(policy.privilegedActorIDs)&&Array.isArray(policy.privilegedAppIDs)&&!policy.privilegedActorIDs.includes(receipt.reviewerActorID)&&!policy.privilegedAppIDs.includes(receipt.reviewerAppID),'Reviewer is not independent');
 requireValue(receipt.verdict==='approved'&&positive(receipt.expiresAt)&&receipt.expiresAt>now&&Array.isArray(receipt.findings)&&receipt.findings.length<=100,'Review absent, inconclusive or expired');
 requireValue(Array.isArray(receipt.methods)&&['deterministic-style','security-tests','evidence-review'].every(x=>receipt.methods.includes(x)),'Independent review needs deterministic checks and evidence');
 for(const finding of receipt.findings)requireValue(exact(finding,['severity','summary','evidence'])&&['info','low'].includes(finding.severity)&&typeof finding.summary==='string'&&finding.summary.length>0&&finding.summary.length<=2000&&typeof finding.evidence==='string'&&finding.evidence.length>0&&finding.evidence.length<=8000,'Blocking or invalid review finding');
 requireValue(typeof receipt.humanReviewVerified==='boolean'&&(receipt.humanReviewVerified||(policy.allowBotApproval===true&&policy.requiresHumanReview===false)),'Required human review absent');
 return receipt;
}

export function createSourceSigning({storage,policy,git,signer,approvalVerifier,ci,review,scans,publisher,clock=()=>Math.floor(Date.now()/1000)}){
 for(const [adapter,methods] of [[storage,['get','put','transaction']],[policy,['current','authorizeCandidate']],[git,['snapshot','main','source']],[signer,['signGit','verifyGit']],[approvalVerifier,['verify']],[ci,['verify']],[review,['verify']],[scans,['verify']],[publisher,['putObject','readRef','createRef']]])requireValue(adapter&&methods.every(m=>typeof adapter[m]==='function'),'Required isolated source adapter unavailable');
 const key=(repo,seq)=>{requireValue(positive(repo)&&positive(seq),'Invalid source generation');return `source-signing:${repo}:${seq}`;};
 const load=async input=>{requireValue(exact(input,['repositoryID','sequence']),'Invalid generation lookup');const record=await storage.get(key(input.repositoryID,input.sequence));requireValue(record,'Unknown source generation');return record;};
 async function save(record,expected){await storage.transaction(async tx=>{const k=key(record.repositoryID,record.sequence),old=await tx.get(k);requireValue(old&&expected.includes(old.state),'Source generation changed');await tx.put(k,record);});}
 async function current(record,{mainFinal=false}={}){
  const config=await policy.current({repositoryID:record.repositoryID});requireValue(canonical(config)===canonical(record.config),'Source policy changed');
  requireValue(signer.keyID===config.signerKeyID,'Installed signer identity changed');
  const main=await git.main(config);requireValue(main===record.snapshot.mainSHA||(mainFinal&&main===record.finalSignedCommitSHA),'Main changed; new candidate and approval required');
  requireValue(await git.source(config)===record.snapshot.sourceSHA,'Source changed; new candidate and approval required');
  return config;
 }
 async function candidateIntegrity(r){
  const unsigned=`tree ${r.snapshot.treeSHA}\nparent ${r.snapshot.mainSHA}\nauthor ${identity(r.author)}\ncommitter ${identity(r.committer)}\n\n${r.message}`;
  requireValue(r.unsignedCommit===unsigned&&r.unsignedCommitDigest===sha256(unsigned)&&r.signedCommit===signedCommit(unsigned,r.commitSignature)&&gitObjectID('commit',r.signedCommit)===r.finalSignedCommitSHA&&r.shadowRef===`refs/heads/promotion/${r.sequence}/shadow`,'Retained candidate bytes differ');
  const p=r.approvalPayload;
  for(const [field,value] of Object.entries({repository:r.config.repository,repositoryID:r.repositoryID,sourceRef:r.config.sourceRef,targetRef:r.config.targetRef,sourceSHA:r.snapshot.sourceSHA,expectedMainParent:r.snapshot.mainSHA,finalSignedCommitSHA:r.finalSignedCommitSHA,treeSHA:r.snapshot.treeSHA,unsignedCommitDigest:r.unsignedCommitDigest,artifactIntentDigest:r.artifactIntentDigest,policyDigest:r.config.policyDigest,signerKeyID:r.config.signerKeyID,sequence:r.sequence,shadowRef:r.shadowRef}))requireValue(p?.[field]===value,'Retained approval generation differs');
  requireValue(canonical(p.sourcePR)===canonical(r.sourcePR)&&r.sourcePR.headSHA===r.snapshot.sourceSHA,'Source PR identity differs');
  requireValue(signer.keyID===r.config.signerKeyID&&await signer.verifyGit({type:'commit',payload:unsigned,signature:r.commitSignature}),'Candidate signer verification failed');
 }
 async function tagIntegrity(r){
  await candidateIntegrity(r);
  for(const name of ['source','main']){const t=r.tags?.[name],payload=r.approvalPayload[`${name}TagPayload`];requireValue(t&&t.payload===payload&&t.name===`promotion/${r.sequence}/${name}`&&t.targetSHA===(name==='source'?r.snapshot.sourceSHA:r.finalSignedCommitSHA)&&t.object===signedTag(payload,t.signature)&&gitObjectID('tag',t.object)===t.objectSHA&&await signer.verifyGit({type:'tag',payload,signature:t.signature}),'Retained tag bytes or signature differ');}
 }
 function candidateRequest(r){const s=r.snapshot,config=r.config;return {repositoryID:r.repositoryID,repository:config.repository,sourceRef:config.sourceRef,targetRef:config.targetRef,sourcePR:r.sourcePR,sourceSHA:s.sourceSHA,sourceBaseSHA:s.sourceBaseSHA,baseSHA:s.mainSHA,treeSHA:s.treeSHA,historyDigest:s.historyDigest,unsignedCommit:r.unsignedCommit,unsignedCommitDigest:r.unsignedCommitDigest,artifactIntentDigest:r.artifactIntentDigest,sequence:r.sequence,shadowRef:r.shadowRef,signerKeyID:config.signerKeyID,policyDigest:config.policyDigest};}
 function shadowSpec(r){return {headRef:r.shadowRef,headSHA:r.finalSignedCommitSHA,baseRef:r.config.targetRef,baseSHA:r.snapshot.mainSHA,title:`Promotion candidate ${r.sequence}`,body:`Original source: ${r.config.repository}#${r.sourcePR.number}\nSource commit: ${r.snapshot.sourceSHA}\nSigned candidate: ${r.finalSignedCommitSHA}\nParent: ${r.snapshot.mainSHA}\nGeneration: ${r.sequence}\n`,draft:true,maintainerCanModify:false};}
 function publicCandidate(r){return {sequence:r.sequence,shadowRef:r.shadowRef,finalSignedCommitSHA:r.finalSignedCommitSHA,signedCommit:r.signedCommit,approvalPayload:clone(r.approvalPayload)};}
 function evidenceInput(r){return {repositoryID:r.repositoryID,sourcePRNumber:r.sourcePR.number,sourceSHA:r.snapshot.sourceSHA,baseSHA:r.snapshot.mainSHA,commitSHA:r.finalSignedCommitSHA,treeSHA:r.snapshot.treeSHA,policyDigest:r.config.policyDigest,artifactIntentDigest:r.artifactIntentDigest,shadowRef:r.shadowRef};}
 async function evidence(r){const input=evidenceInput(r),ciResult=await ci.verify(clone(input));requireValue(ciResult?.verified===true&&ciResult.requestDigest===sha256(canonical(input)),'Exact candidate CI unavailable');const scanned=await scans.verify(clone(input));requireValue(scanned?.verified===true,'Scanner evidence not authenticated');validateScanEvidence(scanned.receipt,input,r.config.scanPolicy,r.snapshot.inventory,clock());const reviewed=await review.verify(clone(input));requireValue(reviewed?.verified===true,'Independent review not authenticated');validateReviewReceipt(reviewed.receipt,input,r.config.reviewPolicy,clock());return {ciReceiptDigest:sha256(canonical(ciResult)),reviewReceiptDigest:sha256(canonical(reviewed.receipt)),scanReceiptDigest:sha256(canonical(scanned.receipt))};}
 async function verifiedSign(type,payload,authorization){let signature;try{signature=await signer.signGit({type,payload,authorization:clone(authorization)});checkSignature(signature);requireValue(await signer.verifyGit({type,payload,signature}),'Git signature verification failed');}catch{throw Error('Git signing outcome uncertain; explicit reconciliation required');}return signature;}
 async function ownerProof(r,envelope){const result=await approvalVerifier.verify(envelope,r.approvalPayload,{repositoryID:r.repositoryID});requireValue(result?.hardwareVerified===true&&HASH.test(result.ownerKeyID)&&HASH.test(result.proofDigest)&&positive(result.validUntil)&&result.validUntil>clock(),'Verified current owner hardware required');return result;}
 const api={
  async approvalIntent(input){
   requireValue(exact(input,['repositoryID','sequence','expiresAt'])&&positive(input.expiresAt)&&input.expiresAt>clock()&&input.expiresAt<=clock()+300,'Invalid owner approval lifetime');
   const r=await load({repositoryID:input.repositoryID,sequence:input.sequence});requireValue(r.state==='awaiting-owner','Owner approval already reserved');await current(r);await candidateIntegrity(r);const checks=await evidence(r);await current(r);
   r.expiresAt=input.expiresAt;r.approvalPayload.expiresAt=input.expiresAt;Object.assign(r,checks);await save(r,['awaiting-owner']);return publicCandidate(r);
  },
  async prepare(input){
   requireValue(exact(input,['repositoryID','sourcePR','author','committer','message','artifactIntentDigest','expiresAt'])&&positive(input.repositoryID)&&exact(input.sourcePR,['number','repositoryID','headSHA'])&&positive(input.sourcePR.number)&&input.sourcePR.repositoryID===input.repositoryID&&SHA.test(input.sourcePR.headSHA),'Invalid source request');
   identity(input.author);identity(input.committer);requireValue(typeof input.message==='string'&&input.message.length>0&&Buffer.byteLength(input.message)<=8000&&!input.message.includes('\0')&&input.message.endsWith('\n')&&HASH.test(input.artifactIntentDigest)&&positive(input.expiresAt)&&input.expiresAt>clock()&&input.expiresAt<=clock()+300,'Invalid exact commit content or lifetime');
   const config=await policy.current({repositoryID:input.repositoryID});requireValue(config?.authority==='workflow_depot'&&config.repositoryID===input.repositoryID&&repository(config.repository)&&ref(config.sourceRef)&&config.targetRef==='refs/heads/main'&&config.sourceRef!==config.targetRef&&fingerprint(config.signerKeyID)&&config.signerKeyID===signer.keyID&&HASH.test(config.policyDigest)&&config.reviewPolicy,'Invalid independently accepted source policy');
   const sequence=await storage.transaction(async tx=>{const counter=`source-sequence:${input.repositoryID}`,previous=await tx.get(counter)??0;requireValue(Number.isSafeInteger(previous)&&previous>=0&&previous<Number.MAX_SAFE_INTEGER,'Source sequence exhausted');const next=previous+1;await tx.put(counter,next);await tx.put(key(input.repositoryID,next),{repositoryID:input.repositoryID,sequence:next,state:'reserved'});return next;});
   let r={...clone(input),sequence,config:clone(config),state:'reserved',shadowRef:`refs/heads/promotion/${sequence}/shadow`};
   try{
    r.snapshot=await git.snapshot(clone(config));const s=r.snapshot;requireValue(s?.verified===true&&[s.sourceSHA,s.sourceBaseSHA,s.mainSHA,s.treeSHA].every(x=>SHA.test(x))&&s.sourceSHA===input.sourcePR.headSHA&&HASH.test(s.historyDigest)&&typeof s.retentionReference==='string'&&s.retentionReference.length>0,'Full retained Git history unavailable');
    r.unsignedCommit=`tree ${s.treeSHA}\nparent ${s.mainSHA}\nauthor ${input.author}\ncommitter ${input.committer}\n\n${input.message}`;r.unsignedCommitDigest=sha256(r.unsignedCommit);
    const request=candidateRequest(r);
    const authorization=await policy.authorizeCandidate(clone(request));requireValue(authorization?.eligible===true&&authorization.requestDigest===sha256(canonical(request))&&authorization.policyDigest===config.policyDigest&&authorization.signerKeyID===config.signerKeyID&&positive(authorization.expiresAt)&&authorization.expiresAt>clock(),'Candidate is not policy eligible');
    await current(r);r.candidateAuthorization=authorization;r.state='signing';await save(r,['reserved']);
    requireValue(authorization.expiresAt>clock()&&input.expiresAt>clock(),'Candidate authority expired before signing');
    const signature=await verifiedSign('commit',r.unsignedCommit,{kind:'candidate-policy',...authorization,repositoryID:r.repositoryID,sequence});
    requireValue(authorization.expiresAt>clock()&&input.expiresAt>clock(),'Candidate authority expired');await current(r);
    r.commitSignature=signature;r.signedCommit=signedCommit(r.unsignedCommit,signature);r.finalSignedCommitSHA=gitObjectID('commit',r.signedCommit);
    const approvalReference=sha256(canonical({repositoryID:r.repositoryID,sequence,finalSignedCommitSHA:r.finalSignedCommitSHA,sourceSHA:s.sourceSHA,unsignedCommitDigest:r.unsignedCommitDigest,artifactIntentDigest:r.artifactIntentDigest}));
    const names={source:`promotion/${sequence}/source`,main:`promotion/${sequence}/main`};
    const message=canonical({schema:'repoctl-paired-source-tags/v1',repositoryID:r.repositoryID,repository:config.repository,sequence,sourceRef:config.sourceRef,sourceSHA:s.sourceSHA,finalSignedCommitSHA:r.finalSignedCommitSHA,approvalReference,sourceTag:names.source,mainTag:names.main})+'\n';
    const tag=(name,target)=>`object ${target}\ntype commit\ntag ${name}\ntagger ${input.committer}\n\n${message}`;
    r.approvalPayload={schema:'repoctl-source-approval/v1',repository:config.repository,repositoryID:r.repositoryID,sourceRef:config.sourceRef,targetRef:config.targetRef,sourcePR:r.sourcePR,sourceSHA:s.sourceSHA,expectedMainParent:s.mainSHA,finalSignedCommitSHA:r.finalSignedCommitSHA,treeSHA:s.treeSHA,unsignedCommitDigest:r.unsignedCommitDigest,artifactIntentDigest:r.artifactIntentDigest,policyDigest:config.policyDigest,signerKeyID:config.signerKeyID,sequence,shadowRef:r.shadowRef,approvalReference,sourceTagPayload:tag(names.source,s.sourceSHA),mainTagPayload:tag(names.main,r.finalSignedCommitSHA),expiresAt:input.expiresAt};
    r.state='awaiting-owner';await save(r,['signing']);return publicCandidate(r);
   }catch(error){const old=await storage.get(key(r.repositoryID,sequence));await save({...old,state:old.state==='signing'?'signing-uncertain':'candidate-denied'},[old.state]);throw error;}
  },
  async publishShadow(input){
   const r=await load(input);requireValue(r.state==='awaiting-owner','Candidate is not awaiting checks and owner approval');
   requireValue(typeof publisher.findPullRequest==='function'&&typeof publisher.createPullRequest==='function','Installed shadow publisher unavailable');
   await current(r);await candidateIntegrity(r);const request=candidateRequest(r),authorization=await policy.authorizeCandidate(clone(request));
   requireValue(authorization?.eligible===true&&authorization.requestDigest===sha256(canonical(request))&&authorization.policyDigest===r.config.policyDigest&&authorization.signerKeyID===r.config.signerKeyID&&positive(authorization.expiresAt)&&authorization.expiresAt>clock()&&authorization.expiresAt<=clock()+300,'Candidate publication is not policy eligible');
   const fresh=async()=>{await current(r);requireValue(authorization.expiresAt>clock(),'Candidate publication authority expired');};
   const journal=`source-shadow:${r.repositoryID}:${r.sequence}`;
   async function reserve(effect){await storage.transaction(async tx=>{requireValue(!await tx.get(journal+':'+effect),'Shadow publication outcome uncertain; reconcile without retry');const actual=await tx.get(key(r.repositoryID,r.sequence));requireValue(actual?.state==='awaiting-owner'&&actual.finalSignedCommitSHA===r.finalSignedCommitSHA,'Candidate generation changed');requireValue(authorization.expiresAt>clock(),'Candidate publication authority expired');await tx.put(journal+':'+effect,{commitSHA:r.finalSignedCommitSHA,requestDigest:authorization.requestDigest});});await fresh();}
   await fresh();requireValue(await publisher.putObject('commit',r.signedCommit)===r.finalSignedCommitSHA,'Candidate object readback differs');
   const existing=await publisher.readRef(r.shadowRef);requireValue(existing===null||existing===r.finalSignedCommitSHA,'Shadow ref conflicts; no replacement permitted');
   if(existing===null){await reserve('ref');try{await publisher.createRef(r.shadowRef,r.finalSignedCommitSHA);}catch{/* The exact readback alone can reconcile a lost response. */}}
   requireValue(await publisher.readRef(r.shadowRef)===r.finalSignedCommitSHA,'Shadow publication outcome uncertain; explicit reconciliation required');
   const spec=shadowSpec(r);
   let pull=await publisher.findPullRequest({headRef:spec.headRef,baseRef:spec.baseRef});
   if(pull===null){await reserve('pr');requireValue(await publisher.readRef(r.shadowRef)===r.finalSignedCommitSHA,'Shadow ref changed');await fresh();try{await publisher.createPullRequest(clone(spec));}catch{/* Never retry POST after an ambiguous outcome. */}pull=await publisher.findPullRequest({headRef:spec.headRef,baseRef:spec.baseRef});}
   requireValue(exact(pull,['number','repositoryID','headRef','headSHA','baseRef','baseSHA','state','draft','url'])&&positive(pull.number)&&pull.repositoryID===r.repositoryID&&pull.headRef===r.shadowRef&&pull.headSHA===r.finalSignedCommitSHA&&pull.baseRef===r.config.targetRef&&pull.baseSHA===r.snapshot.mainSHA&&pull.state==='open'&&pull.draft===true&&pull.url===`https://github.com/${r.config.repository}/pull/${pull.number}`,'Shadow PR differs or publication outcome uncertain');
   await fresh();requireValue(await publisher.readRef(r.shadowRef)===r.finalSignedCommitSHA,'Shadow ref changed');
   const receipt={schema:'repoctl-source-shadow/v1',repositoryID:r.repositoryID,sequence:r.sequence,commitSHA:r.finalSignedCommitSHA,shadowRef:r.shadowRef,sourceSHA:r.snapshot.sourceSHA,baseSHA:r.snapshot.mainSHA,pullRequest:clone(pull)};
   await storage.transaction(async tx=>{const previous=await tx.get(journal+':receipt');requireValue(!previous||canonical(previous)===canonical(receipt),'Shadow receipt changed');await tx.put(journal+':receipt',receipt);});return receipt;
  },
  // Installed delivery_control capability only: one exact already-reserved effect.
  async authorizePublication(input){
   requireValue(input&&positive(input.repositoryID)&&['create-ref','create-pull-request'].includes(input.operation),'Invalid publication effect');
   const target=input.operation==='create-ref'?input.ref:input.headRef,match=/^refs\/(?:heads\/promotion\/([1-9][0-9]*)\/shadow|tags\/promotion\/([1-9][0-9]*)\/(source|main))$/.exec(target??'');requireValue(match&&positive(Number(match[1]??match[2])),'Invalid immutable publication target');
   const r=await load({repositoryID:input.repositoryID,sequence:Number(match[1]??match[2])}),tag=match[3],part=tag??(input.operation==='create-ref'?'ref':'pr'),expectedState=tag?'tagged':'awaiting-owner';requireValue(r.state===expectedState,'Publication generation unavailable');
   const expected=input.operation==='create-ref'?{repository:r.config.repository,repositoryID:r.repositoryID,operation:'create-ref',ref:target,objectSHA:tag?r.tags?.[tag]?.objectSHA:r.finalSignedCommitSHA}:{repository:r.config.repository,repositoryID:r.repositoryID,operation:'create-pull-request',...shadowSpec(r)};
   requireValue(canonical(input)===canonical(expected),'Publication effect bytes differ');await current(r);await candidateIntegrity(r);let expiresAt;
   if(tag){requireValue(input.operation==='create-ref','Tags are not PR sources');await tagIntegrity(r);const proof=await ownerProof(r,r.ownerApproval);await evidence(r);expiresAt=Math.min(r.expiresAt,proof.validUntil,clock()+60);}
   else{const request=candidateRequest(r),authorized=await policy.authorizeCandidate(clone(request));requireValue(authorized?.eligible===true&&authorized.requestDigest===sha256(canonical(request))&&authorized.policyDigest===r.config.policyDigest&&authorized.signerKeyID===r.config.signerKeyID&&positive(authorized.expiresAt)&&authorized.expiresAt<=clock()+300,'Candidate publication not eligible');expiresAt=Math.min(authorized.expiresAt,clock()+60);}
   await current(r);requireValue(expiresAt>clock(),'Publication authority expired');const requestDigest=sha256(canonical(input)),grantKey=`source-effect-grant:${r.repositoryID}:${r.sequence}:${part}`,reservationKey=tag?`source-publication:${r.repositoryID}:${r.sequence}:${tag}`:`source-shadow:${r.repositoryID}:${r.sequence}:${part}`;
   await storage.transaction(async tx=>{const actual=await tx.get(key(r.repositoryID,r.sequence)),reservation=await tx.get(reservationKey);requireValue(actual?.state===expectedState&&actual.finalSignedCommitSHA===r.finalSignedCommitSHA&&reservation&&(tag?reservation.objectSHA===r.tags[tag].objectSHA:reservation.commitSHA===r.finalSignedCommitSHA&&reservation.requestDigest===sha256(canonical(candidateRequest(r)))),'Publication has no exact durable reservation');requireValue(!await tx.get(grantKey),'Publication effect grant already consumed');requireValue(expiresAt>clock(),'Publication authority expired');await tx.put(grantKey,{requestDigest,expiresAt});});
   await current(r);requireValue(expiresAt>clock(),'Publication authority expired');return {verified:true,requestDigest,expiresAt};
  },
  async approve(input){
   requireValue(exact(input,['repositoryID','sequence','ownerApproval']),'Invalid owner handoff');let r=await load({repositoryID:input.repositoryID,sequence:input.sequence});const approvalDigest=sha256(canonical(input.ownerApproval));
   if(['tagged','published'].includes(r.state)){requireValue(r.approvalDigest===approvalDigest,'Owner approval changed');return {state:r.state,sequence:r.sequence};}
   requireValue(r.state==='awaiting-owner'&&r.expiresAt>clock(),'Approval unavailable, expired or already consumed');await current(r);await candidateIntegrity(r);const checks=await evidence(r),proof=await ownerProof(r,input.ownerApproval);await current(r);requireValue(r.expiresAt>clock()&&proof.validUntil>clock(),'Approval expired during verification');
   r={...r,...checks,ownerApproval:clone(input.ownerApproval),ownerProof:proof,approvalDigest,state:'tag-signing'};
   await storage.transaction(async tx=>{const old=await tx.get(key(r.repositoryID,r.sequence));requireValue(old?.state==='awaiting-owner','Owner approval already consumed');const tombstone=`source-approval:${approvalDigest}`;requireValue(!await tx.get(tombstone),'Owner approval replay');await tx.put(tombstone,{repositoryID:r.repositoryID,sequence:r.sequence});await tx.put(key(r.repositoryID,r.sequence),r);});
   try{
    r.tags={};for(const name of ['source','main']){await current(r);requireValue(r.expiresAt>clock()&&proof.validUntil>clock(),'Tag approval expired');const payload=r.approvalPayload[`${name}TagPayload`];const signature=await verifiedSign('tag',payload,{kind:'owner-approved-tags',approvalReference:r.approvalPayload.approvalReference,approvalDigest,repositoryID:r.repositoryID,sequence:r.sequence,objectDigest:sha256(payload)});const object=signedTag(payload,signature);r.tags[name]={name:`promotion/${r.sequence}/${name}`,targetSHA:name==='source'?r.snapshot.sourceSHA:r.finalSignedCommitSHA,payload,signature,object,objectSHA:gitObjectID('tag',object)};await save(r,['tag-signing']);}
    await current(r);requireValue(r.expiresAt>clock(),'Tag approval expired');r.state='tagged';await save(r,['tag-signing']);return {state:'tagged',sequence:r.sequence};
   }catch{await save({...r,state:'tag-signing-uncertain'},['tag-signing']);throw Error('Tag signing outcome uncertain; explicit reconciliation required');}
  },
  async publish(input){
   let r=await load(input);if(r.state==='published')return {receiptDigest:r.receiptDigest,receipt:clone(r.receipt)};requireValue(r.state==='tagged','Signed approved pair unavailable');await current(r);await tagIntegrity(r);requireValue(r.expiresAt>clock(),'Publication approval expired');await ownerProof(r,r.ownerApproval);await evidence(r);
   requireValue(await signer.verifyGit({type:'commit',payload:r.unsignedCommit,signature:r.commitSignature}),'Candidate signer verification failed');
   requireValue(await publisher.putObject('commit',r.signedCommit)===r.finalSignedCommitSHA,'Candidate object readback differs');
   for(const name of ['source','main']){
    const tag=r.tags[name];requireValue(await signer.verifyGit({type:'tag',payload:tag.payload,signature:tag.signature}),'Tag signer verification failed');requireValue(await publisher.putObject('tag',tag.object)===tag.objectSHA,'Tag object readback differs');
    const tagRef=`refs/tags/${tag.name}`,existing=await publisher.readRef(tagRef);requireValue(existing===null||existing===tag.objectSHA,'Existing tag differs; no retagging');if(existing===tag.objectSHA)continue;
    const mutation=`source-publication:${r.repositoryID}:${r.sequence}:${name}`;await storage.transaction(async tx=>{requireValue(!await tx.get(mutation),'Publication outcome uncertain; reconcile existing ref');await tx.put(mutation,{objectSHA:tag.objectSHA});});
    await current(r);requireValue(r.expiresAt>clock(),'Publication approval expired');try{await publisher.createRef(tagRef,tag.objectSHA);}catch{/* Read back a possibly successful write; never retry it. */}
    requireValue(await publisher.readRef(tagRef)===tag.objectSHA,'Publication outcome uncertain; explicit reconciliation required');
   }
   const pairedTags=Object.fromEntries(Object.entries(r.tags).map(([name,t])=>[name,{name:t.name,objectSHA:t.objectSHA,targetSHA:t.targetSHA}]));
   const receipt={schema:'repoctl-source-receipt/v1',repository:r.config.repository,repositoryID:r.repositoryID,sourceRef:r.config.sourceRef,sourceSHA:r.snapshot.sourceSHA,baseSHA:r.snapshot.mainSHA,finalSignedCommitSHA:r.finalSignedCommitSHA,treeSHA:r.snapshot.treeSHA,sequence:r.sequence,shadowRef:r.shadowRef,sourcePR:r.sourcePR,signerKeyID:r.config.signerKeyID,ownerApprovalReference:r.approvalPayload.approvalReference,hardwareApprovalVerified:true,pairedTags,artifactIntentDigest:r.artifactIntentDigest,ciReceiptDigest:r.ciReceiptDigest,reviewReceiptDigest:r.reviewReceiptDigest,scanReceiptDigest:r.scanReceiptDigest,historyDigest:r.snapshot.historyDigest};
   const receiptDigest=sha256(canonical(receipt));r={...r,state:'published',receipt,receiptDigest};await storage.transaction(async tx=>{const old=await tx.get(key(r.repositoryID,r.sequence));requireValue(old?.state==='tagged'||old?.receiptDigest===receiptDigest,'Publication state changed');await tx.put(key(r.repositoryID,r.sequence),r);const receiptKey=`source-receipt:${receiptDigest}`,previous=await tx.get(receiptKey);requireValue(!previous||canonical(previous)===canonical({repositoryID:r.repositoryID,sequence:r.sequence}),'Receipt collision');await tx.put(receiptKey,{repositoryID:r.repositoryID,sequence:r.sequence});});return {receiptDigest,receipt:clone(receipt)};
  },
  async lookupCandidate(input){
   requireValue(exact(input,['repositoryID','commitSHA','shadowRef'])&&positive(input.repositoryID)&&SHA.test(input.commitSHA)&&typeof input.shadowRef==='string','Invalid candidate lookup');const match=/^refs\/heads\/promotion\/([1-9][0-9]*)\/shadow$/.exec(input.shadowRef);requireValue(match&&positive(Number(match[1])),'Invalid immutable shadow ref');
   const r=await load({repositoryID:input.repositoryID,sequence:Number(match[1])});requireValue(['awaiting-owner','tagged','published'].includes(r.state)&&r.finalSignedCommitSHA===input.commitSHA&&r.shadowRef===input.shadowRef,'Candidate generation differs');await candidateIntegrity(r);await current(r);requireValue(await publisher.readRef(input.shadowRef)===input.commitSHA,'Shadow ref is missing or changed');await current(r);
   return {schema:'repoctl-source-candidate/v1',verified:true,repository:r.config.repository,repositoryID:r.repositoryID,commitSHA:r.finalSignedCommitSHA,treeSHA:r.snapshot.treeSHA,sourceRef:r.config.sourceRef,sourceSHA:r.snapshot.sourceSHA,expectedMainParent:r.snapshot.mainSHA,shadowRef:r.shadowRef,sourcePR:clone(r.sourcePR),sequence:r.sequence,signerKeyID:r.config.signerKeyID,unsignedCommitDigest:r.unsignedCommitDigest,artifactIntentDigest:r.artifactIntentDigest,policyDigest:r.config.policyDigest,sourceHistoryDigest:r.snapshot.historyDigest};
  },
  async lookupReviewPolicy(input){
   const candidate=await api.lookupCandidate(input),r=await load({repositoryID:input.repositoryID,sequence:candidate.sequence});await current(r);
   const accepted=r.config.candidateReviewPolicy;if(accepted===undefined)return null;
   requireValue(exact(accepted,['ownerID','reviewPolicy','scanPolicy','priorJobs','applicablePolicy','maxAgeSeconds'])&&positive(accepted.ownerID)&&positive(accepted.maxAgeSeconds)&&accepted.maxAgeSeconds<=3600&&Buffer.byteLength(canonical(accepted))<=256*1024,'Invalid retained review policy');
   requireValue(canonical(accepted.reviewPolicy)===canonical(r.config.reviewPolicy)&&canonical(accepted.scanPolicy)===canonical(r.config.scanPolicy),'Retained review policy differs');
   const jobs=accepted.priorJobs;requireValue(exact(jobs,['workflowID','workflowPath','workflowDigest','jobWorkflowRef','jobWorkflowSHA','actorIDs','requiredJobNames','scanJobName','maxAgeSeconds'])&&positive(jobs.workflowID)&&jobs.workflowPath==='.github/workflows/build.yml'&&HASH.test(jobs.workflowDigest)&&SHA.test(jobs.jobWorkflowSHA)&&jobs.jobWorkflowRef==='susanbeasles/workflow_depot/.github/workflows/orchestration.yml@'+jobs.jobWorkflowSHA&&Array.isArray(jobs.actorIDs)&&jobs.actorIDs.length>0&&jobs.actorIDs.every(positive)&&Array.isArray(jobs.requiredJobNames)&&jobs.requiredJobNames.length>0&&jobs.requiredJobNames.length<=100&&jobs.requiredJobNames.every(n=>typeof n==='string'&&n.length>0&&n.length<=300)&&new Set(jobs.requiredJobNames).size===jobs.requiredJobNames.length&&jobs.requiredJobNames.includes(jobs.scanJobName)&&positive(jobs.maxAgeSeconds)&&jobs.maxAgeSeconds<=86400,'Invalid retained prior job policy');
   await current(r);return {repositoryID:r.repositoryID,commitSHA:r.finalSignedCommitSHA,policyDigest:r.config.policyDigest,policy:{repository:r.config.repository,repositoryID:r.repositoryID,ownerID:accepted.ownerID,policyDigest:r.config.policyDigest,reviewPolicy:clone(accepted.reviewPolicy),scanPolicy:clone(accepted.scanPolicy),priorJobs:{...clone(jobs),policyDigest:r.config.policyDigest},applicablePolicy:clone(accepted.applicablePolicy),maxAgeSeconds:accepted.maxAgeSeconds}};
  },
  async lookupReceipt(input){
   requireValue(exact(input,['receiptDigest'])&&HASH.test(input.receiptDigest),'Invalid receipt lookup');const location=await storage.get(`source-receipt:${input.receiptDigest}`);requireValue(location,'Unknown verified receipt');const r=await load(location);requireValue(r.state==='published'&&r.receiptDigest===input.receiptDigest&&sha256(canonical(r.receipt))===input.receiptDigest,'Receipt integrity mismatch');await ownerProof(r,r.ownerApproval);await tagIntegrity(r);return clone(r.receipt);
  },
  async verifyPromotion(input){
   const receipt=await api.lookupReceipt(input),r=await load({repositoryID:receipt.repositoryID,sequence:receipt.sequence});
   await current(r);await evidence(r);
   for(const tag of Object.values(receipt.pairedTags))requireValue(await publisher.readRef('refs/tags/'+tag.name)===tag.objectSHA,'Published source tag changed');
   const candidate=await api.lookupCandidate({repositoryID:r.repositoryID,commitSHA:r.finalSignedCommitSHA,shadowRef:r.shadowRef});
   await ownerProof(r,r.ownerApproval);await current(r);return {receipt,candidate};
  }
 };return Object.freeze(api);
}
