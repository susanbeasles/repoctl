import test from 'node:test';
import assert from 'node:assert/strict';
import * as handoff from '../src/source-signing/promotion.mjs';
import {canonical,digest,base64} from '../src/ledger.mjs';
import {signApproval} from '../src/promotion.mjs';
import {admissionEvidence} from '../src/evidence/admission.mjs';
import {authorize} from '../src/authority/authorize.mjs';
const sha=c=>c.repeat(40),hash=c=>c.repeat(64);
function memory(){const data=new Map();let tail=Promise.resolve();const s={get:async k=>structuredClone(data.get(k)),put:async(k,v)=>data.set(k,structuredClone(v)),transaction(fn){const work=tail.then(()=>fn(s));tail=work.catch(()=>{});return work;}};return s;}
async function fixture(){
 let now=1000000;
 async function signer(){const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),raw=await crypto.subtle.exportKey('raw',pair.publicKey);return {...pair,keyID:await digest([...new Uint8Array(raw)]),raw};}
 const owner=await signer(),validator=await signer();
 for(const key of [owner,validator])key.keyID=Buffer.from(await crypto.subtle.digest('SHA-256',key.raw)).toString('hex');
 const trust={appID:1,installationID:2,repositoryIDs:[7],acceptedPolicyRevision:1,acceptedPolicyDigest:hash('b'),targetRef:'refs/heads/main',audiencePrefix:'repoctl',repository:'owner/delivery_control',repositoryID:10,ownerID:20,ref:'refs/heads/main',workflowRef:'owner/delivery_control/.github/workflows/promote.yml@refs/heads/main',workflowSHA:sha('a'),jobWorkflowRef:'owner/delivery_control/.github/workflows/executor.yml@refs/heads/main',jobWorkflowSHA:sha('a'),eventNames:['workflow_dispatch'],actorIDs:[30]};
 const policy={repositoryID:7,repository:'owner/project',targetRef:'refs/heads/main',revision:1,digest:hash('b'),maxIntentTTL:300,ownerKeys:[{keyID:owner.keyID,publicKeyX963:base64(owner.raw)}],validatorKeys:[{keyID:validator.keyID,publicKeyX963:base64(validator.raw)}],executorTrust:trust};
 const receipt={schema:'repoctl-source-receipt/v1',repository:policy.repository,repositoryID:7,sourceRef:'refs/heads/source',sourceSHA:sha('c'),baseSHA:sha('a'),finalSignedCommitSHA:sha('d'),treeSHA:sha('e'),sequence:13,shadowRef:'refs/heads/promotion/13/shadow',sourcePR:{number:4,repositoryID:7,headSHA:sha('c')},signerKeyID:'SHA256:'+Buffer.alloc(32).toString('base64').replace(/=/g,''),ownerApprovalReference:hash('1'),hardwareApprovalVerified:true,pairedTags:{source:{name:'promotion/13/source',objectSHA:sha('1'),targetSHA:sha('c')},main:{name:'promotion/13/main',objectSHA:sha('2'),targetSHA:sha('d')}},artifactIntentDigest:hash('2'),ciReceiptDigest:hash('3'),reviewReceiptDigest:hash('4'),scanReceiptDigest:hash('5'),historyDigest:hash('6')};
 const receiptDigest=await digest(receipt),candidate={schema:'repoctl-source-candidate/v1',verified:true,repository:policy.repository,repositoryID:7,commitSHA:sha('d'),treeSHA:sha('e'),sourceRef:receipt.sourceRef,sourceSHA:sha('c'),expectedMainParent:sha('a'),shadowRef:receipt.shadowRef,sourcePR:receipt.sourcePR,sequence:13,signerKeyID:receipt.signerKeyID,unsignedCommitDigest:hash('7'),artifactIntentDigest:receipt.artifactIntentDigest,policyDigest:policy.digest,sourceHistoryDigest:receipt.historyDigest};
 const anchor={repositoryID:7,startSequence:0,startDigest:hash('0'),startCommit:sha('0'),endSequence:3,endDigest:hash('8'),endCommit:sha('a')},storage=memory();
 const policyAdapter={current:async()=>policy};
 const admission=admissionEvidence({policy:policyAdapter,clock:()=>now,
  github:{verify:async intent=>{const body={protocol:'repoctl-github-evidence-v1',intent,checks:[]};return {...body,githubVerified:true,digest:await digest(body)};}},
  history:{verify:async intent=>{const body={protocol:'repoctl-history-evidence-v1',repositoryID:7,checkpoint:anchor,tip:{sha:anchor.endCommit},intent};return {...body,historyVerified:true,digest:await digest(body)};}},
  archives:{verify:async intent=>{const body={protocol:'repoctl-archive-evidence-v1',intent,objects:[receipt.historyDigest],recovery:{candidate:receipt.finalSignedCommitSHA,source:receipt.sourceSHA}};return {...body,archiveVerified:true,recoveryVerified:true,digest:await digest(body)};}}});
 const source={verifyPromotion:async()=>({receipt,candidate})},checkpoint={current:async()=>anchor};
 const create=()=>handoff.createSourcePromotion({storage,source,policy:policyAdapter,checkpoint,admission,clock:()=>now});
 const proposal={receiptDigest,nonce:hash('9'),expiresAt:now+200000};
 async function bundleFor(intent){const approvals={owner:await signApproval(intent,'owner',owner.keyID,owner.privateKey),validator:await signApproval(intent,'validator',validator.keyID,validator.privateKey)},run={operationID:intent.nonce,approvalDigest:await digest(approvals),repositoryID:7,repository:policy.repository,targetRef:policy.targetRef,policyRevision:1,policyDigest:policy.digest,executorTrustDigest:await digest(trust),runID:60,runAttempt:1,expiresAt:Math.floor(intent.expiresAt/1000)};const payload=canonical(run),signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},owner.privateKey,Buffer.from('repoctl-execution-owner-v1\n'+payload));return {...approvals,executionOwner:{protocol:'repoctl-execution-owner-v1',keyID:owner.keyID,encoding:'p1363',payload:base64(Buffer.from(payload)),signature:base64(signature)}};}
 const services={storage,policy:policyAdapter,hardware:{verify:async()=>({keyID:owner.keyID,proofDigest:hash('f'),hardwareVerified:true,revoked:false,validUntil:Math.floor(now/1000)+1000})}};
 return {create,proposal,receipt,candidate,anchor,storage,source,policy,admission,services,bundleFor,advance:n=>now+=n,now:()=>now};
}
test('source receipt constructs existing intent with independent ledger sequence then actual authority verifies all three envelopes',async()=>{
 const f=await fixture();assert.equal(typeof handoff.createSourcePromotion,'function');const bridge=f.create(),intent=await bridge.prepare(f.proposal);
 assert.equal(intent.sequence,4);assert.notEqual(intent.sequence,f.receipt.sequence);assert.equal(intent.previousDigest,f.anchor.endDigest);assert.equal(intent.commitSHA,f.receipt.finalSignedCommitSHA);assert.equal(intent.expiresAt,f.proposal.expiresAt);
 const result=await authorize(await f.bundleFor(intent),{...f.services,evidence:bridge},Math.floor(f.now()/1000));assert.equal(result.state,'authorized');assert.equal(result.runID,60);
 assert.equal((await f.storage.get('authority:'+intent.nonce)).record.intent.commitSHA,intent.commitSHA);
});
test('altered receipt, foreign policy and checkpoint parent mismatch fail before retaining an intent',async()=>{
 for(const change of [f=>f.receipt.treeSHA=sha('f'),f=>f.candidate.policyDigest=hash('f'),f=>f.anchor.endCommit=sha('f'),f=>f.candidate.sourceSHA=sha('f')]){const f=await fixture();change(f);await assert.rejects(f.create().prepare(f.proposal));assert.equal(await f.storage.get('source-promotion:'+f.proposal.nonce),undefined);}
});
test('retained operation prevents replacement and rechecks source/ledger after independent evidence',async()=>{
 const f=await fixture(),bridge=f.create(),intent=await bridge.prepare(f.proposal);await assert.rejects(bridge.prepare({...f.proposal,expiresAt:f.proposal.expiresAt-1}));
 const bundle=await f.bundleFor(intent),verify=f.admission.verify;f.admission.verify=async request=>{const result=await verify(request);f.anchor.endSequence++;return result;};
 await assert.rejects(authorize(bundle,{...f.services,evidence:bridge},Math.floor(f.now()/1000)));assert.equal(await f.storage.get('authority:'+intent.nonce),undefined);
});
test('source approval and missing validator/execution approval never substitute for promotion authority',async()=>{
 const f=await fixture(),bridge=f.create(),intent=await bridge.prepare(f.proposal),bundle=await f.bundleFor(intent);
 for(const changed of [{owner:bundle.owner},{...bundle,validator:bundle.owner},{...bundle,executionOwner:bundle.owner},{...bundle,owner:{...bundle.owner,payload:base64(Buffer.from(canonical(f.receipt)))}}])await assert.rejects(authorize(changed,{...f.services,evidence:bridge},Math.floor(f.now()/1000)));
 assert.equal(await f.storage.get('authority:'+intent.nonce),undefined);
});
test('expiry during read-only evidence or durable proposal reservation cannot return usable authority',async()=>{
 for(const stage of ['evidence','storage']){const f=await fixture();if(stage==='evidence'){const inspect=f.admission.inspect;f.admission.inspect=async intent=>{const result=await inspect(intent);f.advance(300000);return result;};}else{const transaction=f.storage.transaction;f.storage.transaction=fn=>transaction(async tx=>{const result=await fn(tx);f.advance(300000);return result;});}await assert.rejects(f.create().prepare(f.proposal));}
});
