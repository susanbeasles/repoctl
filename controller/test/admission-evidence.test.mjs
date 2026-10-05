import test from 'node:test';
import assert from 'node:assert/strict';
import {admissionEvidence} from '../src/evidence/admission.mjs';
import {base64,digest} from '../src/ledger.mjs';
import {signApproval} from '../src/promotion.mjs';
const hash='a'.repeat(64),a='a'.repeat(40),b='b'.repeat(40),c='c'.repeat(40);
async function fixture(){
 async function key(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);const raw=await crypto.subtle.exportKey('raw',k.publicKey);return {...k,keyID:Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),b=>b.toString(16).padStart(2,'0')).join(''),publicKeyX963:base64(raw)};}
 const owner=await key(),validator=await key();const now=Date.now();
 const trust={appID:1,installationID:2,repositoryIDs:[1],acceptedPolicyRevision:1,acceptedPolicyDigest:hash,targetRef:'refs/heads/main',audiencePrefix:'broker',repository:'owner/executor',repositoryID:2,ownerID:3,ref:'refs/heads/main',workflowRef:'owner/executor/.github/workflows/promote.yml@refs/heads/main',workflowSHA:a,jobWorkflowRef:'owner/executor/.github/workflows/executor.yml@refs/heads/main',jobWorkflowSHA:a,eventNames:['workflow_dispatch'],actorIDs:[3]};
 const policy={repositoryID:1,repository:'owner/repo',targetRef:'refs/heads/main',revision:1,digest:hash,maxIntentTTL:300,ownerKeys:[{keyID:owner.keyID,publicKeyX963:owner.publicKeyX963}],validatorKeys:[{keyID:validator.keyID,publicKeyX963:validator.publicKeyX963}],executorTrust:trust};
 const gi={baseSHA:a,commitSHA:b,sourceSHA:c,treeSHA:a},hi={repositoryID:1,sequence:1,previousDigest:hash,baseSHA:a,commitSHA:b},ai={repositoryID:1,commitSHA:b,sourceSHA:c,treeSHA:a,archiveDigests:[hash]};
 const gb={protocol:'repoctl-github-evidence-v1',intent:gi,checks:[]},hb={protocol:'repoctl-history-evidence-v1',repositoryID:1,checkpoint:{},tip:{},intent:hi},rb={protocol:'repoctl-archive-evidence-v1',intent:ai,objects:[hash],recovery:{candidate:b,source:c}};
 const g={...gb,githubVerified:true,digest:await digest(gb)},h={...hb,historyVerified:true,digest:await digest(hb)},r={...rb,archiveVerified:true,recoveryVerified:true,digest:await digest(rb)};
 const report={protocol:'repoctl-admission-evidence-v1',repositoryID:1,policyDigest:hash,githubDigest:g.digest,historyDigest:h.digest,archiveDigest:r.digest};
 const p={...hi,sourceSHA:c,treeSHA:a,policyDigest:hash,evidenceDigest:await digest(report),archiveDigests:[hash],nonce:hash,expiresAt:now+60000};
 const request={operationID:hash,repositoryID:1,intent:p,owner:await signApproval(p,'owner',owner.keyID,owner.privateKey),validator:await signApproval(p,'validator',validator.keyID,validator.privateKey)};
 const services={policy:{current:async()=>policy},github:{verify:async()=>g},history:{verify:async()=>h},archives:{verify:async()=>r},clock:()=>now};
 return {services,request,g,h,r,policy,owner,validator};
}
test('admission requires independent approvals and all three exact evidence bodies',async()=>{
 const f=await fixture();const result=await admissionEvidence(f.services).verify(f.request);assert.equal(result.verified,true);assert.equal(result.intentDigest,await digest(f.request.intent));
});
test('missing or foreign archive/history/CI evidence cannot authorize',async()=>{
 for(const mutate of [f=>f.r.recoveryVerified=false,f=>f.r.intent.sourceSHA=a,f=>f.h.historyVerified=false,f=>f.g.githubVerified=false,f=>f.r.objects=[],f=>f.g.digest=hash,f=>f.request.intent.commitSHA=c,f=>f.request.operationID='b'.repeat(64)]){
 const f=await fixture();mutate(f);await assert.rejects(admissionEvidence(f.services).verify(f.request));}
 assert.throws(()=>admissionEvidence({}));
});
test('changed approved evidence digest and policy rotation deny admission',async()=>{
 const f=await fixture();f.request.intent.evidenceDigest=hash;f.request.owner=await signApproval(f.request.intent,'owner',f.owner.keyID,f.owner.privateKey);f.request.validator=await signApproval(f.request.intent,'validator',f.validator.keyID,f.validator.privateKey);await assert.rejects(admissionEvidence(f.services).verify(f.request));
 const g=await fixture();let reads=0;g.services.policy.current=async()=>({...g.policy,digest:++reads===1?g.policy.digest:'b'.repeat(64),executorTrust:{...g.policy.executorTrust,acceptedPolicyDigest:reads===1?g.policy.digest:'b'.repeat(64)}});await assert.rejects(admissionEvidence(g.services).verify(g.request));
});
