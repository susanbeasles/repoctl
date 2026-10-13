import test from 'node:test';
import assert from 'node:assert/strict';
import {deploymentEvidence} from '../src/deployment-evidence.mjs';
import {digest} from '../src/shared/contract.mjs';
import {readFile} from 'node:fs/promises';

async function fixture(){
 const source={repository:'owner/app',repositoryID:7,commitSHA:'a'.repeat(40),signerKeyID:'b'.repeat(64),ciRunID:81,ciRunAttempt:1};
 const receipt={schema:'repoctl-source-receipt/v1',repository:source.repository,repositoryID:7,sourceRef:'refs/heads/feature/reviewed',sourceSHA:'c'.repeat(40),baseSHA:'d'.repeat(40),finalSignedCommitSHA:source.commitSHA,treeSHA:'e'.repeat(40),sequence:3,signerKeyID:source.signerKeyID,ownerApprovalReference:'f'.repeat(64),hardwareApprovalVerified:true,pairedTags:{source:{name:'promotion/3/source',objectSHA:'1'.repeat(40),targetSHA:'c'.repeat(40)},main:{name:'promotion/3/main',objectSHA:'2'.repeat(40),targetSHA:source.commitSHA}}};
 receipt.shadowRef='refs/heads/int/feature/reviewed';source.signingReceiptDigest=await digest(receipt);
 const operation={operationID:'9'.repeat(64),artifactDigest:'8'.repeat(64),metadataDigest:'7'.repeat(64),source};
 const verification={signerKeyIDs:[source.signerKeyID],ciWorkflowRef:'owner/workflow_depot/.github/workflows/build-cloudflare.yml@'+'6'.repeat(40),ciWorkflowSHA:'6'.repeat(40),requiredJobs:['Build approved artifact']};
 const run={id:81,run_attempt:1,head_sha:source.commitSHA,head_branch:'int/feature/reviewed',event:'push',status:'completed',conclusion:'success',repository:{id:7,full_name:source.repository},referenced_workflows:[{path:verification.ciWorkflowRef,sha:verification.ciWorkflowSHA}]};
 const commit={sha:source.commitSHA,tree:{sha:receipt.treeSHA},parents:[{sha:receipt.baseSHA}],verification:{verified:true,reason:'valid'}};
 const provenance={schema:'workflow-depot-build-provenance/v1',repository:source.repository,repositoryID:7,sourceSHA:source.commitSHA,sourceRef:receipt.shadowRef,artifactDigest:operation.artifactDigest,metadataDigest:operation.metadataDigest,runID:81,runAttempt:1,workflowRef:verification.ciWorkflowRef,workflowSHA:verification.ciWorkflowSHA};
 const data={'':{id:7,full_name:source.repository,archived:false,fork:false,default_branch:'main'},'/git/ref/heads/main':{object:{sha:source.commitSHA}},['/git/commits/'+source.commitSHA]:commit,'/actions/runs/81':run,'/actions/runs/81/attempts/1/jobs?per_page=100&page=1':{total_count:1,jobs:[{name:'Build approved artifact',status:'completed',conclusion:'success',head_sha:source.commitSHA}]}};
 let receiptReads=0,provenanceReads=0;const hooks={};
 const evidence=deploymentEvidence({policy:{verification},github:{read:async(repo,path)=>{assert.equal(repo,source.repository);assert.ok(Object.hasOwn(data,path));await hooks.read?.(path);return structuredClone(data[path]);}},signingReceipts:{lookupReceipt:async()=>{receiptReads++;return structuredClone(receipt);}},provenance:{lookup:async()=>{provenanceReads++;return structuredClone(provenance);}}});
 return {operation,evidence,data,receipt,provenance,verification,hooks,reads:()=>({receiptReads,provenanceReads})};
}
test('binds current signed main, exact paired-tag receipt, required CI and immutable artifact provenance',async()=>{
 const f=await fixture();assert.deepEqual(await f.evidence.verify(f.operation),{verified:true,operationID:f.operation.operationID,artifactDigest:f.operation.artifactDigest,sourceSHA:f.operation.source.commitSHA});assert.deepEqual(f.reads(),{receiptReads:1,provenanceReads:1});
});
test('rejects unsigned, drifted, foreign or unapproved source and skipped required checks',async()=>{
 const mutations=[f=>f.data[''].id++,f=>f.data['/git/ref/heads/main'].object.sha='0'.repeat(40),f=>f.data['/git/commits/'+f.operation.source.commitSHA].verification.verified=false,f=>f.data['/actions/runs/81'].head_sha='0'.repeat(40),f=>f.data['/actions/runs/81'].referenced_workflows[0].sha='0'.repeat(40),f=>f.data['/actions/runs/81/attempts/1/jobs?per_page=100&page=1'].jobs[0].conclusion='skipped',f=>f.verification.signerKeyIDs=[]];
 for(const mutate of mutations){const f=await fixture();mutate(f);await assert.rejects(f.evidence.verify(f.operation));}
});
test('rejects missing, altered or wrongly linked signing receipts and foreign provenance',async()=>{
 for(const mutate of [f=>f.receipt.hardwareApprovalVerified=false,f=>f.receipt.pairedTags.main.targetSHA='0'.repeat(40),f=>f.provenance.artifactDigest='0'.repeat(64),f=>f.provenance.sourceSHA='0'.repeat(40),f=>f.provenance.runAttempt=2]){const f=await fixture();mutate(f);await assert.rejects(f.evidence.verify(f.operation));}
});
test('evidence dependencies are mandatory and errors do not expose provider payloads',async()=>{
 assert.throws(()=>deploymentEvidence({policy:{verification:{}},github:{read(){}},signingReceipts:{lookupReceipt(){}}}));
 const f=await fixture();f.data['/actions/runs/81'].conclusion='failure';await assert.rejects(f.evidence.verify(f.operation),/Deployment evidence denied/);
});
test('denies main movement during asynchronous receipt and CI inspection',async()=>{
 const f=await fixture();f.hooks.read=path=>{if(path.includes('/jobs?'))f.data['/git/ref/heads/main'].object.sha='0'.repeat(40);};
 await assert.rejects(f.evidence.verify(f.operation),/Deployment evidence denied/);
});
test('denies malformed or incomplete job inventories',async()=>{
 for(const mutate of [r=>r.total_count=-1,r=>r.total_count=0,r=>r.total_count=2,r=>r.jobs=Array(101).fill(r.jobs[0])]){
  const f=await fixture();mutate(f.data['/actions/runs/81/attempts/1/jobs?per_page=100&page=1']);await assert.rejects(f.evidence.verify(f.operation));
 }
 const f=await fixture(),key='/actions/runs/81/attempts/1/jobs?per_page=100&page=';
 f.data[key+'1'].total_count=101;f.data[key+'1'].jobs.push(...Array.from({length:99},(_,i)=>({name:'extra-'+i})));
 f.data[key+'2']={total_count:102,jobs:[{name:'last'}]};await assert.rejects(f.evidence.verify(f.operation));
});
test('post-main rebuild cannot substitute for the accepted candidate build',async()=>{
 const f=await fixture();f.data['/actions/runs/81'].head_branch='main';f.provenance.sourceRef='refs/heads/main';await assert.rejects(f.evidence.verify(f.operation));
});
