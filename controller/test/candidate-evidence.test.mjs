import {createHash} from 'node:crypto';import {test} from 'node:test';import assert from 'node:assert/strict';import {candidateEvidence} from '../src/evidence/candidate.ts';
const recipe=Buffer.from('trusted recipe'),workflowDigest=createHash('sha256').update(recipe).digest('hex');
const sha=c=>c.repeat(40),intent={baseSHA:sha('a'),commitSHA:sha('b'),sourceSHA:sha('c'),treeSHA:sha('d')};
function fixture(){const candidate={sha:intent.commitSHA,parents:[{sha:intent.baseSHA}],tree:{sha:intent.treeSHA},verification:{verified:true,reason:'valid'}},check={name:'security',id:1,head_sha:intent.commitSHA,status:'completed',conclusion:'success',app:{id:2},check_suite:{id:3}},run={id:4,check_suite_id:3,head_sha:intent.commitSHA,workflow_id:5,path:'.github/workflows/security.yml',status:'completed',conclusion:'success',event:'push',head_branch:'int/pr-1',actor:{id:6},triggering_actor:{id:6},run_attempt:1};let tips=0;const github={tip:async()=>{tips++;return intent.baseSHA;},commit:async s=>s===intent.commitSHA?candidate:{sha:intent.sourceSHA},checks:async()=>[check],runForSuite:async()=>run,workflowBytes:async()=>recipe};const config={github,repositoryID:7,signatures:{verify:async b=>({...b,verified:true})},requiredChecks:[{name:'security',appID:2,workflowID:5,workflowPath:run.path,workflowDigest}],actorIDs:[6]};return {candidate,check,run,github,config,verify:()=>candidateEvidence(config).verify(intent)};}
test('GitHub candidate evidence binds signed single child and exact successful execution',async()=>{const f=fixture(),r=await f.verify();assert.equal(r.githubVerified,true);assert.equal(r.verified,undefined);assert.equal(r.checks[0].runID,4);});
test('failed, spoofed, dispatch, stale or outsider CI cannot produce evidence',async()=>{for(const mutate of [f=>f.github.workflowBytes=async()=>Buffer.from('tampered recipe'),f=>f.check.conclusion='failure',f=>f.check.app.id=9,f=>f.check.head_sha=sha('e'),f=>f.run.event='workflow_dispatch',f=>f.run.head_sha=sha('e'),f=>f.run.actor.id=9,f=>f.run.triggering_actor.id=9,f=>f.run.path='.github/workflows/other.yml',f=>f.run.head_branch='main',f=>f.candidate.verification.verified=false,f=>f.candidate.parents.push({sha:sha('e')}),f=>f.candidate.tree.sha=sha('e'),f=>f.github.checks=async()=>[f.check,f.check]]){const f=fixture();mutate(f);await assert.rejects(f.verify());}});
test('moving main and empty CI policy reject',async()=>{const f=fixture();let reads=0;f.github.tip=async()=>++reads===1?intent.baseSHA:sha('e');await assert.rejects(f.verify());assert.throws(()=>candidateEvidence({...f.config,requiredChecks:[]}));});

test('GitHub-valid candidate cannot produce admission evidence without the designated signer capability',async()=>{
 const f=fixture();
 for(const verify of [async b=>({...b,verified:false}),async b=>({...b,repositoryID:8,verified:true}),async()=>{throw Error('SECRET-SIGNATURE-MARKER');}]){
  await assert.rejects(candidateEvidence({...f.config,repositoryID:7,signatures:{verify}}).verify(intent),error=>!error.message.includes('SECRET-SIGNATURE-MARKER'));
 }
 assert.throws(()=>candidateEvidence({...f.config,repositoryID:7,signatures:undefined}),/signature/i);
});

test('candidate signer revocation during CI prevents evidence confirmation',async()=>{
 const f=fixture();let calls=0;
 const signatures={verify:async b=>({...b,verified:++calls===1})};
 await assert.rejects(candidateEvidence({...f.config,signatures}).verify(intent),/signature rejected/);
 assert.equal(calls,2);
});

test('stalled designated signer times out without provider access or secret errors',async()=>{
 const f=fixture();let calls=0,signal;
 f.github.tip=async()=>{calls++;return intent.baseSHA;};
 const signatures={verify:async (_candidate,options)=>{signal=options.signal;return new Promise(()=>{});}};
 await assert.rejects(candidateEvidence({...f.config,signatures,timeoutMS:100}).verify(intent),/signature unavailable/);
 assert.equal(signal.aborted,true);assert.equal(calls,0);
});

test('caller edits during signer verification cannot change candidate evidence bindings',async()=>{
 const f=fixture(),request={...intent};
 const signatures={verify:async b=>{request.commitSHA=sha('e');return {...b,verified:true};}};
 const report=await candidateEvidence({...f.config,signatures}).verify(request);
 assert.deepEqual(report.intent,intent);assert.equal(report.intent.commitSHA,sha('b'));
});
