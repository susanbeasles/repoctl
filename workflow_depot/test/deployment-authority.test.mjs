import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createDeploymentAuthority} from '../src/deployment-authority.mjs';
import {digest} from '../src/shared/contract.mjs';
import {verifyOIDC} from '../src/shared/oidc.mjs';

const hex=n=>n.repeat(64), uuid='12345678-1234-4234-8234-123456789abc';
function storage(){
 const entries=new Map();let queue=Promise.resolve();
 return {get:async k=>structuredClone(entries.get(k)),transaction(fn){
  const pending=queue.then(async()=>{const next=new Map(entries);const result=await fn({get:async k=>structuredClone(next.get(k)),put:async(k,v)=>next.set(k,structuredClone(v))});entries.clear();for(const pair of next)entries.set(...pair);return result;});
  queue=pending.catch(()=>{});return pending;
 }};
}
function trust(repository){return {audiencePrefix:'workflow-depot-deployment',repository,repositoryID:123,ownerID:215839550,ref:'refs/heads/main',workflowRef:repository+'/.github/workflows/deploy.yml@refs/heads/main',workflowSHA:'a'.repeat(40),jobWorkflowRef:repository+'/.github/workflows/deploy.yml@refs/heads/main',jobWorkflowSHA:'a'.repeat(40),eventNames:['workflow_dispatch'],actorIDs:[215839550]};}
async function fixture(overrides={}){
 let time=1000,effect=async op=>proof(op),counter=0;
 const policy={schema:'workflow-depot-cloudflare-policy/v1',revision:1,enabled:true,authorizer:{...trust('susanbeasles/delivery_control'),audiencePrefix:'delivery-control-authorize'},executor:trust('susanbeasles/delivery_control'),targets:[{accountID:'a'.repeat(32),scriptName:'existing-worker',zoneID:'b'.repeat(32),hostname:'app.vespoli.me',metadataDigest:hex('c'),sourceRepository:'susanbeasles/source',sourceRepositoryID:456}],maxArtifactBytes:1048576,verification:{signerKeyIDs:[hex('d')],ciWorkflowRef:'susanbeasles/source/.github/workflows/ci.yml@refs/heads/main',ciWorkflowSHA:'e'.repeat(40),requiredJobs:['test']}};
 const operation={schema:'workflow-depot-cloudflare-deploy/v1',operationID:hex('1'),nonce:hex('2'),policyDigest:await digest(policy),artifactDigest:hex('3'),metadataDigest:hex('c'),accountID:'a'.repeat(32),scriptName:'existing-worker',zoneID:'b'.repeat(32),hostname:'app.vespoli.me',expectedDeploymentID:uuid,source:{repository:'susanbeasles/source',repositoryID:456,commitSHA:'f'.repeat(40),signerKeyID:hex('d'),signingReceiptDigest:hex('5'),ciRunID:50,ciRunAttempt:1},execution:{runID:60,runAttempt:1},expiresAt:1100};
 const identities=[];
 const authority=createDeploymentAuthority({storage:storage(),policy:()=>policy,evidence:{verify:async op=>effect(op)},now:()=>time,jwks:async()=>({keys:[]}),verifyIdentity:async(token,t,expected)=>{identities.push({token,trust:t,expected});if(token==='wrong')throw Error('wrong-identity');return {jti:token,runID:String(expected.runID),runAttempt:String(expected.runAttempt),expiresAt:1090,workflowSHA:t.workflowSHA};},...overrides});
 const authorize=()=>authority.authorize({operation,oidcToken:'authorizer-'+(++counter),authorizerRunID:70,authorizerRunAttempt:1});
 const consume=(token='executor')=>authority.consume({operationID:operation.operationID,oidcToken:token});
 const revoke=()=>authority.revoke({operation,oidcToken:'revoke-'+(++counter),authorizerRunID:70,authorizerRunAttempt:1});
 return {authority,policy,operation,authorize,consume,revoke,identities,setTime:v=>{time=v;},setEvidence:v=>{effect=v;}};
}
function proof(op){return {verified:true,operationID:op.operationID,artifactDigest:op.artifactDigest,sourceSHA:op.source.commitSHA};}

test('authority requires independent evidence and atomic storage',()=>{
 assert.throws(()=>createDeploymentAuthority({storage:storage(),policy:()=>({})}),/evidence-required/);
 assert.throws(()=>createDeploymentAuthority({storage:{},policy:()=>({}),evidence:{verify(){}}}),/atomic-storage-required/);
});
test('exact retained operation advances through one-time upload and activation checks',async()=>{
 const f=await fixture();let evidenceChecks=0;f.setEvidence(async op=>{evidenceChecks++;return proof(op);});
 assert.deepEqual(await f.authorize(),{operationID:f.operation.operationID,state:'authorized'});
 const lease=await f.consume();assert.deepEqual(lease.operation,f.operation);assert.match(lease.leaseID,/^[a-f0-9]{64}$/);
 assert.equal(lease.identityExpiresAt,1090);
 for(const stage of ['upload','activate'])assert.deepEqual(await f.authority.check({operationID:f.operation.operationID,leaseID:lease.leaseID,stage}),lease);
 assert.equal(evidenceChecks,3);
 assert.deepEqual(await f.authority.complete({operationID:f.operation.operationID,leaseID:lease.leaseID,outcome:'completed',receipt:{versionID:uuid,deploymentID:uuid}}),{operationID:f.operation.operationID,state:'completed'});
 await assert.rejects(f.consume(),/operation-not-authorized/);
 assert.equal(f.identities[0].trust.repository,'susanbeasles/delivery_control');assert.equal(f.identities[1].trust.repository,'susanbeasles/delivery_control');
 assert.deepEqual(f.identities[1].expected,{operationID:f.operation.operationID,runID:60,runAttempt:1});
});
test('concurrent authorization and consumption allow exactly one transition',async()=>{
 const f=await fixture();const authorized=await Promise.allSettled([f.authorize(),f.authorize()]);assert.equal(authorized.filter(x=>x.status==='fulfilled').length,1);
 const consumed=await Promise.allSettled([f.consume('one'),f.consume('two')]);assert.equal(consumed.filter(x=>x.status==='fulfilled').length,1);
 const lease=consumed.find(x=>x.status==='fulfilled').value;
 const checked=await Promise.allSettled([1,2].map(()=>f.authority.check({operationID:f.operation.operationID,leaseID:lease.leaseID,stage:'upload'})));assert.equal(checked.filter(x=>x.status==='fulfilled').length,1);
});
test('nonce collision and changed operation cannot replace retained authorization',async()=>{
 const f=await fixture();await f.authorize();f.operation.operationID=hex('6');await assert.rejects(f.authorize(),/nonce-replayed/);
 f.operation.operationID=hex('1');f.operation.artifactDigest=hex('7');await assert.rejects(f.authorize(),/operation-exists/);
 const lease=await f.consume();assert.equal(lease.operation.artifactDigest,hex('3'));
});
test('missing, false, throwing or mutated evidence cannot authorize',async()=>{
 for(const check of [async()=>undefined,async()=>({verified:false}),async()=>{throw Error('sensitive-upstream-body');},async op=>{op.artifactDigest=hex('9');return {verified:true};}]){
  const f=await fixture();f.setEvidence(check);await assert.rejects(f.authorize());
 }
});
test('revocation during evidence await prevents upload authorization',async()=>{
 const f=await fixture();await f.authorize();const lease=await f.consume();let release,started;const ready=new Promise(r=>{started=r;});f.setEvidence(async op=>{started();await new Promise(r=>{release=r;});return proof(op);});
 const pending=f.authority.check({operationID:f.operation.operationID,leaseID:lease.leaseID,stage:'upload'});await ready;await f.revoke();release();await assert.rejects(pending,/operation-revoked/);
});
test('policy drift and expiry after fresh evidence prevent execution',async()=>{
 for(const mutate of [f=>{f.policy.revision++;},f=>f.setTime(1090)]){
  const f=await fixture();await f.authorize();const lease=await f.consume();f.setEvidence(async op=>{mutate(f);return proof(op);});
  await assert.rejects(f.authority.check({operationID:f.operation.operationID,leaseID:lease.leaseID,stage:'upload'}));
 }
});
test('foreign or incomplete independent proof cannot authorize the operation',async()=>{
 for(const value of [{verified:true},{...proof({operationID:hex('9'),artifactDigest:hex('3'),source:{commitSHA:'f'.repeat(40)}})},{verified:true,operationID:hex('1'),artifactDigest:hex('3'),sourceSHA:'f'.repeat(40),extra:true}]){
  const f=await fixture();f.setEvidence(async()=>value);await assert.rejects(f.authorize(),/evidence-rejected/);
 }
});
test('target lock serializes different operations and retains uncertain outcomes',async()=>{
 const f=await fixture();await f.authorize();const lease=await f.consume();
 f.operation.operationID=hex('6');f.operation.nonce=hex('7');await f.authorize();await assert.rejects(f.consume('another-executor'),/target-locked/);
 await f.authority.complete({operationID:hex('1'),leaseID:lease.leaseID,outcome:'uncertain',receipt:{versionID:null,deploymentID:null}});
 await assert.rejects(f.consume('fresh-executor'),/target-locked/);
});
test('activation cannot precede upload, bad leases fail, and terminal state cannot reset',async()=>{
 const f=await fixture();await f.authorize();const lease=await f.consume();
 await assert.rejects(f.authority.check({operationID:f.operation.operationID,leaseID:lease.leaseID,stage:'activate'}),/stage-conflict/);
 await assert.rejects(f.authority.check({operationID:f.operation.operationID,leaseID:hex('9'),stage:'upload'}),/lease-mismatch/);
 await assert.rejects(f.authority.complete({operationID:f.operation.operationID,leaseID:lease.leaseID,outcome:'completed',receipt:{versionID:uuid,deploymentID:uuid}}),/stage-conflict/);
 await f.authority.complete({operationID:f.operation.operationID,leaseID:lease.leaseID,outcome:'uncertain',receipt:{versionID:null,deploymentID:null}});
 await assert.rejects(f.authority.check({operationID:f.operation.operationID,leaseID:lease.leaseID,stage:'upload'}),/stage-conflict/);
 await assert.rejects(f.authority.complete({operationID:f.operation.operationID,leaseID:lease.leaseID,outcome:'uncertain',receipt:{versionID:null,deploymentID:null}}),/terminal-state/);
});
test('authorization rejects wrong identity, caller authority fields, and unsafe receipts',async()=>{
 const f=await fixture();await assert.rejects(f.authority.authorize({operation:f.operation,oidcToken:'wrong',authorizerRunID:70,authorizerRunAttempt:1}));
 await assert.rejects(f.authority.authorize({operation:f.operation,oidcToken:'x',authorizerRunID:70,authorizerRunAttempt:1,approved:true}),/invalid-request/);
 await f.authorize();const lease=await f.consume();
 await assert.rejects(f.authority.complete({operationID:f.operation.operationID,leaseID:lease.leaseID,outcome:'uncertain',receipt:{versionID:null,deploymentID:null,secret:'do-not-store'}}),/invalid-receipt/);
});

test('real signed GitHub OIDC authorizer cannot impersonate the executor or change its run',async()=>{
 const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
 const key=await crypto.subtle.exportKey('jwk',pair.publicKey);key.kid='synthetic';
 const f=await fixture({verifyIdentity:verifyOIDC,jwks:async()=>({keys:[key]})});let count=0;
 async function signed(trust,runID,extra={}){
  const claims={iss:'https://token.actions.githubusercontent.com',aud:trust.audiencePrefix+':'+f.operation.operationID,exp:1090,iat:990,nbf:990,repository:trust.repository,repository_id:String(trust.repositoryID),repository_owner_id:String(trust.ownerID),ref:trust.ref,workflow_ref:trust.workflowRef,workflow_sha:trust.workflowSHA,job_workflow_ref:trust.jobWorkflowRef,job_workflow_sha:trust.jobWorkflowSHA,runner_environment:'github-hosted',run_id:String(runID),run_attempt:'1',event_name:'workflow_dispatch',actor_id:'215839550',jti:'synthetic-identity-'+(++count),...extra};
  const body=Buffer.from(JSON.stringify({alg:'RS256',kid:key.kid})).toString('base64url')+'.'+Buffer.from(JSON.stringify(claims)).toString('base64url');
  return body+'.'+Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,new TextEncoder().encode(body))).toString('base64url');
 }
 await f.authority.authorize({operation:f.operation,oidcToken:await signed(f.policy.authorizer,70),authorizerRunID:70,authorizerRunAttempt:1});
 await assert.rejects(f.authority.consume({operationID:f.operation.operationID,oidcToken:await signed(f.policy.authorizer,60)}));
 await assert.rejects(f.authority.consume({operationID:f.operation.operationID,oidcToken:await signed(f.policy.executor,61)}));
 const lease=await f.authority.consume({operationID:f.operation.operationID,oidcToken:await signed(f.policy.executor,60)});assert.equal(lease.operation.operationID,f.operation.operationID);
});
test('completed operations release targets but retained OIDC tombstones reject reuse',async()=>{
 const f=await fixture();await f.authorize();const lease=await f.consume('same-identity');
 for(const stage of ['upload','activate'])await f.authority.check({operationID:f.operation.operationID,leaseID:lease.leaseID,stage});
 await f.authority.complete({operationID:f.operation.operationID,leaseID:lease.leaseID,outcome:'completed',receipt:{versionID:uuid,deploymentID:uuid}});
 f.operation.operationID=hex('6');f.operation.nonce=hex('7');await f.authorize();await assert.rejects(f.consume('same-identity'),/identity-replayed/);
 assert.equal((await f.consume('new-identity')).operation.operationID,hex('6'));
});
test('identity expiry after authorization evidence and disabled policy fail closed',async()=>{
 const f=await fixture();f.setEvidence(async op=>{f.setTime(1090);return proof(op);});await assert.rejects(f.authorize(),/identity-expired/);
 const disabled=await fixture();disabled.policy.enabled=false;await assert.rejects(disabled.authorize(),/authority-disabled/);
});
test('executor readiness authenticates without consuming and binds the admitted execution',async()=>{
 const f=await fixture(),input={operationID:f.operation.operationID,oidcToken:'executor-status',runID:60,runAttempt:1};
 assert.deepEqual(await f.authority.status(input),{operationID:input.operationID,state:'pending'});
 await assert.rejects(f.authority.status({...input,oidcToken:'wrong'}));
 await f.authorize();assert.deepEqual(await f.authority.status(input),{operationID:input.operationID,state:'authorized'});
 await assert.rejects(f.authority.status({...input,runID:61}));
 const lease=await f.consume(input.oidcToken);assert.equal(lease.operation.operationID,input.operationID);
 await assert.rejects(f.authority.status(input));
});
