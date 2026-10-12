import {test} from 'node:test';
import assert from 'node:assert/strict';
import {executionRequest} from '../src/execution/http.mjs';
import * as broker from '../src/authorization/broker.mjs';
import {durableOperations} from '../src/runtime/state.mjs';

const id='a'.repeat(64),sha=c=>c.repeat(40);
const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
const key={...await crypto.subtle.exportKey('jwk',pair.publicKey),kid:'check-fixture'};
async function fixture(){
 let now=Math.floor(Date.now()/1000),checks=0,credentials=0;
 const start=now,data=new Map();let tail=Promise.resolve(),alarm=null;
 const db={get:async k=>structuredClone(data.get(k)),put:async(k,v)=>data.set(k,structuredClone(v)),getAlarm:async()=>alarm,setAlarm:async t=>{alarm=t;},transaction(fn){const work=tail.then(()=>fn(db));tail=work.catch(()=>{});return work;}};
 const trust={audiencePrefix:'repoctl',repository:'owner/delivery_control',repositoryID:10,ownerID:20,ref:'refs/heads/main',workflowRef:'owner/delivery_control/.github/workflows/promote.yml@refs/heads/main',workflowSHA:sha('a'),jobWorkflowRef:'owner/delivery_control/.github/workflows/executor.yml@refs/heads/main',jobWorkflowSHA:sha('a'),actorIDs:[30],eventNames:['workflow_dispatch'],installationID:50,repositoryIDs:[7],acceptedPolicyRevision:1,acceptedPolicyDigest:'b'.repeat(64),targetRef:'refs/heads/main'};
 const operation={id,state:'authorized',operation:'promote',expiresAt:start+200,authorizationProvider:'hardware',hardwareEnrollmentVerified:true,policyRevision:1,policyDigest:trust.acceptedPolicyDigest,targetRef:trust.targetRef,repositoryID:7,runID:60,runAttempt:1};
 const intent={repository:'owner/project',repositoryID:7,branch:'main',baseSHA:sha('b'),commitSHA:sha('c'),treeSHA:sha('d')};
 const ops=durableOperations(db,()=>now);await ops.retain({operation,intent,trust});
 const lease={operationID:id,jti:'original-lease-token',runID:'60',runAttempt:'1',state:'issuing',expiresAt:start+150};
 await ops.reserve(lease);await ops.issued({...lease,state:'issued',providerExpiresAt:start+3600});
 const services={operations:ops,serialize:async(_,fn)=>fn(),jwks:async()=>({keys:[key]}),executionIntent:async()=>intent,verifyAuthorization:async()=>{checks++;},credentials:{issueInstallationToken:async()=>{credentials++;throw Error('must not issue');},revoke:async()=>{credentials++;throw Error('must not revoke');}}};
 async function token(patch={}){
  const c={iss:'https://token.actions.githubusercontent.com',aud:`repoctl:${id}`,iat:start,nbf:start,exp:start+300,repository:trust.repository,repository_id:'10',repository_owner_id:'20',ref:trust.ref,workflow_ref:trust.workflowRef,workflow_sha:trust.workflowSHA,job_workflow_ref:trust.jobWorkflowRef,job_workflow_sha:trust.jobWorkflowSHA,actor_id:'30',event_name:'workflow_dispatch',runner_environment:'github-hosted',run_id:'60',run_attempt:'1',jti:'fresh-check-token',...patch};
  const enc=v=>Buffer.from(JSON.stringify(v)).toString('base64url');const body=enc({alg:'RS256',kid:key.kid})+'.'+enc(c);return body+'.'+Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,Buffer.from(body))).toString('base64url');
 }
 async function request(patch={}){return executionRequest(new Request('https://controller.example/v1/execution/check',{method:'POST',body:JSON.stringify({operationID:id,oidcToken:await token(),...patch})}),services,trust);}
 return {start,db,ops,trust,operation,intent,services,token,request,clock:()=>now,advance:n=>{now+=n;},checks:()=>checks,credentials:()=>credentials};
}

test('pre-write check returns exact retained intent and original expiry without touching credentials or lease',async()=>{
 const f=await fixture(),before=await f.ops.readLease(id),response=await f.request();
 assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');
 assert.deepEqual(await response.json(),{operationID:id,verified:true,operationExpiresAt:before.expiresAt,intent:f.intent});
 assert.equal(f.checks(),1);assert.equal(f.credentials(),0);assert.deepEqual(await f.ops.readLease(id),before);
 assert.equal(await durableOperations(f.db).usedJTI('fresh-check-token'),true);
 assert.equal((await f.request()).status,403);
});

test('pre-write check rejects request tampering and unknown input fields with sanitized errors',async()=>{
 for(const patch of [{intent:{branch:'other'}},{operationExpiresAt:9999999999},{oidcToken:'private-invalid-token'}, {operationID:'b'.repeat(64)}]){
  const f=await fixture(),response=await f.request(patch);assert.equal(response.status,403);assert.equal(f.checks(),0);assert.equal(f.credentials(),0);assert.equal((await response.text()).includes('private-invalid-token'),false);
 }
});

test('pre-write check keeps the bounded POST-only HTTP boundary',async()=>{
 const f=await fixture();
 const get=await executionRequest(new Request('https://controller.example/v1/execution/check'),f.services,f.trust);assert.equal(get.status,405);
 const oversized=await executionRequest(new Request('https://controller.example/v1/execution/check',{method:'POST',body:'x'.repeat(24001)}),f.services,f.trust);assert.equal(oversized.status,403);assert.equal(f.checks(),0);
});

test('pre-write check requires a fresh signed token for the enrolled executor run and attempt',async()=>{
 const f=await fixture();
 for(const patch of [{jti:'original-lease-token'},{run_attempt:'2'},{run_id:'61'},{job_workflow_sha:sha('f')},{repository_id:'11'},{aud:'repoctl:other'},{exp:f.start}]){
  assert.equal((await f.request({oidcToken:await f.token(patch)})).status,403);
 }
 const signed=await f.token();assert.equal((await f.request({oidcToken:signed.slice(0,-30)+'tampered'})).status,403);
 assert.equal(f.checks(),0);
});

test('pre-write check denies absent, expired, mismatched and non-issued leases',async()=>{
 for(const patch of [null,{state:'issuing'},{state:'uncertain'},{state:'completed'},{operationID:'b'.repeat(64)},{runID:'61'},{runAttempt:'2'},{expiresAt:0},{expiresAt:9999999999},{providerExpiresAt:0}]){
  const f=await fixture();await f.db.put(`lease:operation:${id}`,patch===null?undefined:{...await f.ops.readLease(id),...patch});
  assert.equal((await f.request()).status,403);assert.equal(f.checks(),0);assert.equal(f.credentials(),0);
 }
});

test('pre-write check denies stale policy, revoked hardware and current authority or evidence failure',async()=>{
 for(const patch of [{policyRevision:2},{hardwareEnrollmentVerified:false},{expiresAt:0}]){
  const f=await fixture();await f.db.put(`operation:${id}`,{operation:{...f.operation,...patch},intent:f.intent,trust:f.trust});assert.equal((await f.request()).status,403);assert.equal(f.checks(),0);
 }
 const f=await fixture();f.services.verifyAuthorization=async()=>{throw Error('current authority, candidate or base changed');};
 assert.equal((await f.request()).status,403);assert.equal(await f.ops.usedJTI('fresh-check-token'),false);assert.equal(f.credentials(),0);
});

test('authority and token must still be live after asynchronous evidence verification',async()=>{
 for(const tokenLife of [100,300]){
  const f=await fixture();f.services.verifyAuthorization=async()=>f.advance(tokenLife===100?101:151);
  await assert.rejects(broker.checkAuthority({operationID:id,oidcToken:await f.token({exp:f.start+tokenLife})},f.services,f.trust,f.clock),/expired/i);
  assert.equal(await f.ops.usedJTI('fresh-check-token'),false);assert.equal(f.credentials(),0);
 }
});

test('check replay reservation is atomic and preserves lease expiry across restart',async()=>{
 const f=await fixture(),before=await f.ops.readLease(id),input={operationID:id,jti:'atomic-check-token',leaseJTI:before.jti,runID:before.runID,runAttempt:before.runAttempt,expiresAt:before.expiresAt};
 const results=await Promise.allSettled([f.ops.consumeCheck(input),f.ops.consumeCheck(input)]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.deepEqual(await f.ops.readLease(id),before);
 await assert.rejects(durableOperations(f.db,f.clock).consumeCheck(input));
 f.advance(151);await assert.rejects(f.ops.consumeCheck({...input,jti:'after-expiry-token'}));
});
