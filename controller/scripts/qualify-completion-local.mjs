import {Miniflare,convertV4MiniflareOptions} from 'miniflare';import {readFile} from 'node:fs/promises';import assert from 'node:assert/strict';
import {digest,promotionPayload} from '../src/ledger.mjs';
const [observerPath,brokerPath]=process.argv.slice(2);if(!observerPath||!brokerPath)throw Error('Observer and broker bundles required');
const hash='a'.repeat(64),a='a'.repeat(40),b='b'.repeat(40),c='c'.repeat(40);
const record={operation:{id:hash,state:'authorized',operation:'promote',repositoryID:1,targetRef:'refs/heads/main',authorizationProvider:'hardware',hardwareEnrollmentVerified:true,policyDigest:hash,policyRevision:1,runID:5,runAttempt:1,expiresAt:1000},intent:{repository:'owner/repo',repositoryID:1,branch:'main',baseSHA:a,commitSHA:b,treeSHA:a},trust:{}};
const payload=promotionPayload({repositoryID:1,sequence:1,previousDigest:hash,baseSHA:a,commitSHA:b,sourceSHA:c,policyDigest:hash,evidenceDigest:hash,archiveDigests:[hash]});
const view={record,recordDigest:await digest(record),ledgerPayload:payload,approvalDigest:hash,enrollmentProofDigest:hash},lease={operationID:hash,recordDigest:await digest(record),state:'issued',runID:5,runAttempt:1,expiresAt:900,providerExpiresAt:4000};
const input={operationID:hash,repositoryID:1,entryPayloadDigest:await digest(payload),baseSHA:a,commitSHA:b};let tip=b,drift=false;
const mf=new Miniflare(convertV4MiniflareOptions({workers:[
 {name:'observer',modules:true,script:await readFile(observerPath,'utf8'),compatibilityDate:'2026-10-04',bindings:{OBSERVATION_ENABLED:'true',OBSERVATION_CONFIG_JSON:JSON.stringify([{repositoryID:1,repository:'owner/repo',branch:'main'}])},serviceBindings:{OBSERVATION_BASELINE:async r=>{assert.equal(new URL(r.url).pathname,'/v1/baseline/verify');const {binding}=await r.json();assert.deepEqual(binding,{repositoryID:1,policyRevision:1,policyDigest:hash,targetRef:'refs/heads/main',baseSHA:a});return Response.json({...binding,verified:true,drift});},OBSERVATION_AUTHORITY:async r=>{if(new URL(r.url).pathname==='/v1/authorization/check')return Response.json({operationID:hash,accepted:true});assert.equal(new URL(r.url).pathname,'/v1/authorization/completion-record');assert.deepEqual(await r.json(),{operationID:hash});return Response.json(view);},OBSERVATION_BROKER:async r=>{assert.equal(new URL(r.url).pathname,'/v1/broker/lease-observation');return Response.json(lease);}},outboundService:async r=>{
  const url=new URL(r.url);assert.equal(url.origin,'https://api.github.com');assert.equal(r.headers.get('Authorization'),null);
  if(url.pathname==='/repos/owner/repo')return Response.json({id:1});
  if(url.pathname==='/repos/owner/repo/git/ref/heads/main')return Response.json({ref:'refs/heads/main',object:{type:'commit',sha:tip}});
  const sha=url.pathname.split('/').at(-1);assert.ok([b,c].includes(sha));return Response.json({sha,parents:[{sha:a}],tree:{sha:a},verification:{verified:true,reason:'valid'}});
 }},
 {name:'caller',modules:true,script:'export default {fetch(r,e){return e.OBSERVER.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{OBSERVER:{name:'observer',entrypoint:'CompletionObservationService'}}},
 {name:'verifier-caller',modules:true,script:'export default {fetch(r,e){return e.VERIFIER.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{VERIFIER:{name:'observer',entrypoint:'BrokerVerificationService'}}},
 {name:'missing-baseline',modules:true,script:await readFile(observerPath,'utf8'),compatibilityDate:'2026-10-04',bindings:{OBSERVATION_ENABLED:'true',OBSERVATION_CONFIG_JSON:'[]'},serviceBindings:{OBSERVATION_AUTHORITY:async()=>{throw Error('Unexpected downstream');},OBSERVATION_BROKER:async()=>{throw Error('Unexpected downstream');}}},
 {name:'missing-baseline-caller',modules:true,script:'export default {fetch(r,e){return e.VERIFIER.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{VERIFIER:{name:'missing-baseline',entrypoint:'BrokerVerificationService'}}},
 {name:'broker',modules:true,script:await readFile(brokerPath,'utf8'),compatibilityDate:'2026-10-04',durableObjects:{BROKER_COORDINATOR:{className:'BrokerCoordinator',useSQLite:true}}},
 {name:'broker-caller',modules:true,script:'export default {fetch(r,e){return e.OBSERVER.fetch(r);}}',compatibilityDate:'2026-10-04',serviceBindings:{OBSERVER:{name:'broker',entrypoint:'BrokerObservationService'}}}
]}));
try{
 const caller=await mf.getWorker('caller'),request=()=>new Request('https://internal/v1/ledger/promotion-observation',{method:'POST',body:JSON.stringify(input)});
 assert.equal((await (await mf.getWorker('observer')).fetch(request())).status,404);
 const response=await caller.fetch(request());assert.equal(response.status,200);assert.deepEqual(await response.json(),{...input,promoted:true});
 lease.state='issuing';assert.equal((await caller.fetch(request())).status,403);lease.state='issued';tip=a;assert.equal((await caller.fetch(request())).status,403);
 const verifier=await mf.getWorker('verifier-caller'),brokerRequest={operationID:hash,operation:record.operation,intent:record.intent};
 assert.equal((await verifier.fetch('https://internal/v1/evidence/authorization',{method:'POST',body:JSON.stringify(brokerRequest)})).status,200);
 drift=true;assert.equal((await verifier.fetch('https://internal/v1/evidence/authorization',{method:'POST',body:JSON.stringify(brokerRequest)})).status,403);
 const missing=await mf.getWorker('missing-baseline-caller');assert.equal((await missing.fetch('https://internal/v1/evidence/authorization',{method:'POST',body:JSON.stringify(brokerRequest)})).status,503);
 tip=b;assert.equal((await verifier.fetch('https://internal/v1/evidence/completion',{method:'POST',body:JSON.stringify(brokerRequest)})).status,200);
 const broker=await mf.getWorker('broker'),privateCaller=await mf.getWorker('broker-caller');
 const leaseRequest=new Request('https://internal/v1/broker/lease-observation',{method:'POST',body:JSON.stringify({operationID:hash})});
 assert.equal((await broker.fetch(leaseRequest.clone())).status,404);assert.equal((await privateCaller.fetch(leaseRequest)).status,403);
 console.log('PASS: real workerd private completion RPC, fixed GitHub observations, unissued lease rejection and broker private read isolation');
}finally{await mf.dispose();}
