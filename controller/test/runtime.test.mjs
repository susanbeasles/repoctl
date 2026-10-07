import {test} from 'node:test';
import assert from 'node:assert/strict';
import {durableOperations} from '../src/runtime/state.mjs';
import {tokenCustody,cleanupCredential,journaledCredentials} from '../src/runtime/custody.mjs';
import worker from '../src/worker.mjs';
import {BrokerCoordinator} from '../src/runtime/coordinator.mjs';
const id='a'.repeat(64),other='b'.repeat(64),now=1000;
export function storage(){
 let data=new Map(),alarm=null,tail=Promise.resolve();
 const api={get:async k=>structuredClone(data.get(k)),put:async(k,v)=>{data.set(k,structuredClone(v));},getAlarm:async()=>alarm,setAlarm:async t=>{alarm=t;},list:async({prefix})=>new Map([...data].filter(([k])=>k.startsWith(prefix)).map(([k,v])=>[k,structuredClone(v)])),transaction(fn){const work=tail.then(async()=>{const backup=structuredClone(data),old=alarm;try{return await fn(api);}catch(e){data=backup;alarm=old;throw e;}});tail=work.catch(()=>{});return work;}};return api;
}
const record=operationID=>({operation:{id:operationID,state:'authorized',expiresAt:now+200,runID:60,runAttempt:1},intent:{},trust:{}});
const lease=operationID=>({operationID,jti:'same-replay-id',runID:'60',runAttempt:'1',state:'issuing',expiresAt:now+200});
const key=()=>btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
test('transactional reservations survive restart and reject cross-operation JTI replay',async()=>{
 const db=storage(),ops=durableOperations(db,()=>now);await ops.retain(record(id));await ops.retain(record(other));
 const results=await Promise.allSettled([ops.reserve(lease(id)),ops.reserve(lease(other))]);assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(await db.getAlarm(),(now+200)*1000);
 const restarted=durableOperations(db,()=>now);assert.equal(await restarted.usedJTI('same-replay-id'),true);await assert.rejects(restarted.reserve(lease(id)));await assert.rejects(restarted.retain({...record(id),intent:{changed:true}}));
});
test('lease transitions preserve uncertain outcomes and forbid receipt replacement',async()=>{
 const db=storage(),ops=durableOperations(db,()=>now);await ops.retain(record(id));await ops.reserve(lease(id));await ops.issued({...lease(id),state:'issued',providerExpiresAt:now+3600});await ops.markUncertain(id);
 await ops.completed(id,{digest:'c'.repeat(64)});await ops.completed(id,{digest:'c'.repeat(64)});await assert.rejects(ops.completed(id,{digest:'d'.repeat(64)}));await assert.rejects(ops.markUncertain(id));
});
test('token ciphertext is bound to operation and supports additive remote KEK rotation',async()=>{
 const db=storage(),old=key(),fresh=key();let vault=await tokenCustody(db,{active:'old',keys:{old}});await vault.stage(id,'PRIVATE-TOKEN',now+3600);
 assert.equal(JSON.stringify([...await db.list({prefix:'custody:'})]).includes('PRIVATE-TOKEN'),false);assert.equal((await vault.read(id)).token,'PRIVATE-TOKEN');await db.put(`custody:${other}`,await db.get(`custody:${id}`));await assert.rejects(vault.read(other));
 vault=await tokenCustody(db,{active:'new',keys:{old,new:fresh}});await vault.reencrypt(id);const rotated=await tokenCustody(db,{active:'new',keys:{new:fresh}});assert.equal((await rotated.read(id)).token,'PRIVATE-TOKEN');await rotated.retired(id,'revoked');assert.equal(await rotated.read(id),undefined);assert.equal((await db.get(`custody:${id}`)).ciphertext,undefined);
});
test('cleanup retains encrypted token after failure, then revokes; expiry needs no network',async()=>{
 const db=storage(),vault=await tokenCustody(db,{active:'one',keys:{one:key()}});await vault.stage(id,'PRIVATE-TOKEN',now+3600);assert.equal(await cleanupCredential(id,vault,{revoke:async()=>{throw Error('network');}},now),'retry');assert.equal((await db.get(`custody:${id}`)).attempts,1);
 assert.equal(await cleanupCredential(id,vault,{revoke:async token=>assert.equal(token,'PRIVATE-TOKEN')},now),'revoked');await vault.stage(other,'EXPIRED-TOKEN',now-1);assert.equal(await cleanupCredential(other,vault,{revoke:async()=>{throw Error('unexpected network');}},now),'provider_expired');
});
test('credential journal failure revokes token and exposes no successful grant',async()=>{
 let revoked=0;const credentials=journaledCredentials({issueInstallationToken:async()=>({token:'PRIVATE-TOKEN',expiresAt:2000}),revoke:async()=>revoked++},{stage:async()=>{throw Error('storage unavailable');}},id);await assert.rejects(credentials.issueInstallationToken({}));assert.equal(revoked,1);
});
test('public execution routes are disabled without every required remote binding',async()=>{
 const response=await worker.fetch(new Request('https://controller.test/v1/execution/lease',{method:'POST',body:'{}'}),{BROKER_ENABLED:'true'});assert.equal(response.status,503);assert.equal(response.headers.get('cache-control'),'no-store');const c=new BrokerCoordinator({storage:storage()},{});assert.equal((await c.fetch(new Request('https://internal/v1/execution/lease',{method:'POST',body:'{}'}))).status,503);
});
test('alarm revokes orphaned credentials after restart without reopening authority',async()=>{
 const db=storage(),ops=durableOperations(db,()=>now),r=record(id);r.trust={appID:1,installationID:2,repositoryIDs:[7]};await ops.retain(r);await ops.reserve({...lease(id),expiresAt:now+1});await ops.issued({...lease(id),expiresAt:now+1,state:'issued'});
 const kek=key(),vault=await tokenCustody(db,{active:'one',keys:{one:kek}});await vault.stage(id,'ORPHAN-TOKEN',Math.floor(Date.now()/1000)+3000);const binding={fetch:async()=>{throw Error('unused');}},env={BROKER_ENABLED:'true',TOKEN_KEYRING_JSON:JSON.stringify({active:'one',keys:{one:kek}}),BROKER_AUTHORITY:binding,BROKER_VERIFIER:binding,BROKER_SIGNER:binding,BROKER_RECEIPTS:binding};
 const original=globalThis.fetch;let revoked=0;globalThis.fetch=async(url,options)=>{assert.equal(String(url),'https://api.github.com/installation/token');assert.equal(options.headers.Authorization,'Bearer ORPHAN-TOKEN');revoked++;return new Response(null,{status:204});};try{await new BrokerCoordinator({storage:db},{...env,BROKER_ENABLED:'false',BROKER_VERIFIER:undefined}).alarm();}finally{globalThis.fetch=original;}
 assert.equal(revoked,1);assert.equal((await ops.readLease(id)).state,'uncertain');assert.equal(await vault.read(id),undefined);await assert.rejects(ops.reserve(lease(id)));
});
import {execute} from '../../delivery_control/src/execute.mjs';
test('Worker routes connect durable broker, signed OIDC, remote services and independent completion',async()=>{
 const current=Math.floor(Date.now()/1000),db=storage(),kek=key();
 const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);const publicKey=await crypto.subtle.exportKey('jwk',pair.publicKey);publicKey.kid='runtime';
 const sha=c=>c.repeat(40),trust={appID:1,installationID:2,repositoryIDs:[7],acceptedPolicyRevision:1,acceptedPolicyDigest:'b'.repeat(64),targetRef:'refs/heads/main',audiencePrefix:'repoctl',repository:'owner/delivery_control',repositoryID:10,ownerID:20,ref:'refs/heads/main',workflowRef:'owner/delivery_control/.github/workflows/promote.yml@refs/heads/main',workflowSHA:sha('a'),jobWorkflowRef:'owner/delivery_control/.github/workflows/executor.yml@refs/heads/main',jobWorkflowSHA:sha('a'),eventNames:['workflow_dispatch'],actorIDs:[30]};
 const operation={id,state:'authorized',operation:'promote',expiresAt:current+200,authorizationProvider:'hardware',hardwareEnrollmentVerified:true,policyRevision:1,policyDigest:trust.acceptedPolicyDigest,targetRef:trust.targetRef,repositoryID:7,runID:60,runAttempt:1};const intent={repository:'owner/project',repositoryID:7,branch:'main',baseSHA:sha('b'),commitSHA:sha('c'),treeSHA:sha('d')};
 let writes=0,revokes=0,tip=intent.baseSHA,checks=[],count=0;
 const binding=fn=>({fetch:async(url,options)=>Response.json(await fn(new URL(url).pathname,JSON.parse(options.body)))});
 const env={BROKER_ENABLED:'true',TOKEN_KEYRING_JSON:JSON.stringify({active:'one',keys:{one:kek}}),
 BROKER_AUTHORITY:binding((path,input)=>{assert.equal(input.operationID,id);return path.endsWith('/load')?{operation,intent,trust}:{operationID:id,accepted:true};}),
 BROKER_VERIFIER:binding((path,input)=>{checks.push(path);assert.deepEqual(input.intent,intent);return {operationID:id,verified:true};}),
 BROKER_SIGNER:binding((path,input)=>{assert.equal(path,'/v1/github/app-jwt');assert.equal(input.appID,1);return {jwt:'server.only.jwt'};}),
 BROKER_RECEIPTS:binding(()=>({operationID:id,digest:'e'.repeat(64)}))};
 const coordinator=new BrokerCoordinator({storage:db},env);env.BROKER_COORDINATOR={idFromName:name=>{assert.equal(name,'authority-v1');return name;},get:()=>coordinator};
 async function oidc(){const claims={iss:'https://token.actions.githubusercontent.com',aud:`repoctl:${id}`,iat:current,nbf:current,exp:current+300,repository:trust.repository,repository_id:'10',repository_owner_id:'20',ref:trust.ref,workflow_ref:trust.workflowRef,workflow_sha:trust.workflowSHA,job_workflow_ref:trust.jobWorkflowRef,job_workflow_sha:trust.jobWorkflowSHA,event_name:'workflow_dispatch',actor_id:'30',runner_environment:'github-hosted',run_id:'60',run_attempt:'1',jti:`runtime-unique-${++count}`};const encode=v=>Buffer.from(JSON.stringify(v)).toString('base64url');const body=encode({alg:'RS256',kid:'runtime'})+'.'+encode(claims);return body+'.'+Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,Buffer.from(body))).toString('base64url');}
 const transport=async(url,options={})=>{
  url=String(url);if(url.includes('run.actions.githubusercontent.com'))return Response.json({value:await oidc()});
  if(url.startsWith('https://controller.example/'))return worker.fetch(new Request(url,options),env);
  if(url==='https://token.actions.githubusercontent.com/.well-known/jwks')return Response.json({keys:[publicKey]});
  if(url.endsWith('/access_tokens'))return Response.json({token:'PRIVATE-RUNTIME-TOKEN',expires_at:new Date((current+3600)*1000).toISOString(),repositories:[{id:7}],permissions:{contents:'write'}});
  if(url.endsWith('/installation/token')){revokes++;return new Response(null,{status:204});}
  if(url.endsWith('/repos/owner/project'))return Response.json({id:7});
  if(url.includes('/git/commits/'))return Response.json({sha:intent.commitSHA,parents:[{sha:intent.baseSHA}],tree:{sha:intent.treeSHA},verification:{verified:true}});
  if(options.method==='PATCH'){assert.deepEqual(JSON.parse(options.body),{sha:intent.commitSHA,force:false});writes++;tip=intent.commitSHA;}
  return Response.json({object:{sha:tip}});
 };
 const original=globalThis.fetch;globalThis.fetch=transport;
 try{await execute({operationID:id,controller:'https://controller.example/',oidcURL:'https://run.actions.githubusercontent.com/token',oidcBearer:'request-token',audiencePrefix:'repoctl'},transport,()=>current);}finally{globalThis.fetch=original;}
 assert.equal(writes,1);assert.equal(revokes,2);assert.deepEqual(checks,['/v1/evidence/authorization','/v1/evidence/authorization','/v1/evidence/completion']);assert.equal((await durableOperations(db).readLease(id)).state,'completed');assert.equal((await db.get(`custody:${id}`)).state,'revoked');
 let replay;globalThis.fetch=transport;try{replay=await coordinator.fetch(new Request('https://internal/v1/execution/lease',{method:'POST',body:JSON.stringify({operationID:id,oidcToken:await oidc()})}));}finally{globalThis.fetch=original;}assert.equal(replay.status,403);
 assert.equal(JSON.stringify([...await db.list({prefix:''})]).includes('PRIVATE-RUNTIME-TOKEN'),false);
});

test('lease observation is private, read-only and does not wait on execution queue',async()=>{
 const db=storage(),r=record(id);await db.put(`operation:${id}`,r);await db.put(`lease:operation:${id}`,{...lease(id),state:'issued',providerExpiresAt:4600});
 const coordinator=new BrokerCoordinator({storage:db},{});coordinator.tail=new Promise(()=>{});
 const request=()=>new Request('https://internal/v1/private/lease-observation',{method:'POST',body:JSON.stringify({operationID:id})});
 const response=await coordinator.fetch(request());assert.equal(response.status,200);const view=await response.json();assert.equal(view.state,'issued');assert.equal('jti' in view,false);
 assert.equal((await worker.fetch(request(),{})).status,404);
 assert.equal((await coordinator.fetch(new Request('https://internal/v1/private/lease-observation',{method:'POST',body:JSON.stringify({operationID:id,token:'expose'})}))).status,403);
});
