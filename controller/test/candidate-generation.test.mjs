import test from 'node:test';import assert from 'node:assert/strict';import {integrationGeneration} from '../src/candidate/generation.mjs';
const sha=c=>c.repeat(40),intent={generationID:'e'.repeat(64),baseSHA:sha('a'),commitSHA:sha('b'),treeSHA:sha('c')};
function fixture(){let writes=0,ref=null;const journal=new Map(),state={lost:false,lostAbsent:false,foreign:false,immutable:true,moved:false,wrongCommit:false};
 const records={async reserve(b){if(journal.has(b.generationID))return false;journal.set(b.generationID,{...b,phase:'reserved'});return true;},async read(id){return journal.get(id);},async transition(id,from,to){const r=journal.get(id);if(r?.phase!==from)return false;r.phase=to;return true;}};
 const fetcher=async(url,options)=>{assert.equal(new URL(url).origin,'https://api.github.com');assert.equal(options.redirect,'manual');const path=new URL(url).pathname.replace('/repos/owner/fixture','');
  if(options.method==='POST'){writes++;assert.equal(path,'/git/refs');const b=JSON.parse(options.body);assert.equal(b.ref,'refs/heads/int/'+intent.generationID);assert.equal(b.sha,intent.commitSHA);if(state.lostAbsent)throw Error('SECRET-PROVIDER-MARKER');ref={ref:b.ref,object:{type:'commit',sha:b.sha}};if(state.lost)throw Error('SECRET-PROVIDER-MARKER');return Response.json(ref);}
  assert.equal(options.method,'GET');if(path==='')return Response.json({id:state.foreign?8:7,full_name:'owner/fixture',fork:false,archived:false});
  if(path==='/git/ref/heads/main')return Response.json({ref:'refs/heads/main',object:{type:'commit',sha:state.moved?sha('d'):intent.baseSHA}});
  if(path==='/git/commits/'+intent.commitSHA)return Response.json({sha:intent.commitSHA,parents:[{sha:intent.baseSHA}],tree:{sha:intent.treeSHA},verification:{verified:!state.wrongCommit,reason:'valid'}});
  if(path==='/git/ref/heads/int/'+intent.generationID)return ref?Response.json(ref):new Response('',{status:404});throw Error('Unexpected path');};
 const config={repository:'owner/fixture',repositoryID:7,token:async()=> 'fixture-secret',records,verifyCandidate:async b=>({...b,verified:true}),verifyNamespace:async b=>({...b,verified:true,immutable:state.immutable}),fetcher};return {config,api:integrationGeneration(config),state,journal,writes:()=>writes,setRef:r=>ref=r};}
test('integration generation creates once, verifies exact signed child and readback, resumes without ref updates',async()=>{const f=fixture();const first=await f.api.publish(intent);assert.equal(first.published,true);assert.equal(f.writes(),1);assert.deepEqual(await f.api.publish(intent),first);assert.equal(f.writes(),1);});
test('lost create response reconciles matching retained operation without another mutation',async()=>{const f=fixture();f.state.lost=true;await assert.rejects(f.api.publish(intent),error=>error.message.includes('uncertain')&&!error.message.includes('SECRET-PROVIDER-MARKER'));assert.equal(f.journal.get(intent.generationID).phase,'uncertain');assert.equal((await f.api.publish(intent)).published,true);assert.equal(f.writes(),1);});
test('foreign identity, moving base, unverified commit or mutable namespace cannot create',async()=>{for(const key of ['foreign','moved','wrongCommit']){const f=fixture();f.state[key]=true;await assert.rejects(f.api.publish(intent));assert.equal(f.writes(),0);}const f=fixture();f.state.immutable=false;await assert.rejects(f.api.publish(intent));assert.equal(f.writes(),0);});
test('existing generation without retained provenance is never adopted, replaced or deleted',async()=>{const f=fixture();f.setRef({ref:'refs/heads/int/'+intent.generationID,object:{type:'commit',sha:intent.commitSHA}});await assert.rejects(f.api.publish(intent),/already exists/);await assert.rejects(f.api.publish(intent),/collision/);assert.equal(f.writes(),0);});

test('uncertain creation with no observed ref never auto-retries the mutation',async()=>{const f=fixture();f.state.lostAbsent=true;await assert.rejects(f.api.publish(intent),/uncertain/);await assert.rejects(f.api.publish(intent),/unresolved/);assert.equal(f.writes(),1);assert.equal(f.journal.get(intent.generationID).phase,'uncertain');});
test('a moved confirmed generation is rejected without replacement',async()=>{const f=fixture();await f.api.publish(intent);f.setRef({ref:'refs/heads/int/'+intent.generationID,object:{type:'commit',sha:sha('d')}});await assert.rejects(f.api.publish(intent),/collision/);assert.equal(f.writes(),1);});

test('stalled credential acquisition aborts before network and namespace errors cannot expose provider secrets',async()=>{
 const f=fixture();let signal,calls=0;const start=Date.now();
 const api=integrationGeneration({...f.config,timeoutMS:100,token:options=>{signal=options.signal;return new Promise(()=>{});},fetcher:async()=>{calls++;throw Error('Unexpected network');}});
 await assert.rejects(api.publish(intent),/timed out/);assert.equal(signal.aborted,true);assert.equal(calls,0);assert.ok(Date.now()-start<1000);
 await assert.rejects(integrationGeneration({...f.config,verifyNamespace:async()=>{throw Error('SECRET-PROVIDER-MARKER');}}).publish(intent),error=>error.message.includes('namespace')&&!error.message.includes('SECRET-PROVIDER-MARKER'));assert.equal(f.writes(),0);
});

test('GitHub-valid signatures cannot bypass designated signer verification',async()=>{
 const f=fixture();
 assert.throws(()=>integrationGeneration({...f.config,verifyCandidate:undefined}),/configuration/);
 for(const verifyCandidate of [async b=>({...b,verified:false}),async b=>({...b,commitSHA:sha('d'),verified:true}),async()=>{throw Error('SECRET-CANDIDATE-MARKER');}]){
  await assert.rejects(integrationGeneration({...f.config,verifyCandidate}).publish(intent),error=>!error.message.includes('SECRET-CANDIDATE-MARKER'));
 }
 assert.equal(f.writes(),0);assert.equal(f.journal.size,0);
});

test('publication retains the validated intent when its caller mutates it during provider observation',async()=>{
 const f=fixture(),request={...intent};let observed=false;
 const api=integrationGeneration({...f.config,fetcher:async (...args)=>{
  if(!observed){observed=true;request.generationID='f'.repeat(64);request.commitSHA=sha('d');}
  return f.config.fetcher(...args);
 }});
 const report=await api.publish(request);
 assert.equal(report.generationID,intent.generationID);assert.equal(report.commitSHA,intent.commitSHA);
 assert.equal(f.journal.get(intent.generationID).phase,'confirmed');assert.equal(f.writes(),1);
 assert.equal(f.journal.has(request.generationID),false);
});

test('intent fields must be primitive strings before any provider request',async()=>{
 const f=fixture();let reads=0;
 const api=integrationGeneration({...f.config,fetcher:async (...args)=>{reads++;return f.config.fetcher(...args);}});
 for(const field of Object.keys(intent))await assert.rejects(api.publish({...intent,[field]:{toString:()=>intent[field]}}),/Invalid integration generation intent/);
 assert.equal(reads,0);assert.equal(f.writes(),0);assert.equal(f.journal.size,0);
});

test('installed native publication claims journal before upload and reconciles lost response without resend',async()=>{
 const f=fixture();let uploaded=false,calls=0,lose=true;
 const publication={async create(binding,{signal}){
  calls++;assert.equal(signal.aborted,false);
  assert.equal(f.journal.get(intent.generationID).phase,'creating');
  assert.equal(binding.repositoryID,7);assert.equal(binding.ref,'refs/heads/int/'+intent.generationID);
  const result={ref:binding.ref,object:{type:'commit',sha:binding.commitSHA}};
  uploaded=true;f.setRef(result);
  if(lose)throw Error('SECRET-UPLOAD-MARKER');return result;
 }};
 const fetcher=async(url,options)=>{
  if(new URL(url).pathname.endsWith('/git/commits/'+intent.commitSHA)&&!uploaded)return new Response('',{status:404});
  return f.config.fetcher(url,options);
 };
 const api=integrationGeneration({...f.config,publication,fetcher});
 await assert.rejects(api.publish(intent),error=>error.message.includes('uncertain')&&!error.message.includes('SECRET-UPLOAD-MARKER'));
 assert.equal(calls,1);assert.equal(f.writes(),0);assert.equal(f.journal.get(intent.generationID).phase,'uncertain');
 lose=false;assert.equal((await api.publish(intent)).published,true);
 assert.equal(calls,1);assert.equal(f.writes(),0);assert.equal(f.journal.get(intent.generationID).phase,'confirmed');
});
test('native publication cannot start for invalid designated proof or immutable namespace',async()=>{
 for(const field of ['verifyCandidate','verifyNamespace']){
  const f=fixture();let calls=0;
  const api=integrationGeneration({...f.config,publication:{create:async()=>{calls++;throw Error('Unexpected upload');}},[field]:async b=>({...b,verified:false})});
  await assert.rejects(api.publish(intent));assert.equal(calls,0);assert.equal(f.journal.size,0);
 }
});

test('native transfer acknowledgement cannot bypass remote signature readback',async()=>{
 const f=fixture();let calls=0;
 const publication={async create(binding){calls++;const result={ref:binding.ref,object:{type:'commit',sha:binding.commitSHA}};f.setRef(result);f.state.wrongCommit=true;return result;}};
 await assert.rejects(integrationGeneration({...f.config,publication}).publish(intent),/signed history/);
 assert.equal(calls,1);assert.equal(f.journal.get(intent.generationID).phase,'creating');
 await assert.rejects(integrationGeneration({...f.config,publication}).publish(intent),/signed history/);
 assert.equal(calls,1);assert.equal(f.writes(),0);
});
