import test from 'node:test';
import assert from 'node:assert/strict';
import {createSourceSigning,gitObjectID,sha256,ownerApprovalVerifier,validateReviewReceipt} from '../src/source-signing/core.mjs';
import {validateScanEvidence,mandatoryScanCategories} from '../src/source-signing/scans.mjs';
import {canonical,base64} from '../src/ledger.mjs';
import {signApproval} from '../src/promotion.mjs';
import {mkdtemp,writeFile,readFile,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {createInstalledGitSigner,signatureKeyID} from '../src/source-signing/installed-signer.mjs';
import {createLocalGitSource} from '../src/source-signing/git.mjs';
import {createSourcePublisher} from '../../delivery_control/src/source-publisher.mjs';

const sha=c=>c.repeat(40),hash=c=>c.repeat(64),keyID='SHA256:'+Buffer.alloc(32,7).toString('base64').replace(/=+$/,'');
function memory(){let data=new Map(),tail=Promise.resolve();const db={get:async k=>structuredClone(data.get(k)),put:async(k,v)=>data.set(k,structuredClone(v)),transaction(fn){const result=tail.then(async()=>{const old=structuredClone(data);try{return await fn(db);}catch(e){data=old;throw e;}});tail=result.catch(()=>{});return result;}};return db;}
async function fixture(){
 const storage=memory(),signatures=[],refs=new Map(),objects=new Map();let now=1000,main=sha('a'),writes=0,failRef=false,ciOK=true,hardware=true,eligible=true;
 const config={authority:'workflow_depot',repository:'owner/project',repositoryID:7,sourceRef:'refs/heads/source',targetRef:'refs/heads/main',signerKeyID:keyID,policyDigest:hash('b')};
 config.reviewPolicy={styleGuideDigest:hash('4'),styleGuideRevision:sha('5'),styleGuidePath:'docs/code-style-guide.md',reviewerAppID:10,reviewerInstallationID:11,reviewerActorID:12,privilegedAppIDs:[20],privilegedActorIDs:[21,22,23],allowBotApproval:true,requiresHumanReview:false};
 config.scanPolicy={supportedLanguages:['javascript'],supportedFrameworks:['node'],requiredCategories:[...mandatoryScanCategories],sonarqubeStandardRulesetDigest:hash('3'),requiredTools:mandatoryScanCategories.map(category=>({id:category==='quality'?'sonarqube':`synthetic-${category}`,category,version:'1',rulesetDigest:hash('3'),databaseMaxAgeSeconds:100})),exemptions:[]};
 const inventory={digest:hash('2'),complete:true,paths:['src/index.mjs','package.json'],languages:['javascript'],frameworks:['node'],manifests:['package.json']};
 const signer={keyID,signGit:async input=>{signatures.push(structuredClone(input));return 'fixture-signature:'+sha256(input.payload);},verifyGit:async({payload,signature})=>signature==='fixture-signature:'+sha256(payload)};
 const git={snapshot:async()=>({sourceSHA:sha('c'),sourceBaseSHA:sha('a'),mainSHA:main,treeSHA:sha('d'),historyDigest:hash('e'),retentionReference:'fixture-archive',verified:true,inventory}),main:async()=>main,source:async()=>sha('c')};
 const policy={current:async()=>config,authorizeCandidate:async input=>({eligible,requestDigest:sha256(canonical(input)),policyDigest:config.policyDigest,signerKeyID:keyID,expiresAt:now+100})};
 const approvalVerifier={verify:async(envelope,expected)=>{assert.equal(envelope.payload,canonical(expected));if(!hardware)throw Error('hardware revoked');return {ownerKeyID:hash('f'),hardwareVerified:true,proofDigest:hash('9'),validUntil:now+100};}};
 const ci={verify:async input=>({verified:ciOK,requestDigest:sha256(canonical(input))})};
 const review={verify:async input=>({verified:true,receipt:{schema:'repoctl-source-review/v1',...Object.fromEntries(['repositoryID','sourcePRNumber','sourceSHA','baseSHA','commitSHA','treeSHA','policyDigest'].map(k=>[k,input[k]])),...Object.fromEntries(['styleGuideDigest','styleGuideRevision','styleGuidePath','reviewerAppID','reviewerInstallationID','reviewerActorID'].map(k=>[k,config.reviewPolicy[k]])),methods:['deterministic-style','security-tests','evidence-review'],verdict:'approved',findings:[],humanReviewVerified:false,expiresAt:now+100}})};
 const scans={verify:async input=>({verified:true,receipt:{schema:'repoctl-source-scans/v1',repositoryID:7,commitSHA:input.commitSHA,treeSHA:input.treeSHA,policyDigest:input.policyDigest,inventoryDigest:inventory.digest,tools:config.scanPolicy.requiredTools.map(({databaseMaxAgeSeconds,...tool})=>({...tool,status:'passed',commitSHA:input.commitSHA,inventoryDigest:inventory.digest,coveredPaths:inventory.paths,databaseUpdatedAt:now-5,completedAt:now,evidenceDigest:hash('1')}))}})};
 const publisher={putObject:async(type,payload)=>{const id=gitObjectID(type,payload);objects.set(id,payload);return id;},readRef:async name=>refs.get(name)??null,createRef:async(name,id)=>{writes++;if(refs.has(name))throw Error('exists');refs.set(name,id);if(failRef){failRef=false;throw Error('lost response');}}};
 const core=createSourceSigning({storage,policy,git,signer,approvalVerifier,ci,review,scans,publisher,clock:()=>now});
 const input={repositoryID:7,sourcePR:{number:9,repositoryID:7,headSHA:sha('c')},author:'Owner <owner@example.test> 1000 +0000',committer:'Signer <signer@example.test> 1000 +0000',message:'Approved source snapshot\n',artifactIntentDigest:hash('8'),expiresAt:1200};
 return {core,input,storage,signatures,refs,objects,config,signer,git,policy,ci,review,scans,inventory,publisher,approvalVerifier,advance:n=>now+=n,setMain:v=>main=v,setHardware:v=>hardware=v,setCI:v=>ciOK=v,setEligible:v=>eligible=v,failRef:()=>failRef=true,writes:()=>writes};
}
const approval=p=>({payload:canonical(p.approvalPayload)});

test('policy-eligible candidate is signed before owner approval; complete tag bytes bind its resulting SHA',async()=>{
 const f=await fixture(),p=await f.core.prepare(f.input);
 assert.equal(f.signatures.length,1);assert.equal(f.signatures[0].type,'commit');
 assert.match(f.signatures[0].payload,new RegExp('^tree '+sha('d')+'\nparent '+sha('a')+'\nauthor '));
 assert.equal(p.finalSignedCommitSHA,gitObjectID('commit',p.signedCommit));
 assert.notEqual(p.finalSignedCommitSHA,gitObjectID('commit',f.signatures[0].payload));
 for(const body of [p.approvalPayload.sourceTagPayload,p.approvalPayload.mainTagPayload]){assert.ok(body.includes(p.finalSignedCommitSHA));assert.ok(body.includes(sha('c')));assert.ok(body.includes(p.approvalPayload.approvalReference));}
 const tagged=await f.core.approve({repositoryID:7,sequence:p.sequence,ownerApproval:approval(p)});
 assert.equal(tagged.state,'tagged');assert.deepEqual(f.signatures.map(x=>x.type),['commit','tag','tag']);
 f.failRef();const result=await f.core.publish({repositoryID:7,sequence:p.sequence});
 assert.equal(f.writes(),2);assert.equal(result.receipt.hardwareApprovalVerified,true);
 assert.equal(result.receipt.ownerApprovalReference,p.approvalPayload.approvalReference);
 assert.deepEqual(await f.core.lookupReceipt({receiptDigest:result.receiptDigest}),result.receipt);
 await f.core.publish({repositoryID:7,sequence:p.sequence});assert.equal(f.writes(),2);
});

test('durable sequences are unique under concurrency and failed candidates leave permanent gaps',async()=>{
 const f=await fixture();f.setEligible(false);await assert.rejects(f.core.prepare(f.input));f.setEligible(true);
 const values=await Promise.all([f.core.prepare(f.input),f.core.prepare(f.input)]);
 assert.deepEqual(values.map(v=>v.sequence).sort(),[2,3]);
});
test('main handoff rechecks published source receipt, immutable refs, current hardware and fresh automated gates',async()=>{
 const f=await fixture(),p=await f.core.prepare(f.input);await f.core.approve({repositoryID:7,sequence:p.sequence,ownerApproval:approval(p)});const published=await f.core.publish({repositoryID:7,sequence:p.sequence});f.refs.set(p.shadowRef,p.finalSignedCommitSHA);
 assert.equal(typeof f.core.verifyPromotion,'function');const proof=await f.core.verifyPromotion({receiptDigest:published.receiptDigest});assert.deepEqual(proof.receipt,published.receipt);assert.equal(proof.candidate.commitSHA,p.finalSignedCommitSHA);
 f.setCI(false);await assert.rejects(f.core.verifyPromotion({receiptDigest:published.receiptDigest}));f.setCI(true);
 f.refs.set('refs/tags/promotion/1/main',sha('f'));await assert.rejects(f.core.verifyPromotion({receiptDigest:published.receiptDigest}));
});

function shadowPublisher(f){
 let pull=null,creates=0;
 f.publisher.findPullRequest=async()=>pull;
 f.publisher.createPullRequest=async spec=>{creates++;pull={number:31,repositoryID:7,headRef:spec.headRef,headSHA:spec.headSHA,baseRef:spec.baseRef,baseSHA:spec.baseSHA,state:'open',draft:true,url:'https://github.com/owner/project/pull/31'};return pull;};
 return {get pull(){return pull;},set pull(value){pull=value;},creates:()=>creates};
}
test('retained signed candidate publishes one immutable shadow branch and draft PR before owner approval',async()=>{
 const f=await fixture(),provider=shadowPublisher(f),p=await f.core.prepare(f.input);
 assert.equal(typeof f.core.publishShadow,'function');const result=await f.core.publishShadow({repositoryID:7,sequence:p.sequence});
 assert.equal(result.commitSHA,p.finalSignedCommitSHA);assert.equal(result.pullRequest.number,31);assert.equal(f.refs.get(p.shadowRef),p.finalSignedCommitSHA);assert.equal(f.refs.has('refs/heads/main'),false);assert.equal(f.signatures.length,1);assert.equal(provider.creates(),1);
 const proof=await f.core.lookupCandidate({repositoryID:7,commitSHA:p.finalSignedCommitSHA,shadowRef:p.shadowRef});assert.equal(proof.sourceSHA,sha('c'));assert.equal(proof.expectedMainParent,sha('a'));
 assert.deepEqual(await f.core.publishShadow({repositoryID:7,sequence:p.sequence}),result);assert.equal(provider.creates(),1);assert.equal(f.writes(),1);
});
test('shadow publication serializes concurrent writes and reconciles lost ref and PR responses without duplicate creation',async()=>{
 const f=await fixture(),provider=shadowPublisher(f),p=await f.core.prepare(f.input),create=f.publisher.createPullRequest;
 f.failRef();f.publisher.createPullRequest=async spec=>{await create(spec);throw Error('lost private response');};
 assert.equal(typeof f.core.publishShadow,'function');const outcomes=await Promise.allSettled(Array.from({length:6},()=>f.core.publishShadow({repositoryID:7,sequence:p.sequence})));
 assert(outcomes.some(r=>r.status==='fulfilled'));assert.equal(provider.creates(),1);assert.equal(f.writes(),1);
 assert.equal((await f.core.publishShadow({repositoryID:7,sequence:p.sequence})).commitSHA,p.finalSignedCommitSHA);assert.equal(provider.creates(),1);
});
test('absent ambiguous shadow mutations are never retried and conflicting refs or PRs cannot be adopted',async()=>{
 for(const mode of ['ref-absent','pr-absent','ref-conflict','pr-conflict']){
  const f=await fixture(),provider=shadowPublisher(f),p=await f.core.prepare(f.input);let attempted=0;
  if(mode==='ref-absent')f.publisher.createRef=async()=>{attempted++;throw Error('lost');};
  if(mode==='pr-absent')f.publisher.createPullRequest=async()=>{attempted++;throw Error('lost');};
  if(mode==='ref-conflict')f.refs.set(p.shadowRef,sha('f'));
  if(mode==='pr-conflict')provider.pull={number:31,repositoryID:7,headRef:p.shadowRef,headSHA:sha('f'),baseRef:'refs/heads/main',baseSHA:sha('a'),state:'open',draft:true,url:'https://github.com/owner/project/pull/31'};
  assert.equal(typeof f.core.publishShadow,'function');await assert.rejects(f.core.publishShadow({repositoryID:7,sequence:p.sequence}));await assert.rejects(f.core.publishShadow({repositoryID:7,sequence:p.sequence}));if(mode.endsWith('absent'))assert.equal(attempted,1);
 }
});
test('revoked eligibility, main drift and expiry during durable shadow reservation prevent publication',async()=>{
 for(const mode of ['eligibility','main','expiry']){
  const f=await fixture();shadowPublisher(f);const p=await f.core.prepare(f.input);if(mode==='eligibility')f.setEligible(false);if(mode==='main')f.setMain(sha('f'));
  if(mode==='expiry'){const transaction=f.storage.transaction;f.storage.transaction=fn=>transaction(async tx=>{const result=await fn(tx);if(await tx.get('source-shadow:7:1:ref'))f.advance(301);return result;});}
  assert.equal(typeof f.core.publishShadow,'function');await assert.rejects(f.core.publishShadow({repositoryID:7,sequence:p.sequence}));assert.equal(f.writes(),0);assert.equal(f.signatures.length,1);
 }
});
test('publisher effect grants bind retained reservations once and never authorize arbitrary source refs or PR bytes',async()=>{
 const f=await fixture();shadowPublisher(f);const p=await f.core.prepare(f.input),grants=[];
 assert.equal(typeof f.core.authorizePublication,'function');const request={repository:f.config.repository,repositoryID:7,operation:'create-ref',ref:p.shadowRef,objectSHA:p.finalSignedCommitSHA};
 await assert.rejects(f.core.authorizePublication(request));
 const create=f.publisher.createRef,pr=f.publisher.createPullRequest;
 f.publisher.createRef=async(ref,objectSHA)=>{const body={repository:f.config.repository,repositoryID:7,operation:'create-ref',ref,objectSHA};const grant=await f.core.authorizePublication(body);assert.equal(grant.requestDigest,sha256(canonical(body)));grants.push(grant);return create(ref,objectSHA);};
 f.publisher.createPullRequest=async spec=>{await assert.rejects(f.core.authorizePublication({repository:f.config.repository,repositoryID:7,operation:'create-pull-request',...spec,body:'changed'}));grants.push(await f.core.authorizePublication({repository:f.config.repository,repositoryID:7,operation:'create-pull-request',...spec}));return pr(spec);};
 await f.core.publishShadow({repositoryID:7,sequence:p.sequence});assert.equal(grants.length,2);await assert.rejects(f.core.authorizePublication(request));await assert.rejects(f.core.authorizePublication({...request,ref:'refs/heads/main'}));
});
test('effect grant expiry during durable consumption prevents publication after reservation',async()=>{
 const f=await fixture();shadowPublisher(f);const p=await f.core.prepare(f.input);assert.equal(typeof f.core.authorizePublication,'function');const transaction=f.storage.transaction;f.storage.transaction=fn=>transaction(async tx=>{const result=await fn(tx);if(await tx.get('source-effect-grant:7:1:ref'))f.advance(301);return result;});let writes=0;
 f.publisher.createRef=async(ref,objectSHA)=>{await f.core.authorizePublication({repository:f.config.repository,repositoryID:7,operation:'create-ref',ref,objectSHA});writes++;};
 await assert.rejects(f.core.publishShadow({repositoryID:7,sequence:p.sequence}));assert.equal(writes,0);
});
test('actual source core and standalone publisher compose through exact one-use effects and synthetic GitHub readback',async()=>{
 const f=await fixture(),p=await f.core.prepare(f.input),objects=new Map();let pull=null,pushes=0,posts=0;
 const publisher=createSourcePublisher({config:{repository:f.config.repository,repositoryID:7},clock:()=>1000,credential:async()=>({token:'SYNTHETIC-BUILDER',repositoryID:7,expiresAt:1200,permissions:{contents:'write',pull_requests:'write',metadata:'read'}}),authorize:request=>f.core.authorizePublication(request),git:{putObject:async(type,body)=>{const id=gitObjectID(type,body);objects.set(id,body);return id;},readObject:async(type,id)=>objects.get(id),pushCreateOnly:async({ref,objectSHA})=>{pushes++;f.refs.set(ref,objectSHA);}},fetcher:async(url,options)=>{
  const u=new URL(url);assert.equal(u.origin,'https://api.github.com');assert.equal(options.redirect,'error');if(u.pathname==='/repos/owner/project')return Response.json({id:7,full_name:'owner/project',archived:false,fork:false});
  if(u.pathname.startsWith('/repos/owner/project/git/ref/')){const ref='refs/'+u.pathname.split('/git/ref/')[1],value=ref==='refs/heads/main'?sha('a'):f.refs.get(ref);return value?Response.json({ref,object:{type:'commit',sha:value}}):new Response('{}',{status:404});}
  if(u.pathname==='/repos/owner/project/pulls'&&options.method==='POST'){posts++;const body=JSON.parse(options.body);pull={number:32,html_url:'https://github.com/owner/project/pull/32',state:'open',draft:true,head:{ref:body.head.split(':')[1],sha:p.finalSignedCommitSHA,repo:{id:7,full_name:'owner/project'}},base:{ref:'main',sha:sha('a'),repo:{id:7,full_name:'owner/project'}}};return Response.json(pull,{status:201});}
  if(u.pathname==='/repos/owner/project/pulls')return Response.json(pull?[pull]:[]);throw Error('Unexpected provider path');
 }});Object.assign(f.publisher,publisher);
 const result=await f.core.publishShadow({repositoryID:7,sequence:p.sequence});assert.equal(result.pullRequest.number,32);assert.equal(pushes,1);assert.equal(posts,1);assert.equal(objects.get(p.finalSignedCommitSHA),p.signedCommit);assert.equal(f.signatures.length,1);
 await f.core.publishShadow({repositoryID:7,sequence:p.sequence});assert.equal(pushes,1);assert.equal(posts,1);
});

test('approval changes, expired approvals, revoked hardware, failed CI and main drift prevent tag signing',async()=>{
 for(const mode of ['changed','expired','hardware','ci','main']){
  const f=await fixture(),p=await f.core.prepare(f.input);const a=approval(p);
  if(mode==='changed')a.payload=a.payload.replace('Approved source snapshot','malicious');
  if(mode==='changed')a.payload=canonical({...p.approvalPayload,finalSignedCommitSHA:sha('f')});
  if(mode==='expired')f.advance(201);if(mode==='hardware')f.setHardware(false);if(mode==='ci')f.setCI(false);if(mode==='main')f.setMain(sha('f'));
  await assert.rejects(f.core.approve({repositoryID:7,sequence:p.sequence,ownerApproval:a}));assert.equal(f.signatures.length,1);assert.equal(f.writes(),0);
 }
});

test('one exact approval is consumed atomically; concurrent calls cannot sign tags twice',async()=>{
 const f=await fixture(),p=await f.core.prepare(f.input),input={repositoryID:7,sequence:p.sequence,ownerApproval:approval(p)};
 const outcomes=await Promise.allSettled([f.core.approve(input),f.core.approve(input)]);
 assert.ok(outcomes.some(v=>v.status==='fulfilled'));assert.equal(f.signatures.length,3);
 await f.core.approve(input);assert.equal(f.signatures.length,3);
 await assert.rejects(f.core.approve({...input,ownerApproval:{payload:'changed'}}));
});

test('uncertain signing never retries the private operation',async()=>{
 const f=await fixture();f.signer.signGit=async input=>{f.signatures.push(input);throw Error('private provider message');};
 await assert.rejects(f.core.prepare(f.input),/signing outcome uncertain/i);assert.equal(f.signatures.length,1);
 assert.equal((await f.storage.get('source-signing:7:1')).state,'signing-uncertain');
});

test('expiry during durable candidate signing reservation prevents the private signing operation',async()=>{
 const f=await fixture(),transaction=f.storage.transaction;
 f.storage.transaction=fn=>transaction(async tx=>{const result=await fn(tx);const r=await tx.get('source-signing:7:1');if(r?.state==='signing')f.advance(301);return result;});
 await assert.rejects(f.core.prepare(f.input),/expired/i);assert.equal(f.signatures.length,0);
});

test('unknown signer, signature failure and unsigned input injection fail closed',async()=>{
 for(const mode of ['key','signature','header','unknown']){
  const f=await fixture();if(mode==='key')f.signer.keyID='other';if(mode==='signature')f.signer.verifyGit=async()=>false;
  const input={...f.input};if(mode==='header')input.author+='\ngpgsig injected';if(mode==='unknown')input.shell='touch /tmp/no';
  await assert.rejects(f.core.prepare(input));assert.equal(f.writes(),0);
 }
});

test('a conflicting existing tag is never replaced; lost absent publication is not retried',async()=>{
 for(const mode of ['conflict','lost']){
  const f=await fixture(),p=await f.core.prepare(f.input);await f.core.approve({repositoryID:7,sequence:p.sequence,ownerApproval:approval(p)});
  if(mode==='conflict')f.refs.set(`refs/tags/promotion/${p.sequence}/source`,sha('f'));
  else f.publisher.createRef=async()=>{throw Error('lost before readback');};
  await assert.rejects(f.core.publish({repositoryID:7,sequence:p.sequence}));
  await assert.rejects(f.core.publish({repositoryID:7,sequence:p.sequence}));assert.equal(f.writes(),0);
 }
});

test('existing P256 owner approval domain and independently current hardware proof are required',async()=>{
 const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const publicKey=await crypto.subtle.exportKey('raw',pair.publicKey),ownerKeyID=sha256(new Uint8Array(publicKey));
 let hardware=true;const expected={kind:'exact-fixture'};
 const verifier=ownerApprovalVerifier({currentPolicy:async()=>({authority:'workflow_depot',repositoryID:7,ownerKeys:[{keyID:ownerKeyID,publicKeyX963:base64(publicKey)}]}),currentHardware:{verify:async()=>({keyID:ownerKeyID,hardwareVerified:hardware,revoked:false,proofDigest:hash('a'),validUntil:1200})},clock:()=>1000});
 const envelope=await signApproval(expected,'owner',ownerKeyID,pair.privateKey);
 assert.equal((await verifier.verify(envelope,expected,{repositoryID:7})).hardwareVerified,true);
 hardware=false;await assert.rejects(verifier.verify(envelope,expected,{repositoryID:7}));
});

test('owner approval can follow long-running CI without resigning or amending the candidate',async()=>{
 const f=await fixture(),p=await f.core.prepare(f.input);f.advance(250);
 const refreshed=await f.core.approvalIntent({repositoryID:7,sequence:p.sequence,expiresAt:1400});
 assert.equal(refreshed.finalSignedCommitSHA,p.finalSignedCommitSHA);assert.equal(refreshed.signedCommit,p.signedCommit);assert.equal(f.signatures.length,1);
 await assert.rejects(f.core.approve({repositoryID:7,sequence:p.sequence,ownerApproval:approval(p)}));
 await f.core.approve({repositoryID:7,sequence:p.sequence,ownerApproval:approval(refreshed)});assert.equal(f.signatures.length,3);
});

test('missing, wrong-identity, unsupported, stale and inconclusive review or scan evidence blocks tag signing',async()=>{
 for(const mode of ['review-app','review-installation','review-self','review-sha','review-style','review-inconclusive','review-model-only','review-finding','scan-missing','scan-sha','scan-version','scan-rules','scan-database','scan-coverage','scan-skipped','stack']){
  const f=await fixture(),p=await f.core.prepare(f.input);const oldReview=f.review.verify,oldScan=f.scans.verify;
  f.review.verify=async input=>{const r=await oldReview(input);if(mode==='review-app')r.receipt.reviewerAppID=999;if(mode==='review-installation')r.receipt.reviewerInstallationID=999;if(mode==='review-self')r.receipt.reviewerActorID=21;if(mode==='review-sha')r.receipt.commitSHA=sha('f');if(mode==='review-style')r.receipt.styleGuideDigest=hash('f');if(mode==='review-inconclusive')r.receipt.verdict='inconclusive';if(mode==='review-model-only')r.receipt.methods=['model'];if(mode==='review-finding')r.receipt.findings=[{severity:'critical',summary:'synthetic issue',evidence:'fixture:1'}];return r;};
  f.scans.verify=async input=>{const r=await oldScan(input),tool=r.receipt.tools[0];if(mode==='scan-missing')r.receipt.tools=[];if(mode==='scan-sha')tool.commitSHA=sha('f');if(mode==='scan-version')tool.version='unknown';if(mode==='scan-rules')tool.rulesetDigest=hash('f');if(mode==='scan-database')tool.databaseUpdatedAt=0;if(mode==='scan-coverage')tool.coveredPaths=[];if(mode==='scan-skipped')tool.status='skipped';return r;};
  if(mode==='stack'){const record=await f.storage.get(`source-signing:7:${p.sequence}`);record.snapshot.inventory.languages.push('unknown');await f.storage.put(`source-signing:7:${p.sequence}`,record);}
  await assert.rejects(f.core.approve({repositoryID:7,sequence:p.sequence,ownerApproval:approval(p)}),mode);assert.equal(f.signatures.length,1,mode);
 }
});

test('failed automatic gates stop before review and owner verification',async()=>{
 const f=await fixture(),p=await f.core.prepare(f.input);let reviews=0,owners=0;f.setCI(false);f.review.verify=async()=>{reviews++;throw Error('not called');};f.approvalVerifier.verify=async()=>{owners++;throw Error('not called');};
 await assert.rejects(f.core.approve({repositoryID:7,sequence:p.sequence,ownerApproval:approval(p)}));assert.equal(reviews,0);assert.equal(owners,0);
});

test('accepted scan policy cannot omit mandatory categories or the pinned SonarQube standard ruleset',async()=>{
 const f=await fixture(),p=await f.core.prepare(f.input),r=await f.storage.get(`source-signing:7:${p.sequence}`);
 const expected={repositoryID:7,commitSHA:p.finalSignedCommitSHA,treeSHA:r.snapshot.treeSHA,policyDigest:r.config.policyDigest};
 const {receipt}=await f.scans.verify(expected);
 assert.throws(()=>validateScanEvidence(receipt,expected,{...r.config.scanPolicy,requiredCategories:['security']},r.snapshot.inventory,1000),/mandatory/i);
});

test('private candidate lookup verifies immutable shadow S before main promotion and denies drift or swapped bytes',async()=>{
 const f=await fixture(),p=await f.core.prepare(f.input),input={repositoryID:7,commitSHA:p.finalSignedCommitSHA,shadowRef:p.shadowRef};
 await assert.rejects(f.core.lookupCandidate(input));f.refs.set(p.shadowRef,p.finalSignedCommitSHA);
 const proof=await f.core.lookupCandidate(input);assert.equal(proof.verified,true);assert.equal(proof.expectedMainParent,sha('a'));assert.equal(proof.sourceSHA,sha('c'));assert.equal(proof.commitSHA,p.finalSignedCommitSHA);
 await assert.rejects(f.core.lookupCandidate({...input,shadowRef:'refs/heads/main'}));
 f.setMain(sha('f'));await assert.rejects(f.core.lookupCandidate(input));f.setMain(sha('a'));
 const record=await f.storage.get(`source-signing:7:${p.sequence}`);record.signedCommit+='forged';await f.storage.put(`source-signing:7:${p.sequence}`,record);await assert.rejects(f.core.lookupCandidate(input));
});

test('private review policy lookup is absent explicitly or binds retained exact candidate policy without future runtime pins',async()=>{
 const f=await fixture();
 const absent=await f.core.prepare(f.input);f.refs.set(absent.shadowRef,absent.finalSignedCommitSHA);
 assert.equal(await f.core.lookupReviewPolicy({repositoryID:7,commitSHA:absent.finalSignedCommitSHA,shadowRef:absent.shadowRef}),null);
 f.config.candidateReviewPolicy={ownerID:42,reviewPolicy:structuredClone(f.config.reviewPolicy),scanPolicy:structuredClone(f.config.scanPolicy),priorJobs:{workflowID:100,workflowPath:'.github/workflows/build.yml',workflowDigest:hash('6'),jobWorkflowRef:'susanbeasles/workflow_depot/.github/workflows/orchestration.yml@'+sha('7'),jobWorkflowSHA:sha('7'),actorIDs:[21],requiredJobNames:['tests','scans'],scanJobName:'scans',maxAgeSeconds:300},applicablePolicy:{languages:['javascript']},maxAgeSeconds:300};
 const candidate=await f.core.prepare(f.input);f.refs.set(candidate.shadowRef,candidate.finalSignedCommitSHA);const input={repositoryID:7,commitSHA:candidate.finalSignedCommitSHA,shadowRef:candidate.shadowRef};
 const proof=await f.core.lookupReviewPolicy(input);assert.equal(proof.commitSHA,candidate.finalSignedCommitSHA);assert.equal(proof.policyDigest,f.config.policyDigest);assert.equal(proof.policy.priorJobs.policyDigest,f.config.policyDigest);assert.deepEqual(proof.policy.reviewPolicy,f.config.reviewPolicy);assert.equal(proof.policy.runtime,undefined);
 f.setMain(sha('f'));await assert.rejects(f.core.lookupReviewPolicy(input));f.setMain(sha('a'));
 f.config.candidateReviewPolicy.reviewPolicy.reviewerAppID=999;await assert.rejects(f.core.lookupReviewPolicy(input));
 const mismatch=await f.core.prepare(f.input);f.refs.set(mismatch.shadowRef,mismatch.finalSignedCommitSHA);await assert.rejects(f.core.lookupReviewPolicy({repositoryID:7,commitSHA:mismatch.finalSignedCommitSHA,shadowRef:mismatch.shadowRef}),/policy differs/i);
});

test('retained tag object substitution is denied before publication even when the signature field is unchanged',async()=>{
 const f=await fixture(),p=await f.core.prepare(f.input);await f.core.approve({repositoryID:7,sequence:p.sequence,ownerApproval:approval(p)});
 const record=await f.storage.get(`source-signing:7:${p.sequence}`);record.tags.source.object+='forged';record.tags.source.objectSHA=gitObjectID('tag',record.tags.source.object);await f.storage.put(`source-signing:7:${p.sequence}`,record);
 await assert.rejects(f.core.publish({repositoryID:7,sequence:p.sequence}));assert.equal(f.writes(),0);
});

test('installed verifier validates a real synthetic SSHSIG and its pinned public key, without signing',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'repoctl-source-ssh-test-'));
 try{
  const program=await realpath('/usr/bin/ssh-keygen'),programSHA256=sha256(await readFile(program));
  const pair=generateKeyPairSync('ed25519'),publicRaw=pair.publicKey.export({type:'spki',format:'der'}).subarray(-32);
  const string=b=>{const v=Buffer.from(b),n=Buffer.alloc(4);n.writeUInt32BE(v.length);return Buffer.concat([n,v]);};
  const blob=Buffer.concat([string('ssh-ed25519'),string(publicRaw)]),id='SHA256:'+createHash('sha256').update(blob).digest('base64').replace(/=+$/,'');
  const payload='synthetic public Git payload\n',digest=createHash('sha512').update(payload).digest(),signed=Buffer.concat([Buffer.from('SSHSIG'),string('git'),string(''),string('sha512'),string(digest)]);
  const version=Buffer.from([0,0,0,1]),signatureBlob=Buffer.concat([string('ssh-ed25519'),string(sign(null,signed,pair.privateKey))]);
  const wire=Buffer.concat([Buffer.from('SSHSIG'),version,string(blob),string('git'),string(''),string('sha512'),string(signatureBlob)]);
  const armor='-----BEGIN SSH SIGNATURE-----\n'+wire.toString('base64').match(/.{1,70}/g).join('\n')+'\n-----END SSH SIGNATURE-----\n';
  const publicKeyPath=join(dir,'fixture.pub');await writeFile(publicKeyPath,'ssh-ed25519 '+blob.toString('base64')+'\n',{mode:0o600});
  const signer=await createInstalledGitSigner({program,programSHA256,verifierProgram:program,verifierSHA256:programSHA256,publicKeyPath,keyID:id,agentSocket:join(dir,'NO_AGENT'),authorize:async()=>({authorized:false})});
  assert.equal(signatureKeyID(armor),id);assert.equal(await signer.verifyGit({payload,signature:armor}),true);assert.equal(await signer.verifyGit({payload:payload+'tampered',signature:armor}),false);
  await assert.rejects(signer.signGit({type:'commit',payload,authorization:{}}),/authorization denied/);
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('normal Git adapter retains complete original history and computes the squash tree without publishing',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'repoctl-source-git-test-'));
 try{
  const gitProgram=await realpath('/usr/bin/git'),gitProgramSHA256=sha256(await readFile(gitProgram));
  const git=(args,input)=>execFileSync(gitProgram,args,{cwd:dir,input,env:{PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'},encoding:'utf8'}).trim();
  git(['init','--bare','--quiet']);git(['symbolic-ref','HEAD','refs/heads/main']);const blob=git(['hash-object','-w','--stdin'],'fixture');const tree=git(['mktree'],`100644 blob ${blob}\tfixture.txt\n`);
  const commit=(parent,message)=>git(['hash-object','-t','commit','-w','--stdin'],`tree ${tree}\n${parent?'parent '+parent+'\n':''}author Fixture <fixture@example.test> 1000 +0000\ncommitter Fixture <fixture@example.test> 1000 +0000\n\n${message}\n`);
  const base=commit(null,'base'),one=commit(base,'source one'),two=commit(one,'source two');git(['update-ref','refs/heads/main',base]);git(['update-ref','refs/heads/source',two]);
  let archive;const adapter=await createLocalGitSource({repositoryPath:dir,gitProgram,gitProgramSHA256,archive:{retain:async value=>{archive=value;return {digest:value.digest,reference:'fixture-retained'};},read:async()=>archive.closure},inventory:{classify:async({entries})=>({complete:true,paths:entries.map(e=>e.path),languages:['text'],frameworks:[],manifests:[]})}});
  const snapshot=await adapter.snapshot({repositoryID:7,repository:'owner/fixture',sourceRef:'refs/heads/source',targetRef:'refs/heads/main'});
  assert.equal(snapshot.sourceSHA,two);assert.equal(snapshot.sourceBaseSHA,base);assert.equal(snapshot.treeSHA,tree);assert.ok([base,one,two,tree,blob].every(id=>archive.closure.objects.some(o=>o.sha===id)));assert.equal(git(['rev-parse','refs/heads/main']),base);
  // The real source producer and real publisher use the same complete object store.
  const f=await fixture();Object.assign(f.git,adapter);f.input.sourcePR.headSHA=two;const candidate=await f.core.prepare(f.input);
  const publisher=createSourcePublisher({config:{repository:'owner/project',repositoryID:7,gitDirectory:dir,gitPath:gitProgram,gitDigest:gitProgramSHA256},credential:async()=>{throw Error('No credentials in local Git fixture');},authorize:async()=>{throw Error('No remote mutation in local Git fixture');}});
  assert.equal(await publisher.putObject('commit',candidate.signedCommit),candidate.finalSignedCommitSHA);
  const closure=git(['rev-list','--objects','--no-object-names',candidate.finalSignedCommitSHA,two]).split('\n');assert.ok([candidate.finalSignedCommitSHA,base,one,two,tree,blob].every(id=>closure.includes(id)));git(['fsck','--connectivity-only','--no-reflogs']);
  assert.equal(git(['rev-parse','refs/heads/main']),base);assert.equal(git(['rev-parse','refs/heads/source']),two);
  git(['config','merge.hostile.driver','touch /tmp/not-executed']);await assert.rejects(adapter.snapshot({repositoryID:7,repository:'owner/fixture',sourceRef:'refs/heads/source',targetRef:'refs/heads/main'}),/External merge drivers/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
