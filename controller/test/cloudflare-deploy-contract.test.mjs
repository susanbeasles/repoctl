import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const core=await import('../src/cloudflare-deploy/contract.mjs').catch(e=>{if(e.code==='ERR_MODULE_NOT_FOUND')return {};throw e;});
const oidc=await import('../src/cloudflare-deploy/oidc.mjs').catch(e=>{if(e.code==='ERR_MODULE_NOT_FOUND')return {};throw e;});
const h=c=>c.repeat(64),s=c=>c.repeat(40),id=c=>c.repeat(32),uuid='12345678-1234-4123-8123-123456789abc',now=1800000000;
const raw=v=>new TextEncoder().encode(JSON.stringify(v));
const trust=()=>({audiencePrefix:'cloudflare-deploy',repository:'owner/delivery_control',repositoryID:1,ownerID:2,ref:'refs/heads/main',workflowRef:'owner/delivery_control/.github/workflows/deploy.yml@refs/heads/main',workflowSHA:s('a'),jobWorkflowRef:'owner/workflow_depot/.github/workflows/deploy.yml@'+s('b'),jobWorkflowSHA:s('b'),eventNames:['workflow_dispatch'],actorIDs:[3]});
async function fixture(){
 const artifact={schema:'workflow-depot-worker-artifact/v1',metadata:{main_module:'worker.mjs',compatibility_date:'2026-10-01',compatibility_flags:[],bindings:[]},modules:[{name:'worker.mjs',type:'esm',content:'export default { fetch() { return new Response("ok"); } };'}]};
 const metadataDigest=await core.digest(artifact.metadata),target={accountID:id('a'),scriptName:'example-worker',zoneID:id('b'),hostname:'app.example.com',metadataDigest,sourceRepository:'owner/project',sourceRepositoryID:4};
 const policy={schema:'workflow-depot-cloudflare-policy/v1',revision:1,enabled:true,authorizer:trust(),executor:trust(),targets:[target],maxArtifactBytes:5*1024*1024,verification:{signerKeyIDs:[h('c')],ciWorkflowRef:'owner/project/.github/workflows/ci.yml@refs/heads/main',ciWorkflowSHA:s('d'),requiredJobs:['Build']}};
 const op={schema:'workflow-depot-cloudflare-deploy/v1',operationID:h('a'),nonce:h('b'),policyDigest:await core.digest(policy),artifactDigest:await core.sha256(raw(artifact)),metadataDigest,accountID:target.accountID,scriptName:target.scriptName,zoneID:target.zoneID,hostname:target.hostname,expectedDeploymentID:uuid,source:{repository:'owner/project',repositoryID:4,commitSHA:s('c'),signerKeyID:h('c'),signingReceiptDigest:h('d'),ciRunID:5,ciRunAttempt:1},execution:{runID:6,runAttempt:1},expiresAt:now+300};
 return {artifact,policy,op,bytes:raw(artifact)};
}
test('shared core exports the agreed pure validation and identity interfaces',()=>{
 for(const n of ['canonical','digest','sha256','validatePolicy','validateOperation','validateArtifact'])assert.equal(typeof core[n],'function',n);
 for(const n of ['verifyOIDC','githubJWKS'])assert.equal(typeof oidc[n],'function',n);
});
test('operation and artifact match exact approved target and immutable byte digests',async()=>{
 const f=await fixture();assert.equal(core.validatePolicy(f.policy),f.policy);assert.equal(await core.validateOperation(f.op,f.policy,now),f.op);assert.deepEqual(await core.validateArtifact(f.bytes,f.op,f.policy),f.artifact);
 assert.equal(await core.sha256(f.bytes),createHash('sha256').update(f.bytes).digest('hex'));
 assert.equal(core.canonical({z:1,a:[true,null]}),'{"a":[true,null],"z":1}');assert.throws(()=>core.canonical({bad:undefined}));
});
test('exact routes and service-only targets preserve approved ingress without creating a hostname',async()=>{
 for(const type of ['routes','service-only']){
  const f=await fixture(),target=f.policy.targets[0];target.ingress={type,zoneIDs:[id('b'),id('c')]};
  if(type==='routes')target.ingress.routes=[{id:id('d'),zoneID:id('b'),pattern:target.hostname+'/component*'}];else target.zoneID=target.hostname=null;
  Object.assign(f.op,{zoneID:target.zoneID,hostname:target.hostname,ingress:structuredClone(target.ingress),policyDigest:await core.digest(f.policy)});
  assert.equal(core.validatePolicy(f.policy),f.policy);assert.equal(await core.validateOperation(f.op,f.policy,now),f.op);assert.deepEqual(await core.validateArtifact(f.bytes,f.op,f.policy),f.artifact);
  await assert.rejects(core.validateOperation({...f.op,ingress:{...f.op.ingress,zoneIDs:[id('b')]}},f.policy,now));
  const omitted=structuredClone(f.op);delete omitted.ingress;await assert.rejects(core.validateOperation(omitted,f.policy,now));
 }
});
test('ingress schemas reject wildcard hosts, duplicate IDs, unknown routes and service-only hostname fallback',async()=>{
 const f=await fixture(),base=f.policy.targets[0],route={id:id('d'),zoneID:base.zoneID,pattern:base.hostname+'/component*'},good={type:'routes',zoneIDs:[base.zoneID],routes:[route]};
 for(const ingress of [{type:'anything',zoneIDs:[base.zoneID]},{...good,zoneIDs:[]},{...good,zoneIDs:[base.zoneID,base.zoneID]},{...good,routes:[]},{...good,routes:[route,route]},{...good,routes:[{...route,zoneID:id('e')}]},{...good,routes:[{...route,pattern:'*.example.com/*'}]},{...good,routes:[{...route,pattern:base.hostname+'/x*/y'}]},{...good,routes:[{...route,script:'other'}]},{type:'service-only',zoneIDs:[base.zoneID]}])assert.throws(()=>core.validatePolicy({...f.policy,targets:[{...base,ingress}]}));
});
test('installed SSH signer fingerprints authorize only an exact pinned canonical identity',async()=>{
 const f=await fixture(),ssh='SHA256:'+Buffer.alloc(32,0xfb).toString('base64').replace(/=+$/,'');
 f.policy.verification.signerKeyIDs=[ssh];f.op.source.signerKeyID=ssh;f.op.policyDigest=await core.digest(f.policy);
 assert.equal(core.validatePolicy(f.policy),f.policy);
 assert.equal(await core.validateOperation(f.op,f.policy,now),f.op);
 assert.deepEqual(await core.validateArtifact(f.bytes,f.op,f.policy),f.artifact);
 const other='SHA256:'+Buffer.alloc(32,0xfa).toString('base64').replace(/=+$/,'');
 for(const signerKeyID of [other,h('c'),ssh.toLowerCase()])await assert.rejects(core.validateOperation({...f.op,source:{...f.op.source,signerKeyID}},f.policy,now));
 const invalid=[ssh+'=',ssh.slice(0,-1),ssh+'A',ssh.replace(/\+/g,'-').replace(/\//g,'_'),ssh.replace('SHA256:','sha256:'),'SHA256:'+'A'.repeat(42)+'B',ssh+'\n',[ssh]];
 for(const signerKeyID of invalid)assert.throws(()=>core.validatePolicy({...f.policy,verification:{...f.policy.verification,signerKeyIDs:[signerKeyID]}}));
});
test('artifact inspection validates bytes before a deployment operation exists',async()=>{
 const f=await fixture();assert.equal(typeof core.inspectArtifact,'function');
 assert.deepEqual(await core.inspectArtifact(f.bytes,5*1024*1024),{artifact:f.artifact,artifactDigest:f.op.artifactDigest,metadataDigest:f.op.metadataDigest});
 for(const limit of [0,5*1024*1024+1,undefined])await assert.rejects(core.inspectArtifact(f.bytes,limit));
 await assert.rejects(core.inspectArtifact(f.bytes,f.bytes.length-1));
 const malformed=structuredClone(f.artifact);malformed.metadata.bindings=[{name:'SECRET',type:'secret_text',text:'synthetic'}];await assert.rejects(core.inspectArtifact(raw(malformed),5*1024*1024));
});
test('disabled placeholders cannot authorize deployment',async()=>{
 const f=await fixture(),disabled={...f.policy,enabled:false,authorizer:{},executor:{},targets:[],verification:{}};
 assert.equal(core.validatePolicy(disabled),disabled);await assert.rejects(core.validateOperation(f.op,disabled,now));
});
test('read-only admission may validate zero targets without weakening deployment or trust checks',async()=>{
 const f=await fixture(),policy={...f.policy,targets:[]};
 assert.throws(()=>core.validatePolicy(policy));
 assert.equal(core.validatePolicy(policy,{requireDeploymentTarget:false}),policy);
 for(const patch of [{authorizer:{}},{executor:{}},{verification:{}},{targets:'not-an-array'}])assert.throws(()=>core.validatePolicy({...policy,...patch},{requireDeploymentTarget:false}));
 for(const requireDeploymentTarget of [null,0,'false'])assert.throws(()=>core.validatePolicy(policy,{requireDeploymentTarget}));
 await assert.rejects(core.validateOperation({...f.op,policyDigest:await core.digest(policy)},policy,now));
 await assert.rejects(core.validateArtifact(f.bytes,{...f.op,policyDigest:await core.digest(policy)},policy));
});
test('policy refuses malformed trust, duplicate targets, unsafe destinations and unbounded artifacts',async()=>{
 const f=await fixture();
 for(const patch of [{other:true},{revision:0},{enabled:'true'},{targets:[]},{targets:[f.policy.targets[0],f.policy.targets[0]]},{maxArtifactBytes:5*1024*1024+1},{maxArtifactBytes:0},{authorizer:{...trust(),issuer:'https://evil.test'}},{executor:{...trust(),repositoryID:0}},{executor:{...trust(),workflowRef:'other/repo/.github/workflows/deploy.yml@refs/heads/main'}},{verification:{...f.policy.verification,signerKeyIDs:[]}},{verification:{...f.policy.verification,requiredJobs:[]}},{verification:{...f.policy.verification,requiredJobs:['Build','Build']}}])assert.throws(()=>core.validatePolicy({...f.policy,...patch}));
 for(const hostname of ['*.example.com','APP.example.com','https://app.example.com','app.example.com.','localhost','127.0.0.1','app..example.com','app.example.com/path'])assert.throws(()=>core.validatePolicy({...f.policy,targets:[{...f.policy.targets[0],hostname}]}));
});
test('operation refuses altered policy/target, unsigned source claims, malformed execution and expiry',async()=>{
 const f=await fixture();
 for(const patch of [{unexpected:true},{policyDigest:h('f')},{metadataDigest:h('f')},{accountID:id('f')},{scriptName:'other'},{zoneID:id('f')},{hostname:'other.example.com'},{expectedDeploymentID:'not-a-uuid'},{source:{...f.op.source,repository:'unrelated/project'}},{source:{...f.op.source,repositoryID:99}},{source:{...f.op.source,signerKeyID:h('f')}},{source:{...f.op.source,signingReceiptDigest:undefined}},{source:{...f.op.source,ciRunID:0}},{source:{...f.op.source,artifactURL:'https://evil.test'}},{execution:{runID:6,runAttempt:0}},{expiresAt:now},{expiresAt:now+601},{operationID:'../escape'},{nonce:'unsafe'}])await assert.rejects(core.validateOperation({...f.op,...patch},f.policy,now));
 const changed=structuredClone(f.policy);changed.verification.ciWorkflowSHA=s('e');await assert.rejects(core.validateOperation(f.op,changed,now));
});
test('schema fields reject coercible non-string identifiers',async()=>{
 const f=await fixture();
 for(const patch of [{scriptName:123},{accountID:[id('a')]},{metadataDigest:[f.op.metadataDigest]},{sourceRepository:['owner/project']}])assert.throws(()=>core.validatePolicy({...f.policy,targets:[{...f.policy.targets[0],...patch}]}));
 for(const patch of [{expectedDeploymentID:[uuid]},{operationID:[h('a')]},{source:{...f.op.source,commitSHA:[s('c')]}}])await assert.rejects(core.validateOperation({...f.op,...patch},f.policy,now));
 assert.throws(()=>core.validatePolicy({...f.policy,executor:{...trust(),jobWorkflowSHA:[s('b')]}}));
});
test('artifact verification hashes exact bytes and rejects stale metadata',async()=>{
 const f=await fixture();await assert.rejects(core.validateArtifact(new Uint8Array([...f.bytes,10]),f.op,f.policy));
 f.artifact.metadata.compatibility_flags=['nodejs_compat'];const bytes=raw(f.artifact);await assert.rejects(core.validateArtifact(bytes,{...f.op,artifactDigest:await core.sha256(bytes)},f.policy));
 await assert.rejects(core.validateArtifact(f.bytes,{...f.op,artifactDigest:'f'.repeat(64)},f.policy));
});
test('artifact rejects unapproved metadata capabilities even when its digests are approved',async()=>{
 const f=await fixture();
 for(const metadata of [{...f.artifact.metadata,migrations:{}},{...f.artifact.metadata,assets:{}},{...f.artifact.metadata,keep_bindings:['secret_text']},{...f.artifact.metadata,compatibility_date:'2026-02-30'},{...f.artifact.metadata,compatibility_flags:['nodejs_compat','nodejs_compat']},{...f.artifact.metadata,bindings:[{type:'secret_text',name:'SECRET',text:'fixture'}]},{...f.artifact.metadata,bindings:[{type:'inherit',name:'OLD',text:'replacement'}]},{...f.artifact.metadata,bindings:[{type:'inherit',name:'*'}]},{...f.artifact.metadata,bindings:[{type:'service',name:'S',service:'x',environment:'unapproved'}]},{...f.artifact.metadata,bindings:[{type:'plain_text',name:'A',text:'one'},{type:'plain_text',name:'A',text:'two'}]}]){
  const bytes=raw({...f.artifact,metadata}),metadataDigest=await core.digest(metadata),policy={...f.policy,targets:[{...f.policy.targets[0],metadataDigest}]},op={...f.op,metadataDigest,policyDigest:await core.digest(policy),artifactDigest:await core.sha256(bytes)};
  await assert.rejects(core.validateArtifact(bytes,op,policy));
 }
});
test('artifact accepts only approved references to supported existing bindings',async()=>{
 const f=await fixture();f.artifact.metadata.bindings=[{type:'plain_text',name:'MODE',text:'production'},{type:'r2_bucket',name:'BUCKET',bucket_name:'existing-bucket'},{type:'d1',name:'DB',database_id:uuid},{type:'kv_namespace',name:'CACHE',namespace_id:id('c')},{type:'service',name:'SERVICE',service:'existing-service',entrypoint:'ExistingService'},{type:'durable_object_namespace',name:'OBJECT',namespace_id:id('d')},{type:'inherit',name:'EXISTING_SECRET'}];
 const metadataDigest=await core.digest(f.artifact.metadata),policy={...f.policy,targets:[{...f.policy.targets[0],metadataDigest}]},bytes=raw(f.artifact),op={...f.op,metadataDigest,policyDigest:await core.digest(policy),artifactDigest:await core.sha256(bytes)};
 assert.deepEqual(await core.validateArtifact(bytes,op,policy),f.artifact);
});
test('artifact refuses extra modules, malformed UTF8, executable metadata and oversized bytes',async()=>{
 const f=await fixture();
 for(const artifact of [{...f.artifact,command:'deploy'},{...f.artifact,modules:[...f.artifact.modules,...f.artifact.modules]},{...f.artifact,modules:[{...f.artifact.modules[0],name:'../worker.mjs'}]},{...f.artifact,modules:[{...f.artifact.modules[0],type:'commonjs'}]}]){
  const bytes=raw(artifact);await assert.rejects(core.validateArtifact(bytes,{...f.op,artifactDigest:await core.sha256(bytes)},f.policy));
 }
 const invalid=new Uint8Array([0xff,0xfe]);await assert.rejects(core.validateArtifact(invalid,{...f.op,artifactDigest:await core.sha256(invalid)},f.policy));
 await assert.rejects(core.validateArtifact(new Uint8Array(5*1024*1024+1),f.op,f.policy));
});
test('strict pinned OIDC validates actual signatures and rejects caller trust or claim substitution',async()=>{
 const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
 const key={...await crypto.subtle.exportKey('jwk',pair.publicKey),kid:'synthetic-oidc'},t=trust(),binding={operationID:h('a'),runID:6,runAttempt:1};
 const claims={iss:'https://token.actions.githubusercontent.com',aud:t.audiencePrefix+':'+binding.operationID,iat:now,nbf:now,exp:now+300,repository:t.repository,repository_id:'1',repository_owner_id:'2',ref:t.ref,workflow_ref:t.workflowRef,workflow_sha:t.workflowSHA,job_workflow_ref:t.jobWorkflowRef,job_workflow_sha:t.jobWorkflowSHA,runner_environment:'github-hosted',run_id:'6',run_attempt:'1',event_name:'workflow_dispatch',actor_id:'3',jti:'synthetic-jti'};
 async function token(patch={},header={alg:'RS256',kid:key.kid}){const enc=v=>Buffer.from(JSON.stringify(v)).toString('base64url'),body=enc(header)+'.'+enc({...claims,...patch});return body+'.'+Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,Buffer.from(body))).toString('base64url');}
 assert.equal((await oidc.verifyOIDC(await token(),t,binding,{keys:[key]},now)).jti,'synthetic-jti');
 for(const patch of [{aud:'other'},{run_attempt:'2'},{job_workflow_sha:s('f')},{repository_id:'999'},{exp:now},{actor_id:'99'}])await assert.rejects(oidc.verifyOIDC(await token(patch),t,binding,{keys:[key]},now));
 await assert.rejects(oidc.verifyOIDC(await token(),{...t,jwksURL:'https://evil.test'},binding,{keys:[key]},now));
 await assert.rejects(oidc.verifyOIDC(await token({}, {alg:'none',kid:key.kid}),t,binding,{keys:[key]},now));
 let requested;await oidc.githubJWKS(async(url,options)=>{requested=url;assert.equal(options.redirect,'manual');return Response.json({keys:[key]});});assert.equal(requested,'https://token.actions.githubusercontent.com/.well-known/jwks');
});
