import {test} from 'node:test';import assert from 'node:assert/strict';
import {recoveryUploadGateway} from '../src/archive/upload-gateway.mjs';import {digest} from '../src/ledger.mjs';
test('recovery upload binds signed OIDC to exact publication and pinned workflow without credentials',async()=>{
 const now=1000,pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
 const key=await crypto.subtle.exportKey('jwk',pair.publicKey);key.kid='test';
 const trust={audiencePrefix:'repoctl-recovery',repository:'owner/jobs',repositoryID:10,ownerID:20,ref:'refs/heads/main',workflowRef:'owner/jobs/.github/workflows/recover.yml@refs/heads/main',workflowSHA:'a'.repeat(40),jobWorkflowRef:'owner/depot/.github/workflows/recover.yml@refs/heads/main',jobWorkflowSHA:'b'.repeat(40),actorIDs:[30],eventNames:['workflow_dispatch'],targetRepositoryIDs:[7]};
 const publication={intent:{repositoryID:7},envelope:{signed:'report'}};let calls=0;
 const gateway=recoveryUploadGateway({trust,clock:()=>now,jwks:async()=>({keys:[key]}),publisher:{async fetch(r){calls++;assert.equal(new URL(r.url).pathname,'/v1/archive/recovery/publish');assert.equal(r.headers.get('authorization'),null);assert.deepEqual(await r.json(),publication);return Response.json({published:true});}}});
 async function token(overrides={}){const c={iss:'https://token.actions.githubusercontent.com',aud:'repoctl-recovery:'+await digest(publication),iat:now,nbf:now,exp:now+300,repository:trust.repository,repository_id:'10',repository_owner_id:'20',ref:trust.ref,workflow_ref:trust.workflowRef,workflow_sha:trust.workflowSHA,job_workflow_ref:trust.jobWorkflowRef,job_workflow_sha:trust.jobWorkflowSHA,runner_environment:'github-hosted',run_id:'60',run_attempt:'1',actor_id:'30',event_name:'workflow_dispatch',jti:'recovery-unique-id',...overrides};const enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url'),input=enc({alg:'RS256',kid:'test'})+'.'+enc(c);return input+'.'+Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,Buffer.from(input))).toString('base64url');}
 const request=(jwt,p=publication)=>new Request('https://upload.example/v1/archive/recovery/upload',{method:'POST',headers:{authorization:'Bearer '+jwt},body:JSON.stringify({publication:p,runID:60,runAttempt:1})});
 const jwt=await token();assert.equal((await gateway.fetch(request(jwt))).status,200);assert.equal(calls,1);
 for(const changes of [{actor_id:'31'},{job_workflow_sha:'c'.repeat(40)},{event_name:'pull_request'},{run_attempt:'2'},{exp:999}])assert.equal((await gateway.fetch(request(await token(changes)))).status,403);
 assert.equal((await gateway.fetch(request(jwt,{...publication,envelope:{signed:'altered'}}))).status,403);
 assert.equal((await gateway.fetch(request(jwt,{...publication,intent:{repositoryID:8}}))).status,403);assert.equal(calls,1);
});
