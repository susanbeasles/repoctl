import test from 'node:test';import assert from 'node:assert/strict';
import {validateDeploymentRequest,verifyDeploymentRequest} from '../src/deployments.mjs';
const q={repository:'susanbeasles/personal-control',repository_id:'1408909065',sha:'a'.repeat(40),source_run_id:'123',target:'personal-control'};
function fixture(change={}){return {request:async path=>{
 if(path.endsWith('/actions/runs/123'))return {event:'push',head_branch:'main',head_sha:q.sha,repository:{id:1408909065},status:'completed',conclusion:'success',workflow_id:8,...change.run};
 if(path.endsWith('/actions/workflows/8'))return {path:'.github/workflows/deploy.yml',...change.workflow};
 if(path.includes('/commits/'))return {sha:q.sha,commit:{verification:{verified:true}},...change.commit};
 if(path.endsWith('/git/ref/heads/main'))return {object:{sha:change.head??q.sha}};
 return {id:1408909065,owner:{id:215839550,login:'susanbeasles'},default_branch:'main',fork:false,archived:false,...change.repo};
}};}
test('valid signed current-main source run maps to the fixed deployment target',async()=>{assert.equal((await verifyDeploymentRequest(q,fixture())).checkout_repository,q.repository);});
test('caller cannot redirect repositories, target, immutable identity or revision',()=>{for(const change of [{repository:'attacker/personal-control'},{repository_id:'1'},{sha:'main'},{target:'signing-control'},{source_run_id:'../123'}])assert.throws(()=>validateDeploymentRequest({...q,...change}));});
test('reject unsigned, stale, failed, forked, PR and substituted workflow source',async()=>{for(const change of [{commit:{commit:{verification:{verified:false}}}},{head:'b'.repeat(40)},{run:{conclusion:'failure'}},{run:{event:'pull_request'}},{repo:{fork:true}},{workflow:{path:'.github/workflows/other.yml'}}])await assert.rejects(verifyDeploymentRequest(q,fixture(change)));});
test('runtime targets remain blocked before any credential or deployment action',async()=>{const {services,requireCommissioned}=await import('../src/deployments.mjs');for(const service of services){if(service.state==='source-only')assert.doesNotThrow(()=>requireCommissioned(service));else assert.throws(()=>requireCommissioned(service),/Deployment blocked/);}});
test('source receipt exception cannot authorize a runtime target',async()=>{await assert.rejects(verifyDeploymentRequest(q,fixture(),{self:true}),/Invalid controller source receipt/);});
test('retired Worker targets cannot be reintroduced through dispatch',()=>{for(const [target,repository,repository_id] of [['deployment-authority','susanbeasles/workflow_depot','1405415683'],['cloudflare-deployer','susanbeasles/delivery_control','1405415291']])assert.throws(()=>validateDeploymentRequest({...q,target,repository,repository_id}),/Unregistered/);});
test('dedicated application sources own their targets, shared login does not',()=>{for(const [target,repository,repository_id] of [['ghcaretaker','susanbeasles/ghcaretaker','1405513776'],['backup-control','susanbeasles/backup-control','1407276404'],['backup-setup','susanbeasles/backup-control','1407276404']]){assert.throws(()=>validateDeploymentRequest({...q,target}));assert.equal(validateDeploymentRequest({...q,target,repository,repository_id}).repository,repository);}});
