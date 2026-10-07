import test from 'node:test';
import assert from 'node:assert/strict';
import {baselineObserver} from '../src/evidence/baseline-observer.ts';
const binding={repositoryID:7,policyRevision:1,policyDigest:'a'.repeat(64),targetRef:'refs/heads/main',baseSHA:'b'.repeat(40)};
function fixture(){
 const rules={id:1,name:'protected',target:'branch',enforcement:'active',conditions:{},rules:[{type:'non_fast_forward'}],bypass_actors:[]};
 const actions={id:2,name:'actors',enforcement:'active',conditions:{},rules:[{type:'actor'}]};
 const baseline={protocol:'repoctl-repository-baseline-v1',repository:'owner/fixture',repository_id:7,owner_id:9,default_branch:'main',settings:{archived:false,fork:false,allow_auto_merge:false,delete_branch_on_merge:false},rulesets:[{id:1,source:'owner/fixture',source_type:'Repository',body:{name:rules.name,target:rules.target,enforcement:rules.enforcement,conditions:rules.conditions,rules:rules.rules,bypass_actors:rules.bypass_actors}}],actions_policies:[{id:2,source:'owner/fixture',source_type:'Repository',body:{name:actions.name,enforcement:actions.enforcement,conditions:actions.conditions,rules:actions.rules}}],actions_permissions:{enabled:true,allowed_actions:'all'},selected_actions:null,workflow_permissions:{default_workflow_permissions:'read',can_approve_pull_request_reviews:false},immutable_releases:{enabled:true}};
 let reads=0;const state={drift:false,foreign:false,missing:false,duplicate:false,changeDuring:false,endMove:false};
 const get=async path=>{
  reads++;if(state.changeDuring&&reads>8)state.drift=true;
  if(path==='')return {id:state.foreign?8:7,full_name:'owner/fixture',owner:{id:9,type:'User'},default_branch:'main',...baseline.settings};
  if(path==='/git/ref/heads/main')return {ref:'refs/heads/main',object:{type:'commit',sha:state.endMove&&reads>=20?'c'.repeat(40):binding.baseSHA}};
  if(path.startsWith('/rulesets?')){const row={id:1,source:'owner/fixture',source_type:'Repository'};return state.missing?[]:state.duplicate?[row,row]:[row];}
  if(path==='/rulesets/1')return {...rules,enforcement:state.drift?'disabled':'active'};
  if(path.startsWith('/actions/policies?'))return {policies:[{id:2,source:'owner/fixture',source_type:'Repository'}]};
  if(path==='/actions/policies/2')return actions;
  if(path==='/actions/permissions')return baseline.actions_permissions;
  if(path==='/actions/permissions/workflow')return baseline.workflow_permissions;
  if(path==='/immutable-releases')return baseline.immutable_releases;
  throw Error('Unexpected path '+path);
 };
 return {baseline,state,get,reads:()=>reads};
}
test('remote observer compares complete accepted configuration twice without claiming effective enforcement',async()=>{
 const f=fixture();const observer=baselineObserver({baseline:f.baseline,ownerID:9,policyRevision:1,policyDigest:binding.policyDigest,provider:{get:f.get}});
 const result=await observer.verify(binding,{signal:new AbortController().signal});assert.equal(result.configurationVerified,true);assert.equal('verified' in result,false);assert.equal(f.reads(),20);
});
test('foreign identity, missing/duplicate controls and mid-observation drift deny baseline configuration',async()=>{
 for(const key of ['foreign','missing','duplicate','drift','changeDuring','endMove']){const f=fixture();f.state[key]=true;await assert.rejects(baselineObserver({baseline:f.baseline,ownerID:9,policyRevision:1,policyDigest:binding.policyDigest,provider:{get:f.get}}).verify(binding,{signal:new AbortController().signal}));}
});

import {baselineEvidence} from '../src/evidence/baseline.ts';
test('configuration observation alone cannot satisfy effective-baseline authorization gate',async()=>{
 const f=fixture(),observer=baselineObserver({baseline:f.baseline,ownerID:9,policyRevision:1,policyDigest:binding.policyDigest,provider:{get:f.get}});
 await assert.rejects(baselineEvidence({verify:value=>observer.verify(value,{signal:new AbortController().signal})}).verify(binding),/baseline/);
});
test('configured baseline is snapshotted and provider denial cannot expose private payloads',async()=>{
 const f=fixture();const observer=baselineObserver({baseline:f.baseline,ownerID:9,policyRevision:1,policyDigest:binding.policyDigest,provider:{get:f.get}});
 f.baseline.rulesets[0].body.enforcement='disabled';
 assert.equal((await observer.verify(binding,{signal:new AbortController().signal})).configurationVerified,true);
 const denied=baselineObserver({baseline:fixture().baseline,ownerID:9,policyRevision:1,policyDigest:binding.policyDigest,provider:{get:async()=>{throw Error('SECRET-PROVIDER');}}});
 await assert.rejects(denied.verify(binding,{signal:new AbortController().signal}),error=>!error.message.includes('SECRET-PROVIDER'));
});

test('full twenty-page inventory is rejected as truncated rather than silently accepted',async()=>{
 const f=fixture();let pages=0,details=0;
 const get=async(path,context)=>{
  if(path.startsWith('/rulesets?')){const page=Number(new URL('https://internal'+path).searchParams.get('page'));pages++;return Array.from({length:100},(_,index)=>({id:(page-1)*100+index+1,source:'owner/fixture',source_type:'Repository'}));}
  if(path.startsWith('/rulesets/')){details++;return {id:Number(path.split('/').at(-1)),...f.baseline.rulesets[0].body};}
  return f.get(path,context);
 };
 await assert.rejects(baselineObserver({baseline:f.baseline,ownerID:9,policyRevision:1,policyDigest:binding.policyDigest,provider:{get}}).verify(binding,{signal:new AbortController().signal}));
 assert.equal(pages,20);assert.equal(details,2000);
});
