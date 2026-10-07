import {canonical,digest} from '../ledger.mjs';
import type {Baseline} from './baseline.ts';
interface Context {signal: AbortSignal}
interface Provider {get(path: string,context: Context): Promise<unknown>}
interface Configuration {baseline: unknown; ownerID: number; policyRevision: number; policyDigest: string; provider: Provider}
interface Row {id: number;source: string;source_type: string;body: Record<string,unknown>}
function object(value: unknown): Record<string,unknown> {
 if(!value||typeof value!=='object'||Object.getPrototypeOf(value)!==Object.prototype)throw Error('Invalid baseline object');return value as Record<string,unknown>;
}
function fields(value: Record<string,unknown>,names: string[]) {
 if(Object.keys(value).sort().join()!==names.slice().sort().join())throw Error('Invalid baseline schema');
}
function rows(value: unknown,rules: boolean): Row[] {
 if(!Array.isArray(value)||!value.length||value.length>2000)throw Error('Incomplete baseline inventory');
 const seen=new Set<number>();return value.map(value=>{
  const row=object(value);fields(row,['id','source','source_type','body']);
  if(typeof row.id!=='number'||!Number.isSafeInteger(row.id)||row.id<1||seen.has(row.id)||typeof row.source!=='string'||!row.source||typeof row.source_type!=='string'||!['Repository','Organization','Enterprise'].includes(row.source_type))throw Error('Invalid baseline inventory identity');seen.add(row.id);
  const body=object(row.body);fields(body,rules?['name','target','enforcement','conditions','rules','bypass_actors']:['name','enforcement','conditions','rules']);
  if(typeof body.name!=='string'||!body.name||body.enforcement!=='active'||!Array.isArray(body.rules)||!body.rules.length||(rules&&(!['branch','tag'].includes(body.target as string)||!Array.isArray(body.bypass_actors))))throw Error('Invalid baseline policy body');object(body.conditions);
  return {id:row.id,source:row.source,source_type:row.source_type,body};
 }).sort((a,b)=>a.id-b.id);
}
// Configuration is supplied by accepted baseline authority. This observer proves
// configuration equality, never signature enrollment or effective enforcement.
export function baselineObserver({baseline: input,ownerID,policyRevision,policyDigest,provider}: Configuration) {
 const text=JSON.stringify(input);if(typeof text!=='string'||text.length>1048576)throw Error('Invalid baseline size');
 const baseline=object(JSON.parse(text));
 fields(baseline,['protocol','repository','repository_id','owner_id','default_branch','settings','rulesets','actions_policies','actions_permissions','selected_actions','workflow_permissions','immutable_releases']);
 const repository=baseline.repository;
 if(baseline.protocol!=='repoctl-repository-baseline-v1'||typeof repository!=='string'||!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)||typeof baseline.repository_id!=='number'||!Number.isSafeInteger(baseline.repository_id)||baseline.repository_id<1||baseline.owner_id!==ownerID||!Number.isSafeInteger(ownerID)||ownerID<1||!['main','master'].includes(baseline.default_branch as string)||!Number.isSafeInteger(policyRevision)||policyRevision<1||typeof policyDigest!=='string'||!/^[a-f0-9]{64}$/.test(policyDigest)||typeof provider?.get!=='function')throw Error('Invalid baseline identity');
 const repo=repository as string;
 const settings=object(baseline.settings);fields(settings,['archived','fork','allow_auto_merge','delete_branch_on_merge']);
 if(!Object.values(settings).every(v=>typeof v==='boolean')||settings.archived!==false||settings.fork!==false)throw Error('Invalid baseline settings');
 const expectedRules=rows(baseline.rulesets,true),expectedActions=rows(baseline.actions_policies,false);
 const actions=object(baseline.actions_permissions),workflow=object(baseline.workflow_permissions),immutable=object(baseline.immutable_releases);
 if(actions.enabled!==true||!['all','selected','local_only'].includes(actions.allowed_actions as string)||workflow.default_workflow_permissions!=='read'||workflow.can_approve_pull_request_reviews!==false||immutable.enabled!==true)throw Error('Unsafe or incomplete baseline controls');
 if(actions.allowed_actions==='selected')object(baseline.selected_actions);else if(baseline.selected_actions!==null)throw Error('Unexpected selected-actions baseline');
 return {async verify(value: Baseline,context: Context) {
  const binding=Object.freeze({...value});
  if(Object.keys(binding).sort().join()!=='baseSHA,policyDigest,policyRevision,repositoryID,targetRef'||binding.repositoryID!==baseline.repository_id||binding.policyRevision!==policyRevision||binding.policyDigest!==policyDigest||binding.targetRef!=='refs/heads/'+baseline.default_branch||typeof binding.baseSHA!=='string'||!/^[a-f0-9]{40}$/.test(binding.baseSHA))throw Error('Observed baseline binding differs');
  const get=async(path: string)=>{context.signal.throwIfAborted();const value=await provider.get(path,context);context.signal.throwIfAborted();return value;};
  const compare=(actual: unknown,expected: unknown)=>{if(canonical(actual)!==canonical(expected))throw Error('Accepted baseline configuration drift');};
  async function identity() {
   const metadata=object(await get('')),owner=object(metadata.owner);
   if(metadata.id!==binding.repositoryID||typeof metadata.full_name!=='string'||metadata.full_name.toLowerCase()!==repo.toLowerCase()||owner.id!==ownerID||owner.type!=='User'||metadata.default_branch!==baseline.default_branch)throw Error('Baseline repository identity drift');
   compare(Object.fromEntries(Object.keys(settings).map(key=>[key,metadata[key]])),settings);
   const tip=object(await get('/git/ref/heads/'+baseline.default_branch)),target=object(tip.object);
   if(tip.ref!==binding.targetRef||target.type!=='commit'||target.sha!==binding.baseSHA)throw Error('Baseline protected ref moved');
  }
  async function inventory(rules: boolean,expected: Row[]) {
   const observed: Row[]=[];const seen=new Set<number>();let complete=false;
   for(let page=1;page<=20;page++){
    const path=rules?'/rulesets?per_page=100&page='+page+'&includes_parents=true':'/actions/policies?per_page=100&page='+page+'&has_parents=true';
    const response=await get(path),items=rules?response:object(response).policies;
    if(!Array.isArray(items)||items.length>100)throw Error('Incomplete baseline inventory page');
    for(const item of items){const row=object(item),id=row.id;
     if(typeof id!=='number'||!Number.isSafeInteger(id)||id<1||seen.has(id)||typeof row.source!=='string'||typeof row.source_type!=='string')throw Error('Ambiguous baseline inventory');seen.add(id);
     const actual=object(await get((rules?'/rulesets/':'/actions/policies/')+id));if(actual.id!==id)throw Error('Foreign baseline policy detail');
     const keys=rules?['name','target','enforcement','conditions','rules','bypass_actors']:['name','enforcement','conditions','rules'];
     observed.push({id,source:row.source,source_type:row.source_type,body:Object.fromEntries(keys.map(key=>[key,actual[key]]))});
    }
    if(items.length<100){complete=true;break;}
   }
   if(!complete)throw Error('Baseline inventory truncated');compare(observed.sort((a,b)=>a.id-b.id),expected);
  }
  async function controls() {
   compare(await get('/actions/permissions'),actions);
   if(actions.allowed_actions==='selected')compare(await get('/actions/permissions/selected-actions'),baseline.selected_actions);
   compare(await get('/actions/permissions/workflow'),workflow);compare(await get('/immutable-releases'),immutable);
  }
  try{
   for(let pass=0;pass<2;pass++){await identity();await inventory(true,expectedRules);await inventory(false,expectedActions);await controls();}
   await identity();
   const report={protocol:'repoctl-baseline-observation-v1',binding,configurationVerified:true};
   return {...report,observationDigest:await digest({...report,baseline})};
  }catch{throw Error('Remote baseline configuration denied or unavailable');}
 }};
}
