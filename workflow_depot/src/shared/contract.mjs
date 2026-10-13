import {validateTrust} from './oidc.mjs';
const encoder=new TextEncoder();
const hex=/^[a-f0-9]{64}$/,id=/^[a-f0-9]{32}$/,sha=/^[a-f0-9]{40}$/;
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const repository=/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const script=/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const identifier=/^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/;
const matches=(pattern,value)=>typeof value==='string'&&pattern.test(value);
// OpenSSH prints SHA-256 fingerprints as 32-byte standard base64 without padding.
// Restrict the final character to zero padding bits; identities are never normalized.
const signerKey=value=>(matches(hex,value)&&value.length===64)||(matches(/^SHA256:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$/,value)&&value.length===50);
const positive=v=>Number.isSafeInteger(v)&&v>0;
const object=v=>v!==null&&typeof v==='object'&&Object.getPrototypeOf(v)===Object.prototype;
const exact=(v,keys)=>object(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const fail=()=>{throw Error('Cloudflare deployment contract denied');};
const require=v=>{if(!v)fail();};
export function canonical(value){
 if(value===null||typeof value==='boolean'||typeof value==='string')return JSON.stringify(value);
 if(typeof value==='number'&&Number.isSafeInteger(value))return String(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(object(value))return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 fail();
}
function byteView(value){if(value instanceof Uint8Array)return value;if(value instanceof ArrayBuffer)return new Uint8Array(value);fail();}
export async function sha256(bytes){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',byteView(bytes)))].map(v=>v.toString(16).padStart(2,'0')).join('');}
export async function digest(value){return sha256(encoder.encode(canonical(value)));}
function hostname(value){return typeof value==='string'&&value.length<=253&&value.includes('.')&&value.split('.').every(p=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p))&&/^[a-z][a-z0-9-]*$/.test(value.split('.').at(-1));}
function workflow(value){return typeof value==='string'&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml@(?:refs\/heads\/[A-Za-z0-9_.\/-]+|[a-f0-9]{40})$/.test(value);}
export function validateIngress(target){
 if(!Object.hasOwn(target,'ingress')){require(matches(id,target.zoneID)&&hostname(target.hostname));return {type:'custom-domain'};}
 const value=target.ingress;
 require(object(value)&&['routes','service-only'].includes(value.type)&&exact(value,value.type==='routes'?['type','zoneIDs','routes']:['type','zoneIDs']));
 require(Array.isArray(value.zoneIDs)&&value.zoneIDs.length>0&&value.zoneIDs.length<=100&&value.zoneIDs.every(v=>matches(id,v))&&new Set(value.zoneIDs).size===value.zoneIDs.length&&canonical(value.zoneIDs)===canonical([...value.zoneIDs].sort()));
 if(value.type==='service-only'){require(target.zoneID===null&&target.hostname===null);return value;}
 require(matches(id,target.zoneID)&&hostname(target.hostname)&&value.zoneIDs.includes(target.zoneID)&&Array.isArray(value.routes)&&value.routes.length>0&&value.routes.length<=100);
 const ids=[];
 for(const route of value.routes){
  require(exact(route,['id','zoneID','pattern'])&&matches(id,route.id)&&route.zoneID===target.zoneID&&typeof route.pattern==='string'&&route.pattern.length<=1024&&route.pattern.startsWith(target.hostname+'/'));
  require(/^[A-Za-z0-9._~!$&'()+,;=:@\/-]*\*?$/.test(route.pattern.slice(target.hostname.length+1)));ids.push(route.id);
 }
 require(new Set(ids).size===ids.length&&canonical(ids)===canonical([...ids].sort())&&new Set(value.routes.map(r=>r.pattern)).size===value.routes.length);
 return value;
}
export function validatePolicy(policy,{requireDeploymentTarget=true}={}){
 require(typeof requireDeploymentTarget==='boolean');
 require(exact(policy,['schema','revision','enabled','authorizer','executor','targets','maxArtifactBytes','verification']));
 require(policy.schema==='workflow-depot-cloudflare-policy/v1'&&positive(policy.revision)&&typeof policy.enabled==='boolean'&&positive(policy.maxArtifactBytes)&&policy.maxArtifactBytes<=5*1024*1024);
 for(const trust of [policy.authorizer,policy.executor])if(policy.enabled||!exact(trust,[]))validateTrust(trust);
 require(Array.isArray(policy.targets)&&policy.targets.length<=100&&(!policy.enabled||!requireDeploymentTarget||policy.targets.length>0));
 const targets=new Set();
 for(const t of policy.targets){
  require(exact(t,['accountID','scriptName','zoneID','hostname','metadataDigest','sourceRepository','sourceRepositoryID',...(Object.hasOwn(t,'ingress')?['ingress']:[])]));
  require(matches(id,t.accountID)&&matches(script,t.scriptName)&&matches(hex,t.metadataDigest)&&matches(repository,t.sourceRepository)&&positive(t.sourceRepositoryID));validateIngress(t);
  const key=t.accountID+'/'+t.scriptName;require(!targets.has(key));targets.add(key);
 }
 const v=policy.verification;
 if(policy.enabled||!exact(v,[])){
  require(exact(v,['signerKeyIDs','ciWorkflowRef','ciWorkflowSHA','requiredJobs'])&&Array.isArray(v.signerKeyIDs)&&v.signerKeyIDs.length>0&&v.signerKeyIDs.length<=20&&v.signerKeyIDs.every(signerKey)&&new Set(v.signerKeyIDs).size===v.signerKeyIDs.length&&workflow(v.ciWorkflowRef)&&matches(sha,v.ciWorkflowSHA));
  require(Array.isArray(v.requiredJobs)&&v.requiredJobs.length>0&&v.requiredJobs.length<=20&&v.requiredJobs.every(n=>typeof n==='string'&&n.length>0&&n.length<=150&&n.trim()===n&&!/[\u0000-\u001f\u007f]/.test(n))&&new Set(v.requiredJobs).size===v.requiredJobs.length);
  const ref=v.ciWorkflowRef.split('@')[1];if(matches(sha,ref))require(ref===v.ciWorkflowSHA);
 }
 return policy;
}
function operationTarget(op,policy){
 require(exact(op,['schema','operationID','nonce','policyDigest','artifactDigest','metadataDigest','accountID','scriptName','zoneID','hostname','expectedDeploymentID','source','execution','expiresAt',...(Object.hasOwn(op,'ingress')?['ingress']:[])]));
 require(op.schema==='workflow-depot-cloudflare-deploy/v1'&&['operationID','nonce','policyDigest','artifactDigest','metadataDigest'].every(k=>matches(hex,op[k]))&&matches(uuid,op.expectedDeploymentID)&&positive(op.expiresAt));
 require(exact(op.source,['repository','repositoryID','commitSHA','signerKeyID','signingReceiptDigest','ciRunID','ciRunAttempt'])&&matches(repository,op.source.repository)&&positive(op.source.repositoryID)&&matches(sha,op.source.commitSHA)&&signerKey(op.source.signerKeyID)&&matches(hex,op.source.signingReceiptDigest)&&positive(op.source.ciRunID)&&positive(op.source.ciRunAttempt));
 require(exact(op.execution,['runID','runAttempt'])&&positive(op.execution.runID)&&positive(op.execution.runAttempt));
 require(policy.verification.signerKeyIDs.includes(op.source.signerKeyID));
 const target=policy.targets.find(t=>t.accountID===op.accountID&&t.scriptName===op.scriptName&&t.zoneID===op.zoneID&&t.hostname===op.hostname&&t.metadataDigest===op.metadataDigest&&t.sourceRepository===op.source.repository&&t.sourceRepositoryID===op.source.repositoryID);
 require(target&&Object.hasOwn(target,'ingress')===Object.hasOwn(op,'ingress')&&canonical(validateIngress(target))===canonical(validateIngress(op)));return target;
}
export async function validateOperation(op,policy,now=Math.floor(Date.now()/1000)){
 validatePolicy(policy);require(policy.enabled&&positive(now));operationTarget(op,policy);
 require(op.expiresAt>now&&op.expiresAt<=now+600&&op.policyDigest===await digest(policy));return op;
}
function binding(b){
 require(object(b)&&matches(identifier,b.name));
 // Inheritance only names an approved binding. The provider adapter must also
 // prove it is an existing secret on the unchanged active/latest version and
 // require strict inheritance; this shape validation does not prove that state.
 const keys={inherit:['name','type'],plain_text:['name','type','text'],r2_bucket:['name','type','bucket_name'],d1:['name','type','database_id'],kv_namespace:['name','type','namespace_id'],service:['name','type','service',...(Object.hasOwn(b,'entrypoint')?['entrypoint']:[])],durable_object_namespace:['name','type','namespace_id']};
 require(Object.hasOwn(keys,b.type)&&exact(b,keys[b.type]));
 if(b.type==='plain_text')require(typeof b.text==='string'&&encoder.encode(b.text).length<=32768);
 if(b.type==='r2_bucket')require(typeof b.bucket_name==='string'&&/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(b.bucket_name));
 if(b.type==='d1')require(matches(uuid,b.database_id));
 if(['kv_namespace','durable_object_namespace'].includes(b.type))require(matches(id,b.namespace_id));
 if(b.type==='service')require(matches(script,b.service)&&(!Object.hasOwn(b,'entrypoint')||matches(identifier,b.entrypoint)));
}
export async function validateArtifact(bytes,op,policy){
 validatePolicy(policy);require(policy.enabled);operationTarget(op,policy);
 require(op.policyDigest===await digest(policy));
 const inspected=await inspectArtifact(bytes,policy.maxArtifactBytes);
 require(op.artifactDigest===inspected.artifactDigest&&op.metadataDigest===inspected.metadataDigest);
 return inspected.artifact;
}
export async function inspectArtifact(bytes,maxArtifactBytes){
 require(positive(maxArtifactBytes)&&maxArtifactBytes<=5*1024*1024);
 const data=byteView(bytes);require(data.length>0&&data.length<=maxArtifactBytes);
 const artifact=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data));
 require(exact(artifact,['schema','metadata','modules'])&&artifact.schema==='workflow-depot-worker-artifact/v1');
 const m=artifact.metadata;require(exact(m,['main_module','compatibility_date','compatibility_flags','bindings'])&&m.main_module==='worker.mjs');
 require(typeof m.compatibility_date==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(m.compatibility_date));
 const date=new Date(m.compatibility_date+'T00:00:00Z');require(Number.isFinite(date.valueOf())&&date.toISOString().slice(0,10)===m.compatibility_date);
 require(Array.isArray(m.compatibility_flags)&&m.compatibility_flags.length<=100&&m.compatibility_flags.every(v=>typeof v==='string'&&/^[a-z][a-z0-9_]{0,99}$/.test(v))&&new Set(m.compatibility_flags).size===m.compatibility_flags.length);
 require(Array.isArray(m.bindings)&&m.bindings.length<=100);const names=new Set();
 for(const b of m.bindings){binding(b);require(!names.has(b.name));names.add(b.name);}
 require(Array.isArray(artifact.modules)&&artifact.modules.length===1);const module=artifact.modules[0];
 require(exact(module,['name','type','content'])&&module.name==='worker.mjs'&&module.type==='esm'&&typeof module.content==='string'&&module.content.length>0);
 return {artifact,artifactDigest:await sha256(data),metadataDigest:await digest(m)};
}
