import {canonical,digest,sha256,validatePolicy,validateOperation} from './shared/contract.mjs';
import {verifyOIDC,githubJWKS} from './shared/oidc.mjs';

const HEX=/^[a-f0-9]{64}$/, UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const terminal=new Set(['completed','uncertain']);
function requireThat(value,code){if(!value)throw Error(code);}
function exact(value,keys,code='invalid-request'){
 requireThat(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(','),code);
}
function freeze(value){if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
function snapshot(value){const text=JSON.stringify(value);requireThat(typeof text==='string'&&new TextEncoder().encode(text).length<=65536,'request-too-large');return freeze(JSON.parse(text));}
function token(value){requireThat(typeof value==='string'&&value.length>0&&value.length<=16384,'invalid-identity');}
function identifier(value){requireThat(typeof value==='string'&&HEX.test(value),'invalid-request');}
function run(value){requireThat(Number.isSafeInteger(value)&&value>0,'invalid-request');}
function randomLease(){return [...crypto.getRandomValues(new Uint8Array(32))].map(x=>x.toString(16).padStart(2,'0')).join('');}

// The storage implementation must atomically commit or roll back every transaction.
// The trusted workflow adapter must preserve global nonce/JTI and target locks across runs.
export function createDeploymentAuthority({storage,policy,evidence,verifyIdentity=verifyOIDC,jwks=githubJWKS,now=()=>Math.floor(Date.now()/1000)}={}){
 requireThat(typeof evidence?.verify==='function','evidence-required');
 requireThat(typeof storage?.transaction==='function'&&typeof storage?.get==='function','atomic-storage-required');
 requireThat(typeof policy==='function','policy-required');
 async function current(operation){
  const value=snapshot(policy());validatePolicy(value);requireThat(value.enabled===true,'authority-disabled');
  requireThat(/^[^/]+\/delivery_control$/.test(value.authorizer.repository),'invalid-authorizer');
  requireThat(value.executor.repository===value.authorizer.repository,'invalid-executor');
  requireThat(value.authorizer.audiencePrefix!==value.executor.audiencePrefix,'distinct-authorization-audience-required');
  if(operation){await validateOperation(operation,value,now());requireThat(await digest(value)===operation.policyDigest,'policy-changed');}
  return value;
 }
 async function identity(oidcToken,trust,operationID,runID,runAttempt){
  token(oidcToken);run(runID);run(runAttempt);
  const who=await verifyIdentity(oidcToken,trust,{operationID,runID,runAttempt},await jwks(),now());
  requireThat(who&&typeof who.jti==='string'&&/^[\x21-\x7e]{1,256}$/.test(who.jti)&&Number.isSafeInteger(who.expiresAt)&&who.expiresAt>now()&&who.runID===String(runID)&&who.runAttempt===String(runAttempt),'invalid-identity');
  return {...who,tombstone:'jti:'+await sha256(new TextEncoder().encode(who.jti))};
 }
 function unexpired(who){requireThat(who.expiresAt>now(),'identity-expired');}
 async function verified(operation){
  const result=await evidence.verify(freeze(structuredClone(operation)));
  exact(result,['verified','operationID','artifactDigest','sourceSHA'],'evidence-rejected');
  requireThat(result.verified===true&&result.operationID===operation.operationID&&result.artifactDigest===operation.artifactDigest&&result.sourceSHA===operation.source.commitSHA,'evidence-rejected');
 }
 async function get(operationID,source=storage){const record=await source.get('op:'+operationID);requireThat(record,'operation-not-found');return record;}
 function active(record,leaseID){requireThat(record.leaseID===leaseID,'lease-mismatch');requireThat(!record.revoked,'operation-revoked');requireThat(record.identityExpiresAt>now(),'identity-expired');}
 const lease=record=>({operation:structuredClone(record.operation),leaseID:record.leaseID,identityExpiresAt:record.identityExpiresAt});
 const targetKey=op=>'target:'+op.accountID+':'+op.scriptName;
 async function status(input){
  input=snapshot(input);exact(input,['operationID','oidcToken','runID','runAttempt']);identifier(input.operationID);
  const p=await current(),who=await identity(input.oidcToken,p.executor,input.operationID,input.runID,input.runAttempt);
  const record=await storage.get('op:'+input.operationID);unexpired(who);
  requireThat(await digest(await current())===await digest(p),'policy-changed');
  if(!record)return {operationID:input.operationID,state:'pending'};
  await current(record.operation);unexpired(who);
  requireThat(record.operation.execution.runID===input.runID&&record.operation.execution.runAttempt===input.runAttempt,'execution-mismatch');
  requireThat(record.state==='authorized'&&!record.revoked,'operation-not-authorized');
  return {operationID:input.operationID,state:'authorized'};
 }
 async function authorize(input){
  input=snapshot(input);exact(input,['operation','oidcToken','authorizerRunID','authorizerRunAttempt']);
  const op=input.operation,p=await current(op),who=await identity(input.oidcToken,p.authorizer,op.operationID,input.authorizerRunID,input.authorizerRunAttempt);
  await verified(op);
  return storage.transaction(async tx=>{
   await current(op);unexpired(who);
   requireThat(!await tx.get('op:'+op.operationID),'operation-exists');
   requireThat(!await tx.get('nonce:'+op.nonce),'nonce-replayed');
   requireThat(!await tx.get(who.tombstone),'identity-replayed');
   await tx.put('op:'+op.operationID,{operation:op,state:'authorized',revoked:false,authorizedAt:now()});
   await tx.put('nonce:'+op.nonce,op.operationID);await tx.put(who.tombstone,op.operationID);
   return {operationID:op.operationID,state:'authorized'};
  });
 }
 async function revoke(input){
  input=snapshot(input);exact(input,['operation','oidcToken','authorizerRunID','authorizerRunAttempt']);identifier(input.operation?.operationID);
  const op=input.operation,p=await current(),who=await identity(input.oidcToken,p.authorizer,op.operationID,input.authorizerRunID,input.authorizerRunAttempt),policyHash=await digest(p);
  return storage.transaction(async tx=>{
   requireThat(await digest(await current())===policyHash,'policy-changed');unexpired(who);
   const record=await get(op.operationID,tx);requireThat(canonical(record.operation)===canonical(op),'operation-mismatch');
   requireThat(!await tx.get(who.tombstone),'identity-replayed');requireThat(!record.revoked,'operation-revoked');
   await tx.put(who.tombstone,op.operationID);await tx.put('op:'+op.operationID,{...record,revoked:true,revokedAt:now()});
   return {operationID:op.operationID,state:'revoked'};
  });
 }
 async function consume(input){
  input=snapshot(input);exact(input,['operationID','oidcToken']);identifier(input.operationID);
  const record=await get(input.operationID),op=record.operation,p=await current(op);
  requireThat(record.state==='authorized','operation-not-authorized');requireThat(!record.revoked,'operation-revoked');
  const who=await identity(input.oidcToken,p.executor,op.operationID,op.execution.runID,op.execution.runAttempt),leaseID=randomLease();
  return storage.transaction(async tx=>{
   await current(op);unexpired(who);const retained=await get(op.operationID,tx);
   requireThat(retained.state==='authorized','operation-not-authorized');requireThat(!retained.revoked,'operation-revoked');
   requireThat(!await tx.get(who.tombstone),'identity-replayed');requireThat(!await tx.get('consumed:'+op.nonce),'nonce-replayed');
   requireThat(!await tx.get(targetKey(op)),'target-locked');
   const claimed={...retained,state:'claimed',leaseID,identityExpiresAt:who.expiresAt,claimedAt:now()};
   await tx.put('op:'+op.operationID,claimed);await tx.put(who.tombstone,op.operationID);await tx.put('consumed:'+op.nonce,op.operationID);await tx.put(targetKey(op),op.operationID);
   return lease(claimed);
  });
 }
 async function check(input){
  input=snapshot(input);exact(input,['operationID','leaseID','stage']);identifier(input.operationID);identifier(input.leaseID);
  requireThat(['upload','activate'].includes(input.stage),'invalid-stage');const expected=input.stage==='upload'?'claimed':'upload-authorized';
  const record=await get(input.operationID);active(record,input.leaseID);requireThat(record.state===expected,'stage-conflict');await current(record.operation);
  await verified(record.operation);
  return storage.transaction(async tx=>{
   const retained=await get(input.operationID,tx);active(retained,input.leaseID);requireThat(retained.state===expected,'stage-conflict');await current(retained.operation);
   // Recheck time after asynchronous policy validation as well as evidence I/O.
   active(retained,input.leaseID);requireThat(retained.operation.expiresAt>now(),'operation-expired');
   requireThat(await tx.get(targetKey(retained.operation))===input.operationID,'target-lock-mismatch');
   const next={...retained,state:input.stage+'-authorized',[input.stage+'AuthorizedAt']:now()};await tx.put('op:'+input.operationID,next);return lease(next);
  });
 }
 async function complete(input){
  input=snapshot(input);exact(input,['operationID','leaseID','outcome','receipt']);identifier(input.operationID);identifier(input.leaseID);
  requireThat(terminal.has(input.outcome),'invalid-outcome');exact(input.receipt,['versionID','deploymentID'],'invalid-receipt');
  for(const value of Object.values(input.receipt))requireThat(value===null||typeof value==='string'&&UUID.test(value),'invalid-receipt');
  if(input.outcome==='completed')requireThat(Object.values(input.receipt).every(v=>typeof v==='string'),'invalid-receipt');
  return storage.transaction(async tx=>{
   const record=await get(input.operationID,tx);requireThat(record.leaseID===input.leaseID,'lease-mismatch');requireThat(!terminal.has(record.state),'terminal-state');
   requireThat(input.outcome==='completed'?record.state==='activate-authorized':['claimed','upload-authorized','activate-authorized'].includes(record.state),'stage-conflict');
   requireThat(await tx.get(targetKey(record.operation))===input.operationID,'target-lock-mismatch');
   await tx.put('op:'+input.operationID,{...record,state:input.outcome,receipt:input.receipt,completedAt:now()});
   // Retain uncertain locks, including failures whose remote outcome is unknown.
   if(input.outcome==='completed')await tx.put(targetKey(record.operation),null);
   return {operationID:input.operationID,state:input.outcome};
  });
 }
 return Object.freeze({authorize,revoke,status,consume,check,complete});
}
