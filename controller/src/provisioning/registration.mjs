import {verifyAppPlan} from './plan.mjs';
const valid = x => typeof x==='string' && /^[a-f0-9]{64}$/.test(x);
const hash = async x => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(x))),b=>b.toString(16).padStart(2,'0')).join('');
// Private adapter: enrollment independently authorizes the reviewed manifest.
// Its implementation must bind owner, role and manifestDigest to approvalReference.
export function registrationSessions(storage,enrollment,callback,clock=()=>Date.now()) {
 const key=id=>{if(!valid(id))throw Error('Invalid operation');return `registration:${id}`;};
 return {
  async create(operationID,plan,approvalReference,expiresAt) {
   const reviewed=await verifyAppPlan(plan);
   if(!valid(approvalReference)||reviewed.manifest.redirect_url!==callback||!Number.isSafeInteger(expiresAt)||expiresAt<=clock()||expiresAt>clock()+300000)throw Error('Invalid registration authorization');
   const state=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
   const stateDigest=await hash(state);
   await storage.transaction(async tx=>{if(await tx.get(key(operationID)))throw Error('Registration already exists');if(await tx.get(`registration-state:${stateDigest}`))throw Error('State collision');await tx.put(`registration-state:${stateDigest}`,operationID);await tx.put(key(operationID),{approvalReference,manifestDigest:reviewed.manifestDigest,manifestBytes:reviewed.manifestBytes,stateDigest,expiresAt,state:'reserved'});});
   await enrollment.create({operationID,approvalReference,reviewed});
   await storage.transaction(async tx=>{const r=await tx.get(key(operationID));if(r.state!=='reserved')throw Error('Registration changed');await tx.put(key(operationID),{...r,state:'ready'});});
   return {operationID,state,expiresAt,manifestBytes:reviewed.manifestBytes,registrationURL:`https://github.com/settings/apps/new?state=${state}`};
  },
  async resolve(state) {if(!valid(state))throw Error('Invalid state');const id=await storage.get(`registration-state:${await hash(state)}`);if(!id)throw Error('Unknown state');return id;},
  async launch(operationID,state) {if(!valid(state))throw Error('Invalid state');const r=await storage.get(key(operationID));if(!r||r.state!=='ready'||r.expiresAt<=clock()||r.stateDigest!==await hash(state))throw Error('Invalid registration session');return {manifestBytes:r.manifestBytes};},
  async complete(operationID,state,code) {
   if(!valid(state)||typeof code!=='string'||!/^[A-Za-z0-9_-]{1,200}$/.test(code))throw Error('Invalid callback');
   const stateDigest=await hash(state);
   const r=await storage.transaction(async tx=>{const r=await tx.get(key(operationID));if(!r||r.state!=='ready'||r.expiresAt<=clock()||r.stateDigest!==stateDigest)throw Error('Invalid callback');await tx.put(key(operationID),{...r,state:'exchanging'});return r;});
   // Reserve before networking; lost response requires custody reconciliation.
   // Never retain callback code, credentials, or unfiltered provider responses.
   const result=await enrollment.exchange({operationID,approvalReference:r.approvalReference,code});
   if(!Number.isSafeInteger(result?.appID)||result.appID<=0)throw Error('Invalid custody result');
   await storage.transaction(async tx=>{const current=await tx.get(key(operationID));if(current?.state!=='exchanging')throw Error('Registration changed');await tx.put(key(operationID),{...current,state:'completed',appID:result.appID});});
   return {operationID,state:'completed',appID:result.appID};
  }
 };
}
