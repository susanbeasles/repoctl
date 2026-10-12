import {randomUUID} from 'node:crypto';
import {integrationRef} from './integration-ref.mjs';
const check=(ok,message='Integration reconciliation denied')=>{if(!ok)throw Error(message);};
const sha=v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v);
// Install once in a durable, single-owner repository actor. Signing operations
// must reconcile the supplied durable operationID; they must never blindly retry.
export function createIntegrationLifecycle({storage,source,signing}){
 check(storage&&typeof storage.get==='function'&&typeof storage.put==='function'&&typeof source?.current==='function'&&['prepare','publish','retire'].every(k=>typeof signing?.[k]==='function'));
 let tail=Promise.resolve();
 function serial(fn){const result=tail.then(fn);tail=result.catch(()=>{});return result;}
 async function current(input){
  check(input&&Object.keys(input).sort().join()==='repositoryID,sourcePRNumber'&&[input.repositoryID,input.sourcePRNumber].every(v=>Number.isSafeInteger(v)&&v>0));
  const s=await source.current(input);check(s?.repositoryID===input.repositoryID&&s.sourcePRNumber===input.sourcePRNumber&&s.headRepositoryID===input.repositoryID&&sha(s.headSHA)&&sha(s.baseSHA)&&['open','closed'].includes(s.state));
  const ref=integrationRef(s.headRef);return {...s,integrationRef:ref};
 }
 const stamp=s=>JSON.stringify([s.repositoryID,s.sourcePRNumber,s.headRef,s.headSHA,s.baseRef,s.baseSHA,s.state]);
 async function reconcile(input,retire=false){
  let s=await current(input);const key=`integration-lifecycle:${input.repositoryID}:${input.sourcePRNumber}`;let record=await storage.get(key)??{};
  const ownerKey=`integration-owner:${input.repositoryID}:${s.integrationRef}`,owner=await storage.get(ownerKey);check(owner===undefined||owner===input.sourcePRNumber||(await storage.get(`integration-lifecycle:${input.repositoryID}:${owner}`))?.state==='retired','Integration ref owned by another PR');await storage.put(ownerKey,input.sourcePRNumber);
  if(retire||s.state!=='open'||s.baseRef!=='refs/heads/main'){
   // Resolve any admitted signing operation before retirement. Never abandon an
   // unknown side effect and submit a fresh signing request with a different ID.
   if(record.pending&&!record.pending.candidate){record.pending.candidate=await signing.prepare({input:record.pending.input,operationID:record.pending.prepareID});await storage.put(key,record);}
   if((record.pending?.candidate&&!record.pending.candidate.noChanges)||record.published){record.retireID??=randomUUID();await storage.put(key,record);await signing.retire({repositoryID:input.repositoryID,sequence:(record.pending?.candidate?.noChanges?record.published:(record.pending?.candidate??record.published)).sequence,operationID:record.retireID});}
   record={state:'retired'};await storage.put(key,record);return {state:'retired'};
  }
  if(['published','no-changes'].includes(record.state)&&record.stamp===stamp(s))return {state:'unchanged',candidate:record.published};
  if(!record.pending){
   check(s.prepareInput?.repositoryID===input.repositoryID&&s.prepareInput.sourcePR?.number===input.sourcePRNumber&&s.prepareInput.sourcePR.repositoryID===input.repositoryID&&s.prepareInput.sourcePR.headSHA===s.headSHA,'Source prepare coordinates differ');
   record.pending={stamp:stamp(s),input:structuredClone(s.prepareInput),prepareID:randomUUID(),publishID:randomUUID()};await storage.put(key,record);
  }
  const pending=record.pending;
  if(!pending.candidate){pending.candidate=await signing.prepare({input:pending.input,operationID:pending.prepareID});check(Number.isSafeInteger(pending.candidate.sequence)&&pending.candidate.sequence>0&&pending.candidate.shadowRef===s.integrationRef);await storage.put(key,record);}
  if(pending.candidate.noChanges){
   if(record.published){record.retireID??=randomUUID();await storage.put(key,record);await signing.retire({repositoryID:input.repositoryID,sequence:record.published.sequence,operationID:record.retireID});}
   await storage.put(key,{state:'no-changes',stamp:pending.stamp});return {state:'no-changes'};
  }
  s=await current(input);
  if(stamp(s)!==pending.stamp){record.pending=null;record.state='stale';await storage.put(key,record);return {state:'stale'};}
  const published=await signing.publish({repositoryID:input.repositoryID,sequence:pending.candidate.sequence,operationID:pending.publishID});
  record={state:'published',stamp:pending.stamp,published:{...pending.candidate,...published}};await storage.put(key,record);
  s=await current(input);return {state:stamp(s)===record.stamp?'published':'stale',candidate:record.published};
 }
 return Object.freeze({reconcileIntegration:input=>serial(()=>reconcile(input)),retireIntegration:input=>serial(()=>reconcile(input,true))});
}
