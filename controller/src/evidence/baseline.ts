export interface Baseline {
 readonly repositoryID: number; readonly policyRevision: number;
 readonly policyDigest: string; readonly targetRef: string; readonly baseSHA: string;
}
export interface Baselines {verify(binding: Baseline,context: {signal: AbortSignal}): Promise<unknown>}
// Installed remote verifier compares effective provider controls against the
// independently accepted baseline enrolled for this exact policy revision.
export function baselineEvidence(baselines: Baselines,timeoutMS=10000) {
 if(typeof baselines?.verify!=='function'||!Number.isSafeInteger(timeoutMS)||timeoutMS<100||timeoutMS>10000)throw Error('Missing mandatory baseline verifier');
 return {async verify(value: Baseline): Promise<void> {
  const binding=Object.freeze({...value});
  if(Object.keys(binding).sort().join()!=='baseSHA,policyDigest,policyRevision,repositoryID,targetRef'||![binding.repositoryID,binding.policyRevision].every(v=>Number.isSafeInteger(v)&&v>0)||typeof binding.policyDigest!=='string'||!/^[a-f0-9]{64}$/.test(binding.policyDigest)||typeof binding.baseSHA!=='string'||!/^[a-f0-9]{40}$/.test(binding.baseSHA)||!['refs/heads/main','refs/heads/master'].includes(binding.targetRef))throw Error('Invalid baseline binding');
  const controller=new AbortController();let timer: ReturnType<typeof setTimeout>|undefined;
  try {
   const proof=await Promise.race([Promise.resolve().then(()=>baselines.verify(binding,{signal:controller.signal})),new Promise<never>((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Error('Baseline verification timed out'));},timeoutMS);})]);
   if(!proof||typeof proof!=='object'||!('verified' in proof)||proof.verified!==true||!('drift' in proof)||proof.drift!==false||Object.entries(binding).some(([key,value])=>Reflect.get(proof,key)!==value))throw Error('Remote baseline rejected');
  }catch{throw Error('Remote baseline rejected or unavailable');}
  finally{if(timer!==undefined)clearTimeout(timer);}
 }};
}
