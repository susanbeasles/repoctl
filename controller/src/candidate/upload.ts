import {generationRequest,generationResult} from './wire.ts';
export interface Generation {
 readonly repositoryID: number;
 readonly ref: string;
 readonly generationID: string;
 readonly baseSHA: string;
 readonly commitSHA: string;
 readonly treeSHA: string;
}
interface Context {signal: AbortSignal}
interface Store {pack(candidate: Readonly<Generation>, context: Context): Promise<Uint8Array>}
interface Transport {send(body: Uint8Array, context: Context): Promise<Uint8Array>}
interface Configuration {repositoryID: number; store: Store; transport: Transport}

// Installed isolated-job capabilities. No caller URL, credential, signer or
// arbitrary ref. The generation coordinator owns authorization and journal CAS.
export function generationUpload({repositoryID,store,transport}: Configuration) {
 if(!Number.isSafeInteger(repositoryID)||repositoryID<1||typeof store?.pack!=='function'||typeof transport?.send!=='function')throw Error('Invalid generation upload configuration');
 return {async create(value: Generation, context: Context) {
  if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join()!=='baseSHA,commitSHA,generationID,ref,repositoryID,treeSHA')throw Error('Invalid generation upload binding');
  const candidate=Object.freeze({...value});
  if(candidate.repositoryID!==repositoryID||typeof candidate.generationID!=='string'||!/^[a-f0-9]{64}$/.test(candidate.generationID)||candidate.ref!=='refs/heads/int/'+candidate.generationID||![candidate.baseSHA,candidate.commitSHA,candidate.treeSHA].every(v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v)&&!/^0+$/.test(v)))throw Error('Invalid generation upload binding');
  if(!context?.signal)throw Error('Generation upload requires cancellation');
  try {
   context.signal.throwIfAborted();
   const pack=await store.pack(candidate,context);
   context.signal.throwIfAborted();
   const request=generationRequest({generationID:candidate.generationID,commitSHA:candidate.commitSHA},pack);
   const result=await transport.send(request,context);
   context.signal.throwIfAborted();
   if(!generationResult(result,{generationID:candidate.generationID,commitSHA:candidate.commitSHA}))throw Error('Generation server rejected creation');
   return {ref:candidate.ref,object:{type:'commit',sha:candidate.commitSHA}};
  }catch{throw Error('Generation upload failed or uncertain; reconcile without resending');}
 }};
}
