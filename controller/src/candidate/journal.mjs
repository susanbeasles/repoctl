const hash=/^[a-f0-9]{64}$/,sha=/^[a-f0-9]{40}$/;
const fields=['repositoryID','ref','generationID','baseSHA','commitSHA','treeSHA'];
const phases=['reserved','creating','uncertain','confirmed'];
// Private installed storage; transaction contains no provider I/O or credentials.
// Generation IDs remain durable tombstones, never reusable after confirmation.
export function generationJournal(storage,repositoryID){
 if(!Number.isSafeInteger(repositoryID)||repositoryID<1||!['get','transaction'].every(k=>typeof storage?.[k]==='function'))throw Error('Invalid generation journal configuration');
 const key=id=>{if(typeof id!=='string'||!hash.test(id))throw Error('Invalid generation reference');return `candidate-generation:v1:${repositoryID}:${id}`;};
 function binding(b){
  if(!b||Object.getPrototypeOf(b)!==Object.prototype||Object.keys(b).sort().join()!==fields.slice().sort().join()||b.repositoryID!==repositoryID||!hash.test(b.generationID??'')||b.ref!=='refs/heads/int/'+b.generationID||![b.baseSHA,b.commitSHA,b.treeSHA].every(v=>sha.test(v??'')))throw Error('Invalid generation binding');return {...b};
 }
 function retained(r,id){if(!r)return null;const {phase,...b}=r;binding(b);if(b.generationID!==id||!phases.includes(phase))throw Error('Invalid retained generation');return {...r};}
 return {
  async reserve(value){const b=binding(value);return storage.transaction(async tx=>{const k=key(b.generationID),old=retained(await tx.get(k),b.generationID);if(old){if(fields.some(f=>old[f]!==b[f]))throw Error('Retained generation collision');return false;}await tx.put(k,{...b,phase:'reserved'});return true;});},
  async read(id){return retained(await storage.get(key(id)),id);},
  async transition(id,from,to){
   if(![['reserved','creating'],['creating','uncertain'],['creating','confirmed'],['uncertain','confirmed']].some(([a,b])=>a===from&&b===to))throw Error('Invalid generation phase transition');
   return storage.transaction(async tx=>{const k=key(id),r=retained(await tx.get(k),id);if(!r||r.phase!==from)return false;await tx.put(k,{...r,phase:to});return true;});
  }
 };
}
