import {canonical,digest,verifyEntry} from '../ledger.mjs';
const hash=/^[a-f0-9]{64}$/,sha=/^[a-f0-9]{40}$/;
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.sort().join();
// Installed storage and signer inventory. No request-selected keys or endpoints.
export function attestedRecovery({store,trustedKeys,policyDigest,clock=()=>Date.now(),maxAgeMs=300000}){
 if(typeof store?.get!=='function'||!(trustedKeys instanceof Map)||!trustedKeys.size||!hash.test(policyDigest??'')||!Number.isSafeInteger(maxAgeMs)||maxAgeMs<1||maxAgeMs>300000)throw Error('Invalid recovery attestation configuration');
 return {async verify(intent){
  if(!exact(intent,['repositoryID','commitSHA','sourceSHA','treeSHA','archiveDigests'])||!Number.isSafeInteger(intent.repositoryID)||intent.repositoryID<1||![intent.commitSHA,intent.sourceSHA,intent.treeSHA].every(v=>sha.test(v??''))||!Array.isArray(intent.archiveDigests)||!intent.archiveDigests.length||intent.archiveDigests.length>100||new Set(intent.archiveDigests).size!==intent.archiveDigests.length||!intent.archiveDigests.every(v=>hash.test(v??'')))throw Error('Invalid recovery attestation intent');
  const envelope=await store.get(await digest(intent));
  if(!exact(envelope,['protocol','algorithm','keyID','payload','signature']))throw Error('Missing or malformed recovery attestation');
  await verifyEntry(envelope,trustedKeys);const p=envelope.payload,now=clock();
  if(!exact(p,['kind','policyDigest','verifiedAt','expiresAt','report'])||p.kind!=='archive-recovery'||p.policyDigest!==policyDigest||!Number.isSafeInteger(p.verifiedAt)||!Number.isSafeInteger(p.expiresAt)||p.verifiedAt>now||p.expiresAt<=now||p.expiresAt<=p.verifiedAt||p.expiresAt-p.verifiedAt>maxAgeMs||now-p.verifiedAt>maxAgeMs)throw Error('Recovery attestation policy or lifetime denied');
  const r=p.report;
  if(!exact(r,['protocol','intent','objects','recovery'])||r.protocol!=='repoctl-archive-evidence-v1'||canonical(r.intent)!==canonical(intent)||!Array.isArray(r.objects)||!r.objects.length||r.objects.length>10000)throw Error('Recovery report binding denied');
  const ids=new Set();let total=0;
  for(const o of r.objects){if(!exact(o,['objectID','type','archiveDigest','bytes','contentDigest'])||!sha.test(o.objectID??'')||ids.has(o.objectID)||!['commit','tree','blob'].includes(o.type)||!intent.archiveDigests.includes(o.archiveDigest)||!Number.isSafeInteger(o.bytes)||o.bytes<1||!hash.test(o.contentDigest??''))throw Error('Recovery object inventory denied');ids.add(o.objectID);total+=o.bytes;if(!Number.isSafeInteger(total))throw Error('Recovery size overflow');}
  const v=r.recovery;
  if(!exact(v,['candidate','source','tree','reachableHistoryComplete','gitlinks','totalBytes'])||v.candidate!==intent.commitSHA||v.source!==intent.sourceSHA||v.tree!==intent.treeSHA||v.reachableHistoryComplete!==true||v.totalBytes!==total||!Array.isArray(v.gitlinks)||!v.gitlinks.every(x=>sha.test(x??''))||![intent.commitSHA,intent.sourceSHA,intent.treeSHA].every(x=>ids.has(x)))throw Error('Recovery closure denied');
  return {...r,digest:await digest(r),archiveVerified:true,recoveryVerified:true};
 }};
}
