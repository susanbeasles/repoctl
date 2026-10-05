import {canonical,digest,signEntry} from '../ledger.mjs';
import {gitRecoveryVerifier} from './git-recovery.mjs';
import {attestedRecovery} from './attested-recovery.mjs';
// Local/dedicated job. Restore, reader, signer and publisher are installed
// capabilities; untrusted callers supply only the bounded archive intent.
export function recoveryJob({restore,readerFor,signer,publisher,policyDigest,clock=()=>Date.now(),lifetimeMs=240000}){
 if(typeof restore?.run!=='function'||typeof readerFor!=='function'||typeof signer?.sign!=='function'||!(signer.trustedKeys instanceof Map)||typeof publisher?.create!=='function'||typeof publisher?.get!=='function'||!/^[a-f0-9]{64}$/.test(policyDigest??'')||!Number.isSafeInteger(lifetimeMs)||lifetimeMs<1||lifetimeMs>300000)throw Error('Invalid recovery job configuration');
 return {async run(intent){
  if(!intent||Object.getPrototypeOf(intent)!==Object.prototype||Object.keys(intent).sort().join()!==['repositoryID','commitSHA','sourceSHA','treeSHA','archiveDigests'].sort().join()||!Number.isSafeInteger(intent.repositoryID)||intent.repositoryID<1||![intent.commitSHA,intent.sourceSHA,intent.treeSHA].every(x=>/^[a-f0-9]{40}$/.test(x??''))||!Array.isArray(intent.archiveDigests)||!intent.archiveDigests.length||intent.archiveDigests.length>100||new Set(intent.archiveDigests).size!==intent.archiveDigests.length||!intent.archiveDigests.every(x=>/^[a-f0-9]{64}$/.test(x??'')))throw Error('Invalid recovery job intent');
  let session;
  try{
   session=await restore.run(structuredClone(intent));
   if(typeof session?.cleanup!=='function')throw Error('Recovery restore lacks cleanup capability');
   const recovered=await gitRecoveryVerifier({reader:await readerFor(session,intent)}).verify(intent);
   const {archiveVerified,recoveryVerified,digest:reportDigest,...report}=recovered;
   const verifiedAt=clock(),payload={kind:'archive-recovery',policyDigest,verifiedAt,expiresAt:verifiedAt+lifetimeMs,report};
   const envelope=await signer.sign(payload);
   const check=()=>attestedRecovery({store:{get:async()=>envelope},trustedKeys:signer.trustedKeys,policyDigest,clock}).verify(intent);
   await check(); // Wrong key, payload substitution and expiry fail before upload.
   const key='recovery/v1/'+intent.repositoryID+'/'+await digest(intent)+'.json';
   await publisher.create(key,envelope);
   const retained=await publisher.get(key);
   if(canonical(retained)!==canonical(envelope))throw Error('Recovery publication readback differs');
   await check();
   return {protocol:'repoctl-recovery-publication-v1',repositoryID:intent.repositoryID,key,reportDigest,envelopeDigest:await digest(envelope),expiresAt:payload.expiresAt,published:true};
  }finally{if(session&&typeof session.cleanup==='function')await session.cleanup();}
 }};
}
export function recoverySigner({keyID,privateKey,publicKey}){
 return {trustedKeys:new Map([[keyID,publicKey]]),async sign(payload){return (await signEntry(payload,keyID,privateKey)).envelope;}};
}
