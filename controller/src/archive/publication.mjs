import {digest} from '../ledger.mjs';
import {attestedRecovery} from './attested-recovery.mjs';
import {recoveryR2Publisher} from './r2-publisher.mjs';
export function recoveryPublication({bucket,configurations,clock}){
 if(!Array.isArray(configurations)||!configurations.length||configurations.length>100)throw Error('Invalid publication configuration');
 const configs=new Map();for(const c of configurations){if(!Number.isSafeInteger(c.repositoryID)||c.repositoryID<1||configs.has(c.repositoryID)||!/^[a-f0-9]{64}$/.test(c.policyDigest??'')||!(c.trustedKeys instanceof Map)||!c.trustedKeys.size)throw Error('Invalid publication trust');configs.set(c.repositoryID,c);}
 const publisher=recoveryR2Publisher({bucket});
 return {async publish(request){
  if(!request||Object.getPrototypeOf(request)!==Object.prototype||Object.keys(request).sort().join()!==['envelope','intent'].sort().join())throw Error('Invalid recovery publication request');
  const {intent,envelope}=request,c=configs.get(intent?.repositoryID);if(!c)throw Error('Recovery repository not installed');
  const verify=store=>attestedRecovery({store,trustedKeys:c.trustedKeys,policyDigest:c.policyDigest,clock}).verify(intent);
  const report=await verify({get:async()=>envelope});
  const key='recovery/v1/'+intent.repositoryID+'/'+await digest(intent)+'.json';
  await publisher.create(key,envelope);
  await verify({get:async()=>publisher.get(key)});
  return {protocol:'repoctl-recovery-publication-v1',repositoryID:intent.repositoryID,key,reportDigest:report.digest,envelopeDigest:await digest(envelope),expiresAt:envelope.payload.expiresAt,published:true};
 }};
}
