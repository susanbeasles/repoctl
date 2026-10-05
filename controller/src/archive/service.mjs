import {attestedRecovery} from './attested-recovery.mjs';
export function archiveEvidenceService({bucket,configurations,clock}){
 if(typeof bucket?.get!=='function'||!Array.isArray(configurations)||!configurations.length||configurations.length>100)throw Error('Invalid archive service configuration');
 const configs=new Map();
 for(const c of configurations){if(!Number.isSafeInteger(c.repositoryID)||c.repositoryID<1||configs.has(c.repositoryID)||!/^[a-f0-9]{64}$/.test(c.policyDigest??'')||!(c.trustedKeys instanceof Map))throw Error('Invalid archive repository configuration');configs.set(c.repositoryID,c);}
 return {async verify(intent){
  const c=configs.get(intent?.repositoryID);if(!c)throw Error('Archive repository not installed');
  return attestedRecovery({trustedKeys:c.trustedKeys,policyDigest:c.policyDigest,clock,store:{async get(id){
   const object=await bucket.get('recovery/v1/'+c.repositoryID+'/'+id+'.json');
   if(!object||!Number.isSafeInteger(object.size)||object.size<1||object.size>4*1024*1024)throw Error('Recovery attestation unavailable or oversized');
   const data=await object.arrayBuffer();if(data.byteLength!==object.size)throw Error('Recovery object size differs');
   return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data));
  }}}).verify(intent);
 }};
}
