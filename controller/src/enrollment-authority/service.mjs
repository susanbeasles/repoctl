import {derToRaw} from '../promotion.mjs';
import {digest} from '../ledger.mjs';
const hash=/^[a-f0-9]{64}$/,domain='repoctl-app-enrollment-owner-v1\n',enc=new TextEncoder();
const fields=(v,n)=>v&&Object.keys(v).sort().join()===n.sort().join();
const decode=v=>Uint8Array.from(atob(v),c=>c.charCodeAt(0));
export function enrollmentApprovalService({storage,trust,hardware,clock=()=>Math.floor(Date.now()/1000)}){
 async function verify(envelope){
  if(!fields(envelope,['protocol','keyID','encoding','payload','signature'])||envelope.protocol!==domain.trim()||!hash.test(envelope.keyID??'')||!['der','p1363'].includes(envelope.encoding)||typeof envelope.payload!=='string'||envelope.payload.length>4096)throw Error('Invalid enrollment approval');
  const accepted=await trust.current(envelope.keyID);
  if(!accepted||accepted.keyID!==envelope.keyID||accepted.revoked!==false||!Number.isSafeInteger(accepted.ownerID)||accepted.ownerID<=0)throw Error('Untrusted enrollment approver');
  const raw=decode(accepted.publicKeyX963),fingerprint=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),b=>b.toString(16).padStart(2,'0')).join('');
  if(fingerprint!==envelope.keyID)throw Error('Enrollment key fingerprint mismatch');
  const key=await crypto.subtle.importKey('raw',raw,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const payload=decode(envelope.payload),prefix=enc.encode(domain),message=new Uint8Array(prefix.length+payload.length);message.set(prefix);message.set(payload,prefix.length);
  if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,envelope.encoding==='der'?derToRaw(envelope.signature):decode(envelope.signature),message))throw Error('Invalid enrollment signature');
  const intent=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(payload));
  if(!fields(intent,['operationID','ownerID','role','manifestDigest','expiresAt'])||!hash.test(intent.operationID??'')||!hash.test(intent.manifestDigest??'')||intent.ownerID!==accepted.ownerID||!['writer','validator','builder','release'].includes(intent.role)||!Number.isSafeInteger(intent.expiresAt))throw Error('Invalid enrollment intent');
  const proof=await hardware.verify({keyID:envelope.keyID,ownerID:intent.ownerID});
  if(proof?.keyID!==envelope.keyID||proof.hardwareVerified!==true||proof.revoked!==false||!hash.test(proof.proofDigest??'')||!Number.isSafeInteger(proof.validUntil)||proof.validUntil<=clock())throw Error('Enrollment hardware trust unavailable');
  return intent;
 }
 return {
  async admit(envelope){
   const intent=await verify(envelope),now=clock();if(intent.expiresAt<=now||intent.expiresAt>now+300)throw Error('Enrollment approval expired or excessive');
   const reference=await digest(envelope);
   await storage.transaction(async tx=>{const k=`enrollment-approval:${intent.operationID}`,r=await tx.get(k);if(r){if(r.reference!==reference)throw Error('Enrollment approval collision');return;}await tx.put(k,{reference,envelope});});
   return {operationID:intent.operationID,approvalReference:reference,expiresAt:intent.expiresAt};
  },
  async authorize(input){
   if(!fields(input,['operationID','approvalReference','action'])||!hash.test(input.operationID??'')||!hash.test(input.approvalReference??'')||!['create','exchange','reconcile','status'].includes(input.action))throw Error('Invalid enrollment authorization');
   const r=await storage.get(`enrollment-approval:${input.operationID}`);if(!r||r.reference!==input.approvalReference)throw Error('Unknown enrollment approval');
   const intent=await verify(r.envelope);
   // Expired approval grants no new conversion or activation. Recovery requires
   // a separately designed renewal protocol; never silently extend its lifetime.
   if(intent.expiresAt<=clock())throw Error('Enrollment approval expired');
   return {accepted:true,operationID:intent.operationID,approvalReference:r.reference,session:{ownerID:intent.ownerID,role:intent.role,manifestDigest:intent.manifestDigest,expiresAt:intent.expiresAt*1000}};
  }
 };
}
