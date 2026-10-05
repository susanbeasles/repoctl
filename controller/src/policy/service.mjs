import {digest} from '../ledger.mjs';
import {importPolicy} from '../authority/authorize.mjs';
import {derToRaw} from '../promotion.mjs';
const hash=/^[a-f0-9]{64}$/;
const fields=(v,n)=>v&&Object.keys(v).sort().join()===n.sort().join();
const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function signature(e,role,keys){
 const protocol=`repoctl-policy-${role}-v1`;
 if(!fields(e,['protocol','keyID','encoding','payload','signature'])||e.protocol!==protocol||!hash.test(e.keyID??'')||!['der','p1363'].includes(e.encoding)||typeof e.payload!=='string'||e.payload.length>32000||typeof e.signature!=='string'||e.signature.length>256)throw Error('Invalid policy approval');
 const entry=keys.find(k=>k.keyID===e.keyID);if(!entry)throw Error('Untrusted policy approver');
 const raw=decode(entry.publicKeyX963),fingerprint=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),b=>b.toString(16).padStart(2,'0')).join('');
 if(fingerprint!==e.keyID)throw Error('Policy signer fingerprint mismatch');
 const key=await crypto.subtle.importKey('raw',raw,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 const bytes=decode(e.payload),prefix=new TextEncoder().encode(protocol+'\n'),message=new Uint8Array(prefix.length+bytes.length);message.set(prefix);message.set(bytes,prefix.length);
 if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,e.encoding==='der'?derToRaw(e.signature):decode(e.signature),message))throw Error('Invalid policy signature');
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
export function acceptedPolicyService({storage,bootstrap,hardware,clock=()=>Math.floor(Date.now()/1000)}){
 if(!fields(bootstrap,['repositoryID','repository','ownerKeys','validatorKeys'])||!Number.isSafeInteger(bootstrap.repositoryID)||bootstrap.repositoryID<=0||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(bootstrap.repository)||!['ownerKeys','validatorKeys'].every(k=>Array.isArray(bootstrap[k])&&bootstrap[k].length>0&&bootstrap[k].length<=10))throw Error('Invalid policy bootstrap');
 const key=`accepted-policy:${bootstrap.repositoryID}`;
 return {
  async admit(bundle){
   if(!fields(bundle,['owner','validator'])||bundle.owner?.payload!==bundle.validator?.payload||bundle.owner?.keyID===bundle.validator?.keyID)throw Error('Independent exact-byte approvals required');
   const current=await storage.get(key);if(current)await this.current({repositoryID:bootstrap.repositoryID});const roots=current?.policy??bootstrap;
   const body=await signature(bundle.owner,'owner',roots.ownerKeys);await signature(bundle.validator,'validator',roots.validatorKeys);
   if(!fields(body,['policy','previousDigest','expiresAt'])||!hash.test(body.previousDigest??'')||!Number.isSafeInteger(body.expiresAt)||body.expiresAt<=clock()||body.expiresAt>clock()+300)throw Error('Invalid policy admission intent');
   await importPolicy(body.policy);
   if(body.policy.revision>1000)throw Error('Policy history qualification limit');
   if(body.policy.repositoryID!==bootstrap.repositoryID||body.policy.repository!==bootstrap.repository)throw Error('Policy repository differs');
   const proof=await hardware.verify({repositoryID:bootstrap.repositoryID,keyID:bundle.owner.keyID});
   if(proof?.keyID!==bundle.owner.keyID||proof.hardwareVerified!==true||proof.revoked!==false||!hash.test(proof.proofDigest??'')||!Number.isSafeInteger(proof.validUntil)||proof.validUntil<=clock())throw Error('Hardware policy approval unavailable');
   const admissionDigest=await digest(bundle);
   await storage.transaction(async tx=>{
    const actual=await tx.get(key);
    if(actual?.admissionDigest===admissionDigest)return;
    if((actual?.admissionDigest??'0'.repeat(64))!==body.previousDigest||body.policy.revision!==(actual?.policy.revision??0)+1)throw Error('Policy revision or parent changed');
    const revision=`accepted-policy-revision:${bootstrap.repositoryID}:${body.policy.revision}`;
    if(await tx.get(revision))throw Error('Policy revision already retained');
    const record={policy:body.policy,admissionDigest,previousDigest:body.previousDigest,bundle,hardwareProofDigest:proof.proofDigest};
    await tx.put(revision,record);await tx.put(key,record);
   });
   return {repositoryID:bootstrap.repositoryID,revision:body.policy.revision,admissionDigest};
  },
  async current(input){
   if(!fields(input,['repositoryID'])||input.repositoryID!==bootstrap.repositoryID)throw Error('Invalid policy repository');
   const r=await storage.get(key);if(!r)throw Error('No accepted policy');
   if(!Number.isSafeInteger(r.policy?.revision)||r.policy.revision<1||r.policy.revision>1000)throw Error('Invalid retained revision');
   let roots=bootstrap,previousDigest='0'.repeat(64),last;
   for(let revision=1;revision<=r.policy.revision;revision++){
    const entry=await storage.get(`accepted-policy-revision:${bootstrap.repositoryID}:${revision}`);
    if(!entry||entry.previousDigest!==previousDigest||entry.admissionDigest!==await digest(entry.bundle)||entry.bundle.owner?.payload!==entry.bundle.validator?.payload||entry.bundle.owner?.keyID===entry.bundle.validator?.keyID)throw Error('Policy history changed');
    const body=await signature(entry.bundle.owner,'owner',roots.ownerKeys);await signature(entry.bundle.validator,'validator',roots.validatorKeys);
    if(!fields(body,['policy','previousDigest','expiresAt'])||body.previousDigest!==previousDigest||body.policy.revision!==revision||body.policy.repositoryID!==bootstrap.repositoryID||body.policy.repository!==bootstrap.repository||await digest(body.policy)!==await digest(entry.policy))throw Error('Policy history identity changed');
    await importPolicy(entry.policy);roots=entry.policy;previousDigest=entry.admissionDigest;last=entry;
   }
   if(await digest(last)!==await digest(r))throw Error('Current policy pointer differs from retained history');
   return r.policy;
  }
 };
}
