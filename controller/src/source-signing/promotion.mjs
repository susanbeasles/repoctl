import {canonical,digest} from '../ledger.mjs';
import {importPolicy} from '../authority/authorize.mjs';
import {validateIntent} from '../promotion.mjs';

const hash=/^[a-f0-9]{64}$/,sha=/^[a-f0-9]{40}$/;
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join()===keys.slice().sort().join();
const positive=n=>Number.isSafeInteger(n)&&n>0;
const check=(ok,message='Source promotion handoff denied')=>{if(!ok)throw Error(message);};

// Install this evidence capability in the existing authority and its fresh
// checks. It creates no signature, provider token, ledger entry or main write.
export function createSourcePromotion({storage,source,policy,checkpoint,admission,clock=()=>Date.now()}){
 for(const [adapter,methods] of [[storage,['get','transaction']],[source,['verifyPromotion']],[policy,['current']],[checkpoint,['current']],[admission,['inspect','verify']]])check(adapter&&methods.every(name=>typeof adapter[name]==='function'));
 const recordKey=nonce=>'source-promotion:'+nonce;
 async function binding(input){
  check(exact(input,['receiptDigest','nonce','expiresAt'])&&hash.test(input.receiptDigest)&&hash.test(input.nonce)&&positive(input.expiresAt));
  const proof=await source.verifyPromotion({receiptDigest:input.receiptDigest});check(exact(proof,['receipt','candidate']));
  const r=proof.receipt,c=proof.candidate;
  check(r?.schema==='repoctl-source-receipt/v1'&&await digest(r)===input.receiptDigest&&r.hardwareApprovalVerified===true&&positive(r.repositoryID)&&positive(r.sequence));
  check(c?.schema==='repoctl-source-candidate/v1'&&c.verified===true&&c.repository===r.repository&&c.repositoryID===r.repositoryID&&c.sequence===r.sequence&&c.commitSHA===r.finalSignedCommitSHA&&c.treeSHA===r.treeSHA&&c.sourceRef===r.sourceRef&&c.sourceSHA===r.sourceSHA&&c.expectedMainParent===r.baseSHA&&c.shadowRef===r.shadowRef&&c.signerKeyID===r.signerKeyID&&c.artifactIntentDigest===r.artifactIntentDigest&&c.sourceHistoryDigest===r.historyDigest&&canonical(c.sourcePR)===canonical(r.sourcePR));
  check([r.sourceSHA,r.baseSHA,r.finalSignedCommitSHA,r.treeSHA].every(v=>sha.test(v))&&[r.historyDigest,c.policyDigest].every(v=>hash.test(v)));
  const accepted=await importPolicy(await policy.current(r.repositoryID));
  check(accepted.repository===r.repository&&accepted.targetRef==='refs/heads/main'&&accepted.digest===c.policyDigest);
  const anchor=await checkpoint.current({repositoryID:r.repositoryID});
  check(exact(anchor,['repositoryID','startSequence','startDigest','startCommit','endSequence','endDigest','endCommit'])&&anchor.repositoryID===r.repositoryID&&Number.isSafeInteger(anchor.endSequence)&&anchor.endSequence>=0&&anchor.endSequence<Number.MAX_SAFE_INTEGER&&hash.test(anchor.endDigest)&&anchor.endCommit===r.baseSHA);
  // Failed source generations leave permanent gaps. Ledger sequence instead
  // extends the independently verified checkpoint, never the source sequence.
  const intent={repositoryID:r.repositoryID,sequence:anchor.endSequence+1,previousDigest:anchor.endDigest,baseSHA:r.baseSHA,commitSHA:r.finalSignedCommitSHA,sourceSHA:r.sourceSHA,treeSHA:r.treeSHA,policyDigest:accepted.digest,evidenceDigest:'0'.repeat(64),archiveDigests:[r.historyDigest],nonce:input.nonce,expiresAt:input.expiresAt};
  validateIntent(intent,accepted,clock());return {intent,accepted};
 }
 async function retained(record){
  const {intent,accepted}=await binding({receiptDigest:record.receiptDigest,nonce:record.intent.nonce,expiresAt:record.intent.expiresAt});
  intent.evidenceDigest=record.intent.evidenceDigest;
  check(canonical(intent)===canonical(record.intent),'Retained source or ledger generation changed');
  validateIntent(intent,accepted,clock());return intent;
 }
 return Object.freeze({
  async prepare(input){
   input=structuredClone(input);const {intent,accepted}=await binding(input);
   const observed=await admission.inspect(intent);check(exact(observed,['evidenceDigest','report'])&&hash.test(observed.evidenceDigest)&&await digest(observed.report)===observed.evidenceDigest);
   intent.evidenceDigest=observed.evidenceDigest;validateIntent(intent,accepted,clock());
   const record={receiptDigest:input.receiptDigest,intent};await retained(record);
   await storage.transaction(async tx=>{
    const previous=await tx.get(recordKey(input.nonce));check(!previous||canonical(previous)===canonical(record),'Source promotion operation collision');
    validateIntent(intent,accepted,clock());if(!previous)await tx.put(recordKey(input.nonce),record);
   });
   await retained(record);return structuredClone(intent);
  },
  async verify(request){
   check(exact(request,['operationID','repositoryID','intent','owner','validator'])&&hash.test(request.operationID)&&request.intent?.nonce===request.operationID);
   const record=await storage.get(recordKey(request.operationID));check(record&&canonical(record.intent)===canonical(request.intent)&&request.repositoryID===record.intent.repositoryID,'No retained source promotion intent');
   await retained(record);
   // Existing admission verifies independent owner/validator envelopes, all
   // original GitHub/history/archive components and the approved report digest.
   const result=await admission.verify(request);
   check(result?.verified===true&&result.operationID===request.operationID&&result.intentDigest===await digest(record.intent));
   await retained(record);return result;
  }
 });
}
