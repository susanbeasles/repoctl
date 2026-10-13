import {createHash} from 'node:crypto';
import {canonical,digest} from './shared/contract.mjs';
import {verifyApproval} from './owner-approval-verification.mjs';
import {verifyGitSignature} from './git-signature-verification.mjs';
const need=v=>{if(!v)throw Error('Independent signing receipt denied');};
const hash=v=>createHash('sha256').update(v).digest('hex');
const gitID=(type,text)=>createHash('sha1').update(`${type} ${Buffer.byteLength(text)}\0`).update(text).digest('hex');
// Bundle bytes are untrusted artifact data. Enrollment comes only from current,
// reviewed controller configuration, never from this bundle or caller inputs.
export function workflowSigningReceipts({bundle,enrollment,github,verifierSHA256,now=()=>Math.floor(Date.now()/1000),verifyGit=verifyGitSignature}) {
  return {async lookupReceipt({receiptDigest}) {
    const r=bundle.signingReceipt,p=bundle.approvalPayload,envelope=bundle.ownerApproval;
    need(r&&p&&envelope&&await digest(r)===receiptDigest);
    const owner=enrollment?.ownerKeys?.find(k=>k.keyID===envelope.keyID&&k.repositoryID===r.repositoryID);
    need(owner&&owner.revoked===false&&owner.hardwareVerified===true&&/^[a-f0-9]{64}$/.test(owner.proofDigest??'')&&owner.validUntil>now());
    const raw=Buffer.from(owner.publicKeyX963,'base64');need(raw.length===65&&raw[0]===4&&hash(raw)===owner.keyID);
    const key=await crypto.subtle.importKey('raw',raw,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
    const verified=await verifyApproval(envelope,'owner',new Map([[owner.keyID,key]]));
    need(Buffer.from(verified.payload,'base64').toString('utf8')===canonical(p));
    for(const [field,value] of Object.entries({schema:'repoctl-source-approval/v1',repository:r.repository,repositoryID:r.repositoryID,sourceRef:r.sourceRef,targetRef:'refs/heads/main',sourceSHA:r.sourceSHA,expectedMainParent:r.baseSHA,finalSignedCommitSHA:r.finalSignedCommitSHA,treeSHA:r.treeSHA,artifactIntentDigest:r.artifactIntentDigest,signerKeyID:r.signerKeyID,sequence:r.sequence,shadowRef:r.shadowRef,approvalReference:r.ownerApprovalReference})) need(p[field]===value);
    need(canonical(p.sourcePR)===canonical(r.sourcePR)&&p.sourcePR.headSHA===r.sourceSHA);
    const commit=await github.read(r.repository,'/git/commits/'+r.finalSignedCommitSHA);
    const unsigned=commit?.verification?.payload,signature=commit?.verification?.signature;
    need(commit.sha===r.finalSignedCommitSHA&&typeof unsigned==='string'&&hash(unsigned)===p.unsignedCommitDigest&&commit.tree?.sha===r.treeSHA&&commit.parents?.length===1&&commit.parents[0].sha===r.baseSHA);
    const boundary=unsigned.indexOf('\n\n');need(boundary>0&&typeof signature==='string');
    const signedCommit=unsigned.slice(0,boundary)+'\ngpgsig '+signature.trimEnd().replaceAll('\n','\n ')+'\n'+unsigned.slice(boundary+1);
    need(gitID('commit',signedCommit)===r.finalSignedCommitSHA);
    need(await verifyGit({payload:unsigned,signature,keyID:r.signerKeyID,verifierSHA256}));
    need(r.ownerApprovalReference===hash(canonical({repositoryID:r.repositoryID,sequence:r.sequence,finalSignedCommitSHA:r.finalSignedCommitSHA,sourceSHA:r.sourceSHA,unsignedCommitDigest:p.unsignedCommitDigest,artifactIntentDigest:r.artifactIntentDigest})));
    for(const role of ['source','main']) {
      const tag=r.pairedTags?.[role],expectedTarget=role==='source'?r.sourceSHA:r.finalSignedCommitSHA;
      need(tag?.name===`promotion/${r.sequence}/${role}`&&tag.targetSHA===expectedTarget);
      const actualRef=await github.read(r.repository,'/git/ref/tags/'+tag.name);
      need(actualRef?.object?.type==='tag'&&actualRef.object.sha===tag.objectSHA);
      const actual=await github.read(r.repository,'/git/tags/'+tag.objectSHA);
      const payload=p[role+'TagPayload'],signed=actual?.verification?.signature;
      need(actual?.sha===tag.objectSHA&&actual.object?.type==='commit'&&actual.object.sha===expectedTarget&&actual.tag===tag.name&&actual.verification?.payload===payload);
      need(typeof payload==='string'&&typeof signed==='string'&&gitID('tag',payload+signed.trimEnd()+'\n')===tag.objectSHA);
      const message=payload.slice(payload.indexOf('\n\n')+2);
      need(message===canonical({schema:'repoctl-paired-source-tags/v1',repositoryID:r.repositoryID,repository:r.repository,sequence:r.sequence,sourceRef:r.sourceRef,sourceSHA:r.sourceSHA,finalSignedCommitSHA:r.finalSignedCommitSHA,approvalReference:r.ownerApprovalReference,sourceTag:r.pairedTags.source.name,mainTag:r.pairedTags.main.name})+'\n');
      need(await verifyGit({payload,signature:signed,keyID:r.signerKeyID,verifierSHA256}));
    }
    need(owner.validUntil>now());
    return structuredClone(r);
  }};
}
