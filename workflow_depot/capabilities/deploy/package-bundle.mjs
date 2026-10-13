import {readFile,writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {inspectArtifact} from '../../src/shared/contract.mjs';
export async function packageBundle({artifactBytes,signingReceipt,approvalPayload,ownerApproval,provenance}) {
  const inspected=await inspectArtifact(artifactBytes,5*1024*1024);
  if(provenance?.schema!=='workflow-depot-build-provenance/v1'||provenance.artifactDigest!==inspected.artifactDigest||provenance.metadataDigest!==inspected.metadataDigest||provenance.sourceSHA!==signingReceipt?.finalSignedCommitSHA||signingReceipt?.repository!==provenance.repository||approvalPayload?.finalSignedCommitSHA!==provenance.sourceSHA||typeof ownerApproval?.signature!=='string') throw Error('Deployment bundle inputs do not match');
  // Packaging confers no authority. The controller independently verifies owner,
  // Git and OIDC signatures, current enrollment, CI, provenance and exact bytes.
  const bundle={schema:'deployment-workflow-bundle/v1',artifactBase64:Buffer.from(artifactBytes).toString('base64'),signingReceipt,approvalPayload,ownerApproval,provenance};
  if(Buffer.byteLength(JSON.stringify(bundle))>7*1024*1024) throw Error('Deployment bundle too large');
  return bundle;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try {
    const [artifact,receipt,approval,owner,provenance,output]=process.argv.slice(2);
    if(!output||process.argv.length!==8)throw Error('Expected artifact, signing receipt, approval payload, owner approval, provenance and output paths');
    const json=async path=>JSON.parse(await readFile(path,'utf8'));
    const bundle=await packageBundle({artifactBytes:await readFile(artifact),signingReceipt:await json(receipt),approvalPayload:await json(approval),ownerApproval:await json(owner),provenance:await json(provenance)});
    await writeFile(output,JSON.stringify(bundle),{flag:'wx',mode:0o600});
  }catch{console.error('Deployment bundle packaging failed; no credentials are accepted');process.exitCode=1;}
}
