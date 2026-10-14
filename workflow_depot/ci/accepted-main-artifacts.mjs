import {deploymentEvidence} from '../src/deployment-evidence.mjs';
import {inspectArtifact,digest} from '../src/shared/contract.mjs';
import {packageBundle} from '../capabilities/deploy/package-bundle.mjs';
// Construct only with installed private readers and owned policy. Requests cannot
// supply evidence verifiers, signer enrollment, URLs or authority booleans.
export function acceptedMainArtifacts(services) {
 const evidence=deploymentEvidence(services);
 if(typeof services.artifacts?.read!=='function')throw Error('Retained artifact reader required');
 return {
  async consume(operation) {
   await evidence.verify(operation);
   const bytes=await services.artifacts.read({artifactDigest:operation.artifactDigest});
   const inspected=await inspectArtifact(bytes,5*1024*1024);
   if(inspected.artifactDigest!==operation.artifactDigest||inspected.metadataDigest!==operation.metadataDigest)throw Error('Retained artifact bytes differ');
   // The accepted main may move during archive retrieval. Recheck all retained
   // source/CI/receipt evidence before returning bytes to the central packager.
   await evidence.verify(operation);
   return {bytes,inspected};
  },
  async envelope(operation,{approvalPayload,ownerApproval}) {
   const {bytes}=await this.consume(operation);
   const signingReceipt=await services.signingReceipts.lookupReceipt({receiptDigest:operation.source.signingReceiptDigest});
   const provenance=await services.provenance.lookup({artifactDigest:operation.artifactDigest});
   if(await digest(signingReceipt)!==operation.source.signingReceiptDigest)throw Error('Retained promotion receipt moved');
   const bundle=await packageBundle({artifactBytes:bytes,signingReceipt,approvalPayload,ownerApproval,provenance});
   await evidence.verify(operation);
   // Packaging grants no authority: delivery_control independently verifies the
   // retained owner/App promotion, signatures, current policy and exact bytes.
   return bundle;
  }
 };
}
