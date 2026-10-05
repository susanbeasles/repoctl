const links={
 controller:{BROKER_AUTHORITY:['authority','AuthorizationService'],BROKER_VERIFIER:['observation','BrokerVerificationService'],BROKER_SIGNER:['signer','AppSignerService'],BROKER_RECEIPTS:['receipts','LedgerReceiptService']},
 authority:{ACCEPTED_POLICY:['policy','AcceptedPolicyService'],AUTHORIZATION_EVIDENCE:['evidence','AdmissionEvidenceService'],AUTHORIZATION_RECEIPTS:['receipts','LedgerReceiptService']},
 evidence:{EVIDENCE_POLICY:['policy','AcceptedPolicyService'],EVIDENCE_HISTORY:['checkpoint','CheckpointService'],EVIDENCE_ARCHIVES:['archive','ArchiveEvidenceService']},
 observation:{OBSERVATION_AUTHORITY:['authority','AuthorizationService'],OBSERVATION_BROKER:['controller','BrokerObservationService']},
 receipts:{RECEIPT_AUTHORITY:['authority','AuthorizationService'],RECEIPT_COMPLETION:['observation','CompletionObservationService'],RECEIPT_CHECKPOINT:['checkpoint','CheckpointService']},
 checkpoint:{CHECKPOINT_COMPLETION:['observation','CompletionObservationService']},
 upload:{RECOVERY_PUBLISHER:['archive','RecoveryPublicationService']},
 signer:{APP_ENROLLMENT_APPROVAL:['enrollment','EnrollmentApprovalService']}
};
export const configFiles={controller:'wrangler.jsonc',authority:'wrangler.authority.jsonc',evidence:'wrangler.evidence.jsonc',observation:'wrangler.observation.jsonc',receipts:'wrangler.receipts.jsonc',checkpoint:'wrangler.checkpoint.jsonc',archive:'wrangler.archive-evidence.jsonc',upload:'wrangler.recovery-upload.jsonc',signer:'wrangler.signer.jsonc',policy:'wrangler.policy.jsonc',enrollment:'wrangler.enrollment-approval.jsonc'};
export function deploymentTopology(templates,{prefix,receiptBucket,recoveryBucket}){
 const name=x=>typeof x==='string'&&/^[a-z][a-z0-9-]{2,50}$/.test(x);
 if(!name(prefix)||!name(receiptBucket)||!name(recoveryBucket)||receiptBucket===recoveryBucket)throw Error('Invalid deployment namespace or separate buckets');
 const configurations={};for(const role of Object.keys(configFiles)){
  const c=structuredClone(templates[role]);if(!c||typeof c.main!=='string'||c.services?.length||c.routes?.length||c.route)throw Error('Expected unbound deployment template');
  c.name=prefix+'-'+role;c.workers_dev=false;c.preview_urls=false;c.vars={...c.vars};for(const k of Object.keys(c.vars))if(k.endsWith('_ENABLED'))c.vars[k]='false';
  c.services=Object.entries(links[role]??{}).map(([binding,[target,entrypoint]])=>({binding,service:prefix+'-'+target,entrypoint}));
  if(role==='controller')c.r2_buckets=[{binding:'ARCHIVE',bucket_name:receiptBucket}];
  if(role==='checkpoint')c.r2_buckets=[{binding:'CHECKPOINT_OBJECTS',bucket_name:receiptBucket}];
  if(role==='archive')c.r2_buckets=[{binding:'RECOVERY_REPORTS',bucket_name:recoveryBucket}];
  configurations[role]=c;
 }
 return {protocol:'repoctl-deployment-topology-v1',activated:false,configurations,unresolved:['Hardware provenance/revocation verifier and enrollment trust service','Reviewed policy, workflow, repository and archive inventories','Remote wrapping keys, receipt signer and App enrollment','Bucket retention and independent checkpoint witness','Authenticated operator provisioning and live qualification']};
}
