# Authenticated recovery upload

The recovery upload Worker exposes only POST `/v1/archive/recovery/upload`.
It is disabled by default. Bind `RECOVERY_PUBLISHER` to the archive evidence
Worker's named `RecoveryPublicationService`, never to a writer or broker.

Install `RECOVERY_UPLOAD_TRUST_JSON` containing audiencePrefix, repository,
repositoryID, ownerID, ref, workflowRef, workflowSHA, jobWorkflowRef,
jobWorkflowSHA, actorIDs, eventNames, and targetRepositoryIDs. Pin both workflow
SHAs to reviewed commits; use a dedicated GitHub-hosted recovery workflow.
The target list contains numeric repository IDs. Enable only after the private
publisher's policy and recovery verification keys are installed.

Request body: `{publication:{intent,envelope},runID:60,runAttempt:1}`.
Request GitHub OIDC with audience `audiencePrefix:SHA256(canonical(publication))`
and send it as a Bearer header. Canonical encoding is repoctl ledger encoding;
JSON.stringify alone is not an interchangeable canonical encoder.
GitHub's signed token must match the installed repository, owner, actor, event,
ref, caller workflow, reusable workflow, both code SHAs, run and attempt.
No caller-controlled identity provider URL is accepted.

The gateway forwards only the publication to the private verifier. The verifier
checks the report signature, policy, expiry and conditional R2 readback. Neither
OIDC nor an allowed workflow alone authenticates the report's signing key.
Exact retries are allowed: this endpoint issues no lease or credential, and the
publisher rejects replacement. The job must still guard its signing key and
actually restore and verify the archive before producing the report.

This change does not deploy a live endpoint, supply a FlareKit process adapter,
provision retention, or solve renewal of an expired report under its fixed key.
