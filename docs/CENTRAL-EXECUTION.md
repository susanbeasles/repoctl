# Central execution handoff

The source trees `delivery_control/` and `workflow_depot/` are independent repository
roots. Their `.github/workflows` files are inactive while nested in repoctl. Copy
those roots into repositories of the same names under the selected personal owner;
do not install the privileged executor in application repositories.

## Dispatch receiver

`delivery_control/.github/workflows/promote.yml` accepts only the controller-retained
operation ID. It calls the local trusted executor workflow. No SHA, ref, repository,
URL, shell or credential is accepted as dispatch input. The caller passes only
read Contents and OIDC issuance permissions. Global concurrency prevents competing
central dispatch jobs; controller leases remain the authoritative per-repository
serialization and authorization mechanism.

The executor checks out ONLY delivery_control at the workflow run's SHA. Its
built-ins-only script requests GitHub OIDC with an operation-specific audience,
receives a no-store controller lease, checks numeric target identity and the signed
single-parent candidate/tree, then makes one non-forced ref update. It reads the
ref back, revokes the installation token and reports a sanitized outcome. A lost
write response produces uncertain state, never an automatic second write.

The source receiver calls a local reusable executor, so enroll the ACTUAL
job_workflow_ref reported by GitHub plus its immutable job_workflow_sha. Do not
assume GitHub will report an @SHA workflow reference when the caller uses a local
workflow path. Register both caller and reusable workflow revisions before issuing
authority. Caller revision drift must fail OIDC verification until explicitly
approved. Native GitHub OIDC behavior needs a live qualification run.

Configure public repository variables REPOCTL_CONTROLLER_ORIGIN and
REPOCTL_OIDC_AUDIENCE_PREFIX. There are no promotion credentials in repo variables
or GitHub Secrets. Changing the controller origin cannot create valid authority
at the real broker; origin changes are nevertheless governed and monitored.

## Shared validation

workflow_depot initially contains `validate-controller.yml`, a read-only exact-SHA
controller test workflow. A consumer uses its full published commit SHA:

```yaml
permissions: {}
jobs:
  validate:
    permissions:
      contents: read
    uses: OWNER/workflow_depot/.github/workflows/validate-controller.yml@FULL_COMMIT_SHA
    with:
      candidate_sha: EXACT_CANDIDATE_SHA
```

This initial validation workflow is not the full SAST/SCA/DAST/artifact profile.
It emits no privileged authority. Required scanning/evidence and candidate
lifecycle remain separate implementation work. A reusable workflow executes in
its caller context; only delivery_control is accepted as a privileged executor.

## HTTP handoff

The new executionRequest handler implements POST /v1/execution/lease and
POST /v1/execution/complete with bounded bodies, strict input fields, no-store
responses and sanitized errors. It is NOT wired into the public receipt Worker.
Connecting it requires the production service adapters below. No route is enabled
with test adapters or unconditional approval.

- serialize: durable per-operation/per-repository serialization, not a Promise
  callback without persistent leases.
- operations: retained authorizations and atomic operation/JTI reservations;
  issuance state survives restart. Unknown issuance blocks retries.
- executionIntent: verified exact retained intent, not request-selected data;
  authorization verifier must bind these same repository/ref/SHA/tree values.
- complete: verify fresh executor OIDC identity against the issued lease, then
  independently read GitHub main, append ledger/receipt and resolve the journal.
  Never accept the submitted outcome string as evidence that a write succeeded.
- credential adapter: verified remote App enrollment and isolated JWT signer.
- accepted policy, hardware enrollment, archive and evidence: real verified
  services from the governance contract, not preview/software fallbacks.

Failed token revocation is an incident. The completion receipt must NOT declare
credentials revoked merely because the executor reported updated main; verify
revocation independently where possible and retain uncertain status otherwise.
An unacknowledged response can strand issued authority, so broker issuance journals
and revocation/reconciliation jobs remain required for production.

The executor does not append the ledger itself or sign receipts: those remain
independent controller responsibilities. No source branch is deleted and no
release/tag is published by this increment.

The supplied reconcileExecution implementation authenticates the executor against
its retained run/attempt, reads protected main independently and finalizes only
when it equals the approved candidate. An unchanged base requires reconciliation;
a third SHA marks the operation degraded. Signed receipt finalization is idempotent
and completion verification is a required service, not an expired-approval bypass.

Central repositories contain built-ins-only Node scripts, so no npm install or
application dependency restore occurs in the privileged executor.
