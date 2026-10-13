# Central deployment implementation

Applications dispatch `delivery_control/.github/workflows/deploy.yml` with exact
repository, immutable ID, signed current-main revision, source run and target.
Only its reusable `deployment-job.yml` uses the protected `deploy` environment.
The user-selected future repository name is `deploy`; current references remain
until coordinated cutover. No Cloudflare authorizer or deployer Worker is used.

The production entry point is `src/workflow-runtime.mjs`. It revalidates admission,
loads one exact GitHub artifact, verifies source/owner/signing/CI/provenance proofs,
authorizes and claims a target in the persistent journal, loads the authorized
1Password Environment, then invokes the existing provider execution module.
Upload and activation each require fresh evidence and unchanged source/controller
main. It verifies the resulting version/deployment and records a receipt and next
baseline. Candidate code is data; the privileged job never executes app scripts.

This path is exercised end to end with real synthetic P-256 owner, SSH Git and
RS256 OIDC signatures. Only external transport, Environment retrieval and provider
effects are mocked. It is no longer an intentionally failing placeholder. The
checked-in configuration remains disabled because actual commissioning inputs
have not been supplied or approved. Passing source tests is not live deployment.

## Durable journal semantics

`src/github-journal.mjs` stores nonsecret operation records in a single
`deployment-state` branch in the controller repository, whose immutable ID is
1405415291. The branch contains only `journal.json`. The adapter requires current
effective deletion and non-fast-forward protection rules and an approved genesis
commit anchor; missing state never initializes itself or resets replay history.

Each transaction reads a snapshot, writes a new data blob/tree and a commit with
exactly that snapshot as parent, then updates the ref with `force:false` and reads
it back. Two writers with the same parent cannot both fast-forward. A conflict or
ambiguous write fails; it is never blindly retried. All target/nonce/JTI records
share the same journal, so separate processes share locks. Journals are bounded
at 8 MiB and fail closed at that limit; no unsafe pruning is implemented.

Authorization reserves an operation and then claims its target before requesting
Cloudflare credentials. Upload/activation intent is persisted before each effect.
An uncertain provider outcome retains its target lock across runs. The workflow
uses a common concurrency group without cancellation of a running deployment;
GitHub concurrency is not treated as a FIFO queue or a durable lock. A completed
exact run cannot replay. A later dispatch/run gets a new operation but still must
pass source/baseline checks. Failed next-baseline persistence is reported as a
failure; the provider refuses a stale baseline on the next attempt.

GitHub branch administration and repository writers remain trusted control-plane
authority. Someone who bypasses protection and rolls back or forges journal
history can violate that trust. The adapter does not claim a GitHub ref is an
external tamper-proof ledger. It never updates main, source branches, workflows,
rules, or grants. Its built-in GitHub token needs contents-write in the controller
only; source reads use the existing GitHub App with contents/actions read.

See [GitHub non-force ref updates](https://docs.github.com/en/rest/git/refs#update-a-reference)
and [Actions concurrency](https://docs.github.com/en/actions/concepts/workflows-and-actions/concurrency).

## Independent evidence and artifacts

The reusable authorizer remains in `workflow_depot/src/deployment-authority.mjs`.
Existing `deployment-evidence.mjs` checks current signed main, paired tags,
accepted candidate CI (not a main rebuild), required successful jobs and matching
build provenance. `workflow-receipts.mjs` independently verifies the existing
owner approval format against reviewed current hardware enrollment, exact signed
approval bytes, actual SSH Git signatures, immutable Git object IDs and paired
tag cross-links. Neither a caller's `verified:true` nor GitHub's generic verified
badge substitutes for the enrolled signer. Current controller-main checks make
enrollment/policy edits revoke an in-flight workflow at the next evidence check.

The read-only owner approval and SSH verification primitives were extracted from
signing_control fae9e4889c906365cbf4b22c998306d3fb458b31. Its isolated producer and
private signing adapters are not imported into the privileged job. No signing key
or hardware operation is needed for deployment verification.

`capabilities/deploy/package-bundle.mjs` packages existing accepted outputs; it
confers no authority. The artifact must be named
`deployment-<exact source SHA>-<registry target>` and contain exactly one file,
`deployment-bundle.json`, with:

- `schema`: `deployment-workflow-bundle/v1`
- `artifactBase64`: exact existing `workflow-depot-worker-artifact/v1` bytes
- `signingReceipt`, `approvalPayload`, `ownerApproval`: accepted source proofs
- `provenance`: existing `workflow-depot-build-provenance/v1` record

Publish it from the accepted candidate CI run using a pinned upload-artifact step.
The consumer requires one unexpired matching artifact, exact producer run/repo/SHA
and archive SHA-256. It follows only the GitHub API's signed storage redirect,
without forwarding any authorization header. ZIP parsing permits one bounded
regular data file, never archive extraction, hooks or executable input. Missing
or ambiguous evidence fails before Environment retrieval.

## Commissioning inputs, not invented defaults

Review and supply `deployment/workflow-config.json`:

- `enabled`, account ID, accepted actor IDs and approved public hardware enrollment.
- `journalAnchorSHA`: real genesis commit of an initialized, protected state branch.
- `verifierSHA256`: reviewed `/usr/bin/ssh-keygen` digest for the chosen runner.
- Each target's existing deployment-policy schema: source identity, Worker,
  metadata digest, exact ingress inventory, CI/workflow and signer pins.
- `baselineDeploymentID`: approved existing deployment; subsequent baselines come
  from successfully verified journal receipts.

Set nonsecret `WORKFLOW_DEPOT_SHA` and `OP_ENVIRONMENT_ID` in the controller's
protected deployment configuration. Retain the existing scoped
`OP_SERVICE_ACCOUNT_TOKEN`; the pinned 1Password SDK loads the Environment only
after authorization and the target claim. Its Cloudflare account must match.
Caller dispatch still needs the existing `RELEASE_DISPATCH_TOKEN` capability.
Git transport credentials cannot replace an Actions/API dispatch capability.
Nothing in this implementation creates a token, widens a grant or uses a browser.

The provider adapter updates one existing Worker from a reviewed immutable
artifact. It preserves existing ingress, checks complete zone inventory and
refuses secret-binding drift. It does not create Workers, Durable Object
namespaces, containers, routes, resource bindings, database migrations or Access
policies. Those explicit lifecycle operations remain separately reviewed tasks.
The signer container and uncommissioned templates cannot be declared deployed
through this narrower adapter. Multi-Worker atomic rollout is not implemented.

## Ownership, Terraform and publication

Dedicated application repositories own their applications. Shared login's release
cannot overwrite Caretaker or Backup Control. The registry includes deployment
purpose, exact source lineage and limitations. ProsRUs code is on preserved
revision e185f8b61d331417c20576f1517f338ddc1ab8df, not main. Secrets Provisioner
extraction and its three-stage qualification are separate work.

Latest naming: personal-control → `auth`; delivery_control → `deploy`;
backup-control remains `backup-control`. Other prepared mappings are in
`deployment/name-migration.json`. Generic GitHub App provisioning reuse is queued;
backup-setup state/credential custody is not deleted or moved by these changes.

The requested private `terraform` repository will own Zero Trust/networking IaC
and the exact nonexecuting token reference. Terraform must be the sole writer of
its Access, enrollment and network resources; artifact deployment never reconciles
Access or runs Terraform. A future central infra job must separately validate a
reviewed plan/state binding and use its approved backend; no automatic apply is
installed. Build artifacts and unsupported provider lifecycle operations require
explicit steps, not competing ownership of the same resource.

No workflow, journal write, credential read, push, merge, rename, deletion,
provisioning or deployment was executed in this session. Before publication,
review main/feature workflow side effects, reconcile repoctl component exports,
publish capabilities and select their immutable revision, then coordinate the
controller/callers and name cutover. Do not point at an invented future commit.
