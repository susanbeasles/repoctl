# Authenticated submission admission

`controller/src/operator/submission.ts` connects independently verified owner
context to an installed repository/job grant and private submission queue.
It does not grant promotion authority, mint provider credentials or run project
code. The existing owner/validator/executor promotion approvals remain required
after exact candidate validation.

Creation accepts only numeric repository ID, generation ID, base/source SHA and
candidate message. It snapshots primitive fields, authorizes the exact intent and
`create` action, then calls the installed private job creator once. Status and
reconciliation accept only repository/generation references, authorize their exact
action, and call their separate private capabilities. A client cannot supply its
owner ID, job URL, credentials, signer, policy grant or promotion target.

The installed grant service must verify the fixed personal owner, enrolled
repository/builder profile, current base and exact submission. The queue must
atomically retain that identity/intent before acknowledging creation, reject
changed duplicate generations, and schedule the isolated candidateSubmission job
with its fixed storage/custody capabilities. Its reconciliation capability must
never resubmit signing or upload. This module does not implement those providers.

Only bound public job states and SHA fields reach output; private queue metadata,
messages, credentials and provider errors are discarded. Publication is explicitly
`published-awaiting-validation`, never a successful promotion. A ten-second
observation deadline and propagated cancellation prevent delayed authorization
from starting a job after timeout. Already-issued queue actions require retained
state inspection; there is no automatic retry or rollback.

Unit checks exercise fixed owner/action/intent grants, queued status projection,
foreign action denial and delayed authorization cancellation with synthetic
providers. HTTP/Worker wiring, native submit dispatch, actual repository grants,
durable queue execution and live integration remain required. No production route
or service binding is enabled by this source increment.

## Durable submission records

`submissionJournal(storage, ownerID, repositoryID)` now retains the exact private
intent and atomically reserves each generation once. A separate compare-and-set
claim permits one worker to leave queued state. Forward transitions retain the
prepared tree/snapshot, retention digest and signed commit before publication;
no phase can rewind. An uncertain record can confirm publication only when those
bindings are present. Failed/uncertain/completed generations remain tombstones.
The journal stores no credential or private key, and transactions perform no
provider, signer or project-code execution. Recorded digests do not establish
their own cryptographic trust: installed retention/signature/generation verifiers
must validate them before state advancement.

`scripts/qualify-submission-local.ts` exercises actual SQLite/workerd concurrent
reservation and execution claims, restart persistence during signing and uncertain
publication, owner/source collision rejection and permanent completed tombstones.
It invokes no signer or provider. The runtime runner includes this qualifier;
durable queue dispatch, isolated job execution and private Worker/HTTP wiring
remain required.

## Private queue dispatch

`submissionQueue` now composes the journal with an installed runner. Creation
retains immutable intent, claims preparing state before calling the runner, and
returns the retained public job state. Matching duplicates never redispatch.
Lost acknowledgments or timeout retain uncertainty without rewinding progress
already written by a running job. Status reads the journal; reconciliation calls
only the runner's non-starting recovery method and then reads retained state.
An unknown or stranded queued job is not automatically started by reconciliation.

The runner receives only fixed owner/repository/generation references and must
load the exact immutable job through its private journal capability. The calling
boundary must independently verify the exact job grant; queue state is neither
authentication nor promotion approval. Runner start acknowledgment proves only
that dispatch was accepted. No caller-selected runner URL or credential exists.

The actual SQLite/workerd fixture now checks eight simultaneous queue creations,
one dispatch, restart duplicates with no redispatch, and lost-ack uncertainty
followed by a separate reconciliation call. Its runner remains synthetic. The
installed isolated runner, stage updates, authenticated Worker/HTTP wiring and
native submit dispatch remain unfinished.

## Isolated execution adapter

`submissionRunner` now obtains a separate atomic journal execution claim after
queue dispatch. The private `started` marker cannot be supplied in admission
intent, cleared or claimed twice. Progress begin requires this claim and exact
retained intent. A crash after claiming requires reconciliation; it never causes
a fresh signing attempt. Actual SQLite/workerd checks race eight execution
claims and preserve the claimed state across restart.

The installed job factory selects fixed isolated storage/custody adapters and
must configure the supplied submissionProgress. Runner execution uses only
retained source/base/message, verifies publication against retained signed
metadata, and returns an explicit public projection. Recovery opens only an
already-started job with complete publication metadata and calls reconcile,
without preparation, signing or upload. Factory observation has a ten-second
deadline; individual job capabilities retain their existing bounds.

The composed actual-Git fixture now runs through this adapter and verifies one
signature/upload despite duplicate delivery and a lost response. Fixture
retention, provider coordination and the local installed job factory remain
synthetic. A commissioned isolated host, background dispatch transport, private
Worker/HTTP wiring and native CLI dispatch are still required. This source does
not create a public runner endpoint or activate production.

## Private authenticated HTTP entrypoint

`SubmissionOperatorService` wires exact POST create/status/reconcile routes under
`/v1/operator/submission/`. `OPERATOR_SUBMISSION_ENABLED` is false in the checked-in
template. Fixed owner configuration, Access identity/session verification,
`OPERATOR_JOB_GRANTS` and `OPERATOR_JOBS` bindings are mandatory. The public operator
Worker still returns404; the existing public relay exposes enrollment only. A
protected submission relay and native submit client remain required.

Identity is verified before reading the bounded32KiB body, then exact primitive
submission validation and job grants precede private queue calls. Responses use
the service's bound public projection and no-store headers. Ten-second observation
and propagated cancellation prevent a late grant from beginning queue creation.
Private service calls cancel stalled response readers. A request already issued
requires retained-state reconciliation, without automatic retry.

The actual workerd qualifier exercises this named service with real RSA-signed
Access JWTs and rejects foreign/revoked sessions before any job grant. Successful
creation returns sanitized queued state. JWKS, sessions, job grants and queue
providers are synthetic; this does not qualify live admission or provider execution.
