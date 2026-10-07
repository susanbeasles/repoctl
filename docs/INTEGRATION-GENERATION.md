# Fresh integration generation publication

`controller/src/candidate/generation.mjs` publishes an already uploaded signed
candidate to `refs/heads/int/<generationID>`. Installed configuration fixes the
repository ID/name, protected base branch, private credential capability,
independent designated-candidate/immutable-namespace verifiers and durable
operation journal. Requests
contain exactly generationID (64 hex), baseSHA, commitSHA and treeSHA. No caller
URL, credential, protected target, ref update/delete or force option is accepted.
The publisher copies and validates primitive string fields before awaiting any
capability, so caller changes cannot alter the reserved or published operation.

The candidate's objects must already exist on GitHub through an authenticated
trusted Git job. This module does not rebuild an unsigned REST commit, handle
project checkout/code, or upload objects. It checks GitHub's valid signature,
exact tree and sole parent, current protected tip and numeric repository identity.
A mandatory installed verifyCandidate(binding, {signal}) verifies the designated
candidate identity independently of GitHub’s general valid-signature flag.
Installed verifyNamespace must independently confirm the exact ref and repository
under the approved frozen namespace and effective protections. A local boolean or
project configuration cannot supply that capability.

The installed journal implements atomic durable reserve(binding), read(id), and
compare-and-set transition(id, expectedPhase, nextPhase). Binding contains
repositoryID/ref/generationID/baseSHA/commitSHA/treeSHA. Reserve returns true only
for the one new reservation. The creating phase is durably retained before POST.
New reservations reject even matching preexisting refs. An interrupted or lost
response can reconcile only a matching ref with matching retained provenance;
an absent/moved ref cannot trigger another POST. No existing ref is adopted,
updated or deleted. Final identity/base/namespace/ref/journal readback precedes
retained confirmation and the publication report.

Native fetch responses are bounded to 64KiB. Credential acquisition, network/body
reads and namespace verification have at most ten-second deadlines/abort signals.
Exceptions from credential/network/verifier capabilities suppress provider text.
Abort cannot prove a provider mutation stopped; uncertain phase remains. The
credential provider must return a scoped, leased builder credential for this one
job, handle revocation/cleanup in its own finally path, and never send it to CLI,
project code, receipts or logs. The token is used only in fixed GitHub requests.
This module has no App enrollment, lease issuance or permission-changing role.

Tests cover create/readback, exact duplicate reconciliation, lost response with
and without an observed ref, collisions, changed confirmed refs, invalid signature,
foreign identity, advanced base, mutable namespace, credential stalls and secret
exception suppression. Their journal/provider/namespace adapters are synthetic;
they do not establish durable remote coordination or live immutable enforcement.

The private `generationJournal(storage, repositoryID)` adapter now implements
atomic reservation/CAS using Durable Object storage transactions. It validates
exact bindings and allowed forward transitions, rejects changed or corrupt
records, and retains confirmed IDs permanently. It exposes no deletion, credential
storage or provider I/O. `qualify-generation-local.mjs` exercises actual SQLite
workerd concurrent reservation, restart uncertainty/confirmation and immutable
collision bindings; the main runtime runner includes this qualification.

Still required: remote job-to-journal wiring and namespace verifier, approved frozen
rules/actor behavior, enrolled remote builder credential/custody, authenticated Git
object upload, workflow validation and authenticated owner submit transport. Live
positive/adversarial disposable GitHub qualification remains required. A published
integration ref is not evidence approval or permission to promote.

The isolated native `signedCandidateVerifier` can supply the candidate capability
from an installed canonical object store and pinned public SSH key. It verifies
exact parent/tree, enforces SSH signature format, runs native key-pinned Git
verification and reads bytes back. It never signs, creates refs or reads private
keys. Actual Git/SSH tests reject another key and foreign/mismatched bindings.
Hardware-origin, enrolled role/revocation and remote job wiring remain separate
production requirements; public-key verification does not prove those properties.

## Signed-object transport constraint

The REST publisher above is usable only when the exact signed object is already
present remotely. It is not an end-to-end submission transport. GitHub's current
[create-commit API](https://docs.github.com/en/rest/git/commits?apiVersion=2026-03-10)
documents its signature parameter as detached PGP. Do not reconstruct the existing
SSH-signed candidate through that API, substitute another signing identity, or
claim that unsigned commit creation preserves its identity.

The native Git upload and initial integration-ref creation must share one
publication claim in the durable generation journal. A separate upload push that
creates the final ref followed by this REST publisher will fail the existing
collision rule; silently adopting that ref would weaken the protocol. The next
transport must reserve the exact candidate/ref binding, verify current personal
repository/base/designated signer/immutable namespace, claim creating once,
transfer the exact native objects with an expected-absent ref transaction, and
perform independent exact-SHA and signer readback before confirmation. Lost
responses remain uncertain and reconciliation performs reads only.

A normal push is insufficient to enforce expected absence: an actual local native
Git probe created a generation ref and then successfully fast-forwarded that same
ref with a second ordinary push. Production enforcement therefore needs a
verified create-only server transaction and immutable namespace restrictions;
preflight absence alone has a race. No force push, ref replacement, unsigned
reconstruction, temporary public upload branch or broad credential grant is
introduced as a workaround. Production native transport remains unimplemented.
Probe receipt: `/private/tmp/repoctl-generation-upload-probe.json`; temporary
fixture repositories were removed and no personal provider resources were used.

## Native create-only wire implementation

`controller/src/candidate/wire.ts` now encodes exactly one receive-pack creation
command with a zero old object ID, the validated candidate SHA and fixed
`refs/heads/int/<generationID>` ref, requesting only report-status. It copies the
supplied pack bytes into the request; it cannot encode ref updates, deletion,
protected branches or force. Pack bounds/header checks are structural; the native
server validates pack/object integrity. The parser requires a complete bounded
report for exactly that ref and rejects malformed/truncated/extra responses.

Actual native receive-pack tests prove fresh creation transfers exact commit
bytes, existing-ref fast-forward and identical duplicate creation are rejected,
and only the intended ref remains. Fixture commits are synthetic unsigned
objects: this tests transport semantics, not enrolled hardware signing. Existing
separate native signer tests cover SSH identity. A positive wire response is an
acknowledgement, not independent readback or completed governance.

This private job codec is not yet network transport. The installed coordinator
must discover required server capabilities, authenticate the exact repository,
verify designated candidate/current base/immutable namespace, hold the single
journal creating claim, send once with bounded credential cleanup, then verify
independent remote readback before confirming. It must retain uncertain outcomes
without retrying creation. No callable public route or provider token is added.

## Journaled native publication adapter

The installed optional `publication.create(binding, {signal})` capability now
shares the publisher's durable claim. The publisher verifies repository/base,
designated candidate and immutable namespace before reservation and again before
claiming creating. Native publication may transfer objects not yet remote; the
REST-only path still requires existing remote objects. Both paths independently
read GitHub's exact candidate parent/tree/signature and generation ref before
confirming. No REST creation occurs when native publication is installed.

`generationUpload` supplies the typed private adapter over installed `store.pack`
and `transport.send` capabilities. Fixed repository ID and exact ref/SHA binding
are checked before object access; signal checks prevent sending after a cancelled
pack request. Errors suppress capability details and leave outcome reconciliation
to the journal. The coordinator supplies the maximum10s deadline. Transport and
store implementations must honor cancellation; deadline expiry does not prove a
remote mutation stopped. Neither capability supplies production credentials here.

Actual local receive-pack exercises this adapter. Journal regressions demonstrate
creating precedes upload, a lost successful response retains uncertain, resumed
publication performs readback without resend, invalid designated/namespace proof
prevents upload, and remote invalid signature cannot confirm an acknowledged
transfer. Provider reads in journal fixtures are synthetic. Production scoped
HTTP transport, capability discovery, exact store pack integration, installed
trust/namespace and live owner submission remain required.

## Bounded GitHub smart-HTTP transport

`generationHTTP` implements the installed transport for a fixed personal numeric
owner/repository. It acquires an installed scoped credential lease, checks numeric
GitHub repository identity, discovers receive-pack/report-status and SHA1
capabilities, and sends the one expected-absent command once. Discovery rejects an
already advertised generation; the server zero-old-ID transaction closes the
remaining race. Caller URLs, update/delete commands and redirect following are
not accepted. Requests omit cookies, disable cache and bound response bodies to
64KiB; the operation has a maximum10s deadline and propagates cancellation.

Credential authority must retain exact repository/owner installation-token leases
before returning and independently recover acquisition or cleanup ambiguity. The
transport checks lease binding/expiry, keeps tokens in memory and attempts release
on success, rejection and lost response, with a separate maximum5s cleanup
deadline. Cleanup failure reports reconciliation required even after transfer;
it is not proof the credential was revoked. No production credential authority
or retained cleanup service is commissioned by this module. Total local lifetime
may extend up to5s beyond the coordinator's observation deadline during cleanup.

Tests compose the HTTP adapter and upload adapter with actual local Git
advertisement/receive-pack processes. HTTP routing and credential leases are
synthetic; no real provider HTTP request is sent. Other cases cover redirects,
foreign owner, unsupported discovery, lost transfer, cleanup failure and a100ms
stalled discovery that aborts before transfer and releases its lease. Production
credential issuance/recovery, HTTP reachability, fixed object-store pack wiring,
current trust/namespace and native authenticated owner submit remain required.

## Fixed candidate object store

`candidateStore` now supplies installed `store.pack` from one configured canonical
object directory and numeric repository. Complete independent objects are checked
at construction and before/after packing: external alternates, shallow/common
stores and graft files are denied. Primitive generation binding is snapshotted;
no caller directory or ref is accepted. Native Git packs the exact designated
candidate and reachable history without hooks or lazy fetching. Configured
candidate proof is checked before and after packing, and signal cancellation
prevents delivering pack bytes to transport. Git child commands use existing10s
bounds; cancellation checkpoints do not prove an already-running native child
stopped immediately. No network credential is acquired until pack returns.

The actual local chain reconstructs and SSH-signs a candidate, packs it using
this store, creates its generation via receive-pack, and cryptographically verifies
its designated SSH signature again in the receiving repository. Complete commit
bytes and submitted file content survive independent pack import. Revoked proof,
foreign repository and external object-store drift are rejected. Signing uses a
temporary fixture software key; snapshot proof is synthetic. This is local chain
qualification, not production role enrollment or GitHub enforcement.

Pinned Node24.19.1 type declarations support strict native filesystem interfaces;
installation ran without scripts and audit reported zero findings. Production
remote object retention/trust, issuer recovery, personal owner submission and live
provider/governance qualification remain required.
