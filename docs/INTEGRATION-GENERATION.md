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
