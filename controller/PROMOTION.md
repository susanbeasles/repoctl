# Promotion implementation and deployment boundary

The new promotion engine is deliberately not exposed by the webhook Worker yet.
The current webhook endpoint still only records receipts. Nothing in this patch
silently grants a bypass, changes a live branch, deploys a Worker, or mints an App
token. CLI protect apply is an explicit remote operation; use plan until readiness
has been established.

## Independent approval

An intent binds repository numeric ID, previous signed checkpoint digest/sequence,
old main SHA, source SHA, candidate SHA, tree SHA, exact policy-file SHA-256,
evidence digest, reconstructable archive digests, nonce and expiry. Maximum local
approval lifetime is five minutes. Owner and validator signatures cover distinct
protocol domains and the SAME exact JSON bytes. Public keys are enrolled out of
band; keys supplied by incoming requests are never trusted. Owner and validator
public keys must be distinct even if configured with different key IDs.

`repoctl approval key POLICY` exports only the existing enrolled policy public
key and its SHA-256 fingerprint. `repoctl approval sign INTENT --policy POLICY
--approve` verifies the policy seal and key binding, then writes INTENT.approval.json.
This uses that policy's provider. Keychain is software-backed; it does not imply
YubiKey authorization. SEP has no automatic fallback. The command does not enroll
trust remotely or execute promotion. Review every SHA and repository identity
before issuing approval. Validator must sign the exact original intent bytes,
not reserialize the document. `signApproval` is a canonical-JSON helper for
producers; an independently signed owner's payload must preserve its bytes.

The existing policy signature protocol is not accepted as promotion approval.
Mac ASN.1 DER signatures are decoded strictly and verified against WebCrypto P-256.

## Writer capability

`ref-writer.mjs` has three installed operations: read configured main tip, read a
SHA-named commit, and PATCH configured main with `{sha, force:false}`. URLs and ref
come from trusted deployment configuration. No shell, checkout, commit/tree
creation, payload-supplied URL, arbitrary ref or force flag. The adapter rechecks
numeric repository identity. GitHub Contents-write itself remains broader than
this wrapper, and stolen credentials remain dangerous.

`promotion.mjs` validates signatures, schema, checkpoint, nonce, signed commit,
exact tree and one parent; then independently verifies archive objects and CI
proofs. It journals an intent, archives it without replacement, updates main,
reads main back, commits the signed ledger and finalizes the journal. Lost ref
responses and interrupted finalization reconcile without another main write.
Unresolved intents block all other promotions for the repository.

## Required production adapters (not supplied in this patch)

- **Serialization/state:** one Durable Object per repository. Execute promote
  under serialization; state get/put/delete plus atomic transaction. This module
  is not safe with an uncoordinated ordinary Map or concurrent stateless requests.
- **Checkpoint:** independently authenticated signed checkpoint; validate signature
  and continuity. Read returns repositoryID, sequence, digest, commitSHA and the
  intentID of the last finalized promotion. Never accept a checkpoint from the
  request itself or reset it to current GitHub main on error.
- **Archive:** verifyObjects reads authenticated manifests, verifies encrypted
  object content and reconstructability, and establishes required independent
  replica coverage. A successful upload, hash-only receipt or existence HEAD
  request is insufficient. Do not install a no-op adapter in production.
- **Evidence:** verify binds exact candidate/tree/policy, fresh complete scan
  reports, trusted workflow revisions, trusted workflow/App identities, run IDs,
  applicable languages and blocking findings. Passing upload jobs are not proof
  of clean CodeQL results. Do not trust branch-selected workflow definitions.
- **Ledger:** append(payload,intentID) is signed, continuity-checked and idempotent
  by intent ID. It updates the independently authenticated checkpoint. After a
  partial failure it returns the original receipt; it never appends twice. A
  checkpoint advanced to this candidate must also bind this exact intent ID.
- **Token:** mint short-lived installation tokens for the configured writer App
  on this repository only. Keep private App material outside candidate jobs.

Failures must leave the journal for reconciliation. Administrative cancellation
requires explicit investigation of remote main and signed ledger state; never
blindly clear a pending intent. Rotation requires continuity and old-key retention
for old receipts. No automated deletion of archived generations is implemented.

## GitHub protection

`repoctl protect plan OWNER/REPO --writer-app SLUG` resolves the numeric App ID and
shows owner working branches, immutable existing tags, owner tag creation,
main/default/master create/delete restrictions with no bypass, no-bypass signed
linear/non-force integrity, and a separate main update rule bypassed only by this
App. Immutable releases are enabled on apply. Writer cannot have Administration
write. An old managed all-writers bootstrap lock is removed only after replacement
rules are installed and verified; modified/inherited locks abort migration.

This preset does not implement native required-review rules, snapshot namespaces,
App release tag creation or the deployable Actions/controller integration yet.
Those must be completed before calling this a finished promotion workflow. Owner
approval is the independent signature gate; GitHub's ordinary PR review cannot
be self-approved by the author. Keep a PR linked to candidate generations for
review/discussion without claiming native reviewer enforcement that is absent.
App installation and actual ruleset behavior need live validation before apply.
Unmanaged/inherited constraints remain in place and can additionally block writes.

## Remaining integration work

1. Create/install separate builder, validator, writer and release authorities.
2. Freeze source/integration generations and link them to a stable PR.
3. Produce signed one-parent squash candidates; preserve source authorship.
4. Run security workflows against candidates and produce validated evidence.
5. Provision verified object archives, replica coverage and signed checkpoints.
6. Wire owner approval, serialized writer and recovery into trusted Actions/Worker
   deployment paths; exercise failure recovery before allowing main writes.
7. Add immutable release/tag creation, full release notes and automatic versions.

Until these are installed, this is a tested promotion core, not a deployed system.
