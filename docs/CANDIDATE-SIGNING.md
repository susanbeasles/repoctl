# Isolated signed candidate construction

`controller/src/candidate/signing.mjs` continues the preparation job. Installed
configuration fixes repository identity, native Git/SSH programs, public SSH key,
author, clock, bounds, separate candidate signer and independent snapshot verifier.
No Worker route, project checkout, provider credential, ref update or promotion
capability is exposed. The promotion App JWT signer is not reused.

`finalize(preparationDirectory, newOutputDirectory, message)` checks the exact
preparation schema and bounded snapshot SHA-256. Input files are opened without
following symlinks or blocking on FIFOs. Installed read-only
`verifySnapshot(binding, {signal})` must independently confirm repositoryID,
sourceSHA, snapshotDigest, verified:true and immutable:true. The real retained-
object verifier remains required; a local digest or caller assertion cannot supply
this installed capability.

The job imports those exact objects into a new private store, independently
reconstructs the submission on the pinned base, and checks prepared tree, merge
base and patch digest. It constructs an unsigned commit with exactly one parent
and fixed author/committer. The proposed bounded message is in the signed bytes.
Immutable source retention is confirmed before signing.

Installed `signer.signGit(request, {signal})` receives fixed repository/source/
snapshot/base/tree binding, preparation digest, Git namespace and a copy of the
unsigned bytes. It returns an armored SSH signature. Native Git verifies against
the pinned public key, reads the exact commit back, and retains candidate.json in
state signed-awaiting-integration-generation. The report includes object/digest
bindings and public-key fingerprint. A fingerprint is not hardware-origin proof.

Commands and data are bounded; capabilities receive abort signals and at most a
ten-second deadline. Uncertain signing or failed verification retains the failed
job without retry or ref publication. Inspect it before a new attempt. Remote
adapters must honor cancellation and implement retained idempotency/reconciliation;
a timeout cannot prove a remote operation stopped. Provider capability exception
text is suppressed. Output directories are private and never overwritten.

Native tests use temporary software SSH keys removed with each fixture directory.
They verify complete Git object integrity, exact parent/tree, pinned key identity,
unchanged dirty source refs/index and no output refs. Unconfirmed immutability,
altered tree, wrong key, lost response, timeout and signer payload mutation fail.
Synthetic snapshot responses do not qualify real retention or hardware enrollment.

Still required: installed verified immutable snapshot transport, designated remote
candidate signer/enrollment/revocation, fresh integration generation creation and
readback, approved validation, accepted baseline/hardware policy, authenticated
native submit, independent approvals/archive/history evidence and live promotion.
Existing admission/execution gates remain mandatory. A signed candidate does not
authorize promotion.
