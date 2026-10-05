# Anchored history evidence

`historyEvidence` is a verification component, not a deployed checkpoint service.
Installed adapters provide the independently trusted checkpoint, ledger objects,
GitHub observer and ledger public keys. Requests cannot supply those trust roots.

Verification binds repository ID, next sequence, previous ledger digest and current
main SHA to the checkpoint. It verifies the entire selected signed ledger segment,
then checks each recorded promotion against actual single-parent Git ancestry.
The candidate must be exactly one child of anchored main. Main and the independent
checkpoint are checked again before evidence is returned. Truncation, substituted
signatures, missing commits, merges and checkpoint changes reject.

The report uses `historyVerified`, never general authorization `verified`. Candidate
signature/tree/CI checks, archive recovery evidence, current hardware trust and
independent owner/validator approvals remain mandatory separate checks.

Checkpoint adapters must authenticate a root retained outside the ledger storage's
rollback domain. Returning an anchor from the same replaceable storage is not an
independent anchor. This component cannot detect a simultaneous rollback of both
that trusted source and ledger. R2 locks, replicas and retained checkpoints require
actual provisioning and verification; none is enabled by this patch.

At most 10,000 entries are accepted; each needs a GitHub observation. Large segments
need authenticated API access and reviewed checkpoint compaction. Unauthenticated
GitHub quotas can cause verification to fail closed. No truncated segment is accepted
to work around quotas. Missing history blocks promotion rather than claiming that a
ledger hash can recover missing Git objects.
