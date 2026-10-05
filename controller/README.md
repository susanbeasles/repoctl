# repoctl Cloudflare controller — foundation

This increment implements a signed-webhook ingress, allowlisted event routing,
per-repository Durable Object bookkeeping, idempotent R2 event receipts, and
standalone signed promotion-ledger creation/verification functions.

**Promotion is disabled. No GitHub App token is minted, no workflow is triggered,
no main ref is updated, and no branch is deleted.** The Worker response explicitly
reports that promotion is disabled. Ledger functions are not yet wired to live
promotion. Event receipts are observations, not signed authorization receipts.

## Tests

```sh
cd controller
npm test
```

Node 22+ is required for tests. Production uses Cloudflare's Web Crypto runtime.
There are no test/runtime npm dependencies in this increment. Wrangler deployment
requires a separately selected and pinned tool version; no account was deployed.
Tests exercise cryptography and mocked storage, not a deployed Cloudflare runtime.

## Provisioning prerequisites

- Personal GitHub App and installation on opted-in repositories.
- Cloudflare account, Worker route, SQLite-backed Durable Objects, and R2 bucket.
- Shared GitHub webhook secret in a Worker secret binding.
- Reviewed repository/actor allowlist in `REPOSITORIES_JSON`:

```json
[
  {
    "repositoryID": 1404914851,
    "ownerID": 215839550,
    "actorIDs": [215839550]
  }
]
```

These numeric values identify the current development repository and owner, not
product defaults. Include a verified App bot actor ID when needed. A GitHub App
ID, installation ID, and sender/bot user ID are different identifiers.

`wrangler.jsonc` deliberately sets `workers_dev` false and supplies no public
route. Select the actual account, bucket and route before deployment. Configure
GitHub's webhook URL as `https://YOUR_HOST/github/webhook`.

The controller rejects unlisted repositories/owners/actors and fork PR heads.
Only the supported event types are admitted. Valid-but-disallowed events receive
202 without scheduling work. Signed raw webhook bytes are verified before parsing;
bodies are capped at 1 MiB. No event body or token is logged. Oversized legitimate
GitHub events require a future reconciliation path; they fail rather than being
partially processed.

Pending archival survives an R2 error in Durable Object storage. A redelivery
retries it. There is no autonomous pending-work alarm/reconciliation scheduler
in this increment; do not depend on indefinite GitHub retries as the final design.

## Archive protection

Configure a bucket lock covering `events/`, and eventually `ledger/`, `objects/`
and `checkpoints/`, with the approved retention duration or indefinite retention.
The code uses create-if-absent writes and compares existing/retrieved bytes.

Cloudflare R2 bucket locks prevent deletion/overwrite while configured. A bucket
administrator can remove the rules. This is not irreversible compliance-mode WORM.
Keep bucket-administration credentials out of the Worker and use separately
controlled checkpoints/backups when an administrator-independent guarantee matters.

A Worker R2 binding is not by itself an append-only security boundary. Runtime
code contains no delete operation, but compromised deployment authority can
replace that code. Locks and administration separation are additional controls.

## Signed commit ledger protocol

`ledger.mjs` defines a protocol-specific deterministic JSON encoding: sorted
object keys, safe integer numbers, arrays and strings. It is not advertised as
RFC 8785. Ledger envelopes use ECDSA P-256/SHA-256 with a fixed protocol identifier.
The public-key trust set is supplied independently to the verifier.

Each promotion entry binds repository ID, sequence, previous signed-envelope
SHA-256 digest, old main SHA, promoted SHA, original source SHA, policy digest,
evidence digest, and backup digests.

A verifier checks each signature, repository binding, sequence continuity,
previous digest and successive Git tip relationship. It then compares the final
sequence/digest/commit to an independently trusted checkpoint. Empty/truncated
or substituted chains cannot satisfy a newer checkpoint.

The ledger does not prove that the Git commit actually has the asserted parent,
or that approvals/checks were real. Before signing, the future promotion engine
must verify Git objects, signatures and GitHub evidence independently. Whole
repository restore tests need the actual Git objects; a ledger is not a backup.

## Remaining promotion and backup work

1. Provision App authentication and narrowly scoped installation tokens.
2. Prove exact-SHA FF compatibility with the no-bypass native PR/review rules in
   a disposable repository, including negative tests.
3. Implement immutable snapshot/candidate creation and trusted CI scheduling.
4. Validate candidate one-parent ancestry, current base, owner review on exact
   candidate, actual successful expected check runs and trusted workflow versions.
5. Capture complete Git objects in verifiable bundles; source archives alone
   do not preserve history. Fetch/tag pinned source and integration objects before
   cleanup. Confirm restoration in a disposable repository.
6. Persist a signed pending promotion intent and backups before the external
   GitHub mutation. After FF succeeds, publish a committed ledger entry and
   checkpoint. Reconcile crashes where GitHub succeeded but local state did not.
   Do not claim the cross-service operation is atomic.
7. Provision the controller signing identity and key-rotation policy. A Workers
   secret is not a YubiKey/SEP-bound or independently protected signing key.
   Choose the required custody boundary explicitly before generating a real key.
8. Publish checkpoints under independent retention/authority to detect rollback.
9. Create/verify both immutable tags and all archives before deleting branches.
10. Add alarms, durable retries, drift detection and CI/backup retention policy.

Changing `promotion:'disabled'` is not how to enable this feature: implement and
test the complete engine first. The existing bootstrap profile keeps Actions
and all protected-branch writers disabled until the trusted path is ready.

## Primary references checked 2026-10-04

- https://developers.cloudflare.com/r2/buckets/bucket-locks/
- https://developers.cloudflare.com/r2/reference/consistency/
- https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/
