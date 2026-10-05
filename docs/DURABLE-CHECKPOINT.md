# Durable promotion checkpoint

The checkpoint Worker retains an independent SQLite Durable Object tip and signed
ledger objects in a separate R2 binding. The default public handler returns 404.
Only the named private CheckpointService entrypoint accepts requests. Each repository
uses its own Durable Object. Configuration and ledger public keys are installed trust
roots; callers cannot supply another bootstrap, bucket, signing key or completion URL.

## Private routes

| Route | Input | Result |
|---|---|---|
| `/v1/checkpoint/initialize` | repositoryID | Pinned genesis checkpoint |
| `/v1/checkpoint/current` | repositoryID | Verified retained checkpoint |
| `/v1/checkpoint/entries` | repositoryID, startSequence, endSequence | Verified signed segment |
| `/v1/checkpoint/append` | operationID, signed entry | Retained completion receipt |
| `/v1/evidence/history` | intent | Anchored history evidence |

Bind CheckpointService as EVIDENCE_HISTORY on the admission Worker. Configuration
CHECKPOINT_CONFIG_JSON is an array of records containing exactly repositoryID,
repository, branch, commitSHA, digest and ledgerKeys. branch is main or master.
commitSHA and digest are the reviewed genesis anchor. ledgerKeys contains keyID and
publicKeyX963; keyID must be the SHA-256 fingerprint of the raw P-256 public key.
Changing bootstrap after initialization is rejected. Key inventory changes require
reviewed deployment; retiring a key needed by historical entries will block readback.

Required bindings are CHECKPOINT_COORDINATOR, CHECKPOINT_OBJECTS and
CHECKPOINT_COMPLETION. CHECKPOINT_ENABLED starts false. The included config does
not provision a bucket, retention lock, completion service or signing service.

## Append and recovery

An append validates the exact signed ledger envelope and promotion payload. It must
extend the current sequence, digest and Git tip by one. A transactional reservation
binds the operation ID and entry digest before network work. Another operation cannot
replace a pending append.

CHECKPOINT_COMPLETION must implement private POST
`/v1/ledger/promotion-observation`. Its response must exactly echo operationID,
repositoryID, entryPayloadDigest, baseSHA and commitSHA, plus promoted true. The
service must independently load the retained approved operation and execution lease,
verify the proposed ledger payload against them, and observe actual promotion.
It must not trust an executor assertion or echo caller fields without verification.
No implementation of that completion observer is supplied by this patch.

After confirmation, the Worker conditionally creates and reads back the signed R2
object. One SQLite transaction commits the index, operation receipt and checkpoint
pointer, then clears the reservation. R2 or state-write failure preserves the pending
operation. Retry with the same ID and exact entry recovers without ref writes. A
completed retry validates retained history and returns the same receipt. No append
method moves a Git ref, mints credentials or creates a replacement signature.

Readback verifies genesis, every retained envelope signature, SQL index digests and
full signed continuity. Missing objects, missing root/pointer, an altered genesis or
a pointer behind a retained successor index reject. Loss of SQLite state while the
R2 genesis exists blocks automatic reinitialization instead of silently resetting history.

## Limits and deployment qualification

The default bound is 1,000 entries per genesis segment. Current verification reads the
whole retained segment. History verification additionally observes Git parentage and
is subject to GitHub API quotas. Checkpoint compaction is not implemented; reaching the
bound blocks further appends. `/entries` responses can exceed a downstream transport's
size limit for long segments and fail closed; history verification reads locally.

This separates the ledger object storage from its retained tip. It does not provide
an independent administrative trust domain: a compromised Cloudflare account able to
roll back both SQLite and R2 can defeat that separation. Provider retention locks,
external witnessed checkpoints and redundant copies still require provisioning.
Conditional object creation alone is not an undeletable retention policy.

Local qualification covers real workerd, SQLite Durable Object transactions, R2
readback, private entrypoints, a pending reservation surviving process restart, and
exact retry. It uses synthetic signing keys and a test completion observer. No live
GitHub promotion, production bucket lock or remote hardware enrollment is qualified.
The Worker is not a substitute for BROKER_RECEIPTS finalize/observe routes; the signed
receipt adapter and independently verifying completion service remain required.
