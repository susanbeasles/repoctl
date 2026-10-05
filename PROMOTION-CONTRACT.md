# Actions-first promotion contract

Implemented in this patch: owner/App actor and event policy configuration;
Actions enabled; read-default workflow tokens; secret scanning toggles;
opt-in candidate security and post-push history templates. Main promotion,
release production, candidate lifecycle and external approvals are NOT implemented.
Templates remain outside .github/workflows until explicitly installed.

## Immutable generations, reusable PR

Working branches are mutable. Each requested PR update produces a new immutable
source generation and an immutable integration generation based on the latest
main. The same PR tracks the current generation; comments/check metadata link all
previous generations. Never unpin/rewrite an already sealed generation. Changing
base or source invalidates approval and all security evidence. Do not expose a
window where any caller can push to an unprotected PR branch.

Rebase creates a replacement working/candidate branch; conflicts stop for local
resolution. Main only gains one squash commit with one parent equal to its exact
current tip. Local branches can fast-forward from main. Re-signing necessarily
changes commit IDs: preserve original authors and archive original commits, use
local YubiKey for user signatures; a remote App signature is a different identity.
A PR author cannot approve their own PR using GitHub's ordinary review mechanism:
owner approval of their own candidates needs an independent exact-SHA gate.

## Approval and minimal writer

Separate validator and writer Apps/credentials. No candidate checkout, package
scripts, repository hooks or arbitrary command input in the writer job. Its
trusted implementation receives a signed, short-lived, single-use promotion
intent binding repository numeric ID, old main SHA, source SHA, candidate SHA,
policy digest, tree digest, CI run IDs/results and exact-candidate owner approval.
Verify the trusted ledger checkpoint and full ancestry; candidate has exactly one
parent equal to old main. Reject stale tip, reused nonce, wrong repository,
expired evidence, unresolved scans or missing approval. Perform only a non-forced
main ref update, verify remote result, finalize ledger; serialize per repository.

Write a durable signed pending intent and verified object archive BEFORE touching
main. A retry reconciles the recorded intent with remote main, without inventing
a second promotion or allowing a new intent while one is unresolved. Publish
immutable source/promoted tags and release only after reconciliation. Persist
signed committed receipts and periodically anchor checkpoints independently.
A hash ledger without stored Git objects cannot restore lost work. Replicate
objects and ledger/checkpoints to independently administered storage.

GitHub bypass + Contents-write credentials are broader than "update this ref
only". Minimal code does not restrict a stolen token. Short-lived tokens,
separate authorization, credential isolation and protected writer workflow are
mandatory; this cannot be advertised as impossible to exploit. Repository admins
can change GitHub settings. R2 locks are not administrator-proof permanent WORM.

## Security gates

CodeQL Swift security-extended (macOS), CodeQL JavaScript, native compilation,
controller tests, lockfile dependency auditing, GitHub secret push protection,
and ClamAV source scanning are supplied as an opt-in starting template.
CodeQL upload success is NOT a clean finding result: validator must query the
completed analysis for the exact candidate and reject policy-blocking findings.
Scan final packaged binaries and dependency SBOM before release too; source-only
malware checks do not cover final artifacts. Add SwiftLint pinned to a reviewed
source revision for quality rules. It is not a security scanner.

DAST runs against an isolated disposable Worker with synthetic data and no
production credentials; scan webhook signature failures, replay, oversized
payloads, outsider/fork rejection, authorization and storage mutation paths.
Do not scan production or substitute a URL scan for CLI runtime tests. SonarQube
Cloud is optional and needs service onboarding; no promise of accountless Cloud
analysis. Scanner errors, stale databases, missing reports and unsupported
languages fail the relevant gate; no green result from skipped checks.

Default policy permits owner (and explicitly configured App) push, dispatch and
workflow_call. Public PRs may exist but do not trigger these workflows. Owner
explicitly dispatches candidate processing, then approved automation can continue.
No pull_request_target checkout, no outsider issue-comment commands, no automatic
fork approval. Workflow templates contain no bypass credentials.
