# Security and release bootstrap

Implemented:

```sh
repoctl security --help
repoctl security inspect susanbeasles/repoctl
repoctl security plan susanbeasles/repoctl
repoctl security apply susanbeasles/repoctl
```

The command enables secret scanning and secret-scanning push protection and reads both settings back. It requires authentication as the personal owner and an active public non-fork repository. It does not retrieve secret alert values, enable Actions, change rulesets, or enable CodeQL default setup. Re-running apply is safe. Partial failures leave successfully enabled protections in place.

The history verifier is implemented at `controller/scripts/verify-history.mjs`. It requires an existing previous main tip and checks that the new tip has exactly that single parent. Initial branch creation requires an explicit bootstrap anchor rather than silently passing a zero SHA.

`templates/history-integrity.yml` is an inactive template. It triggers only on main/master pushes, never PRs. Install it after the App promotion and Actions actor/event policies are configured. Protect a differently named default branch explicitly when rendering for other repositories.

A post-push workflow detects violations; it does not prevent a push or make history permanent against an administrator removing rules or deleting the repository. Prevention requires no-force-push/no-deletion rules without bypass. Independent signed ledger checkpoints and verified retained Git archives provide external evidence and restoration. A workflow removed by a new commit cannot enforce future checks by itself.

## Remaining scanning integration

CodeQL advanced setup should run only against controller-created integration candidates, with exact-SHA checks required before promotion. Do not enable default setup without validating its event behavior against the no-outsider-workflow policy. Security queries, dependency alerts, language-specific quality checks, and release artifact scanning are distinct capabilities. GitHub does not provide a universal free malware scan toggle. Swift and JavaScript analysis need separate validated build/query configurations.

## Release contract to implement with promotion

Proposed automatic SemVer policy:
- Start at v0.1.0.
- Breaking change (`!` or a BREAKING CHANGE footer): major bump.
- feat: minor bump.
- fix and other accepted commit types: patch bump.
- During 0.x, breaking changes still bump major; no hidden special case.

Validate the approved squash message before promotion. Derive the next version from the previous committed release record, not mutable timestamps or workflow run numbers. Reserve the version in the serialized repository coordinator. Exactly one version belongs to one promoted SHA; retries reuse it.

Names:
- Published release tag: `v1.2.3`, pointing at the promoted squash commit.
- Source preservation tag: `repoctl/source/pr-42/<full-source-sha>`.
- Promotion preservation tag: `repoctl/promotion/000042/<full-promoted-sha>`.

The promotion sequence is independent of the PR number. All tags are create-only and cannot be moved or deleted. Create preservation tags before temporary branch cleanup.

On each successful promotion, generate release notes from the previous release to the exact new SHA, including the PR link, approved summary, categorized changes, provenance, and verification results. Do not invent capability descriptions from code or use an untrusted PR title as shell code. Stage any artifacts on a draft, verify their digests, then publish once immutable releases are enabled. Never replace published assets; fixes produce a new version.

Publishing retries must verify the existing tag target and published release identity. A collision or missing predecessor blocks publication. Reconcile missed release events from the promotion ledger rather than skipping earlier commits when concurrent workflow runs occur.

Actual release publication, CodeQL workflows, and the owner-approved App promotion path remain pending. This patch does not activate them or apply locked bootstrap, which would disable Actions and block all main writers.
