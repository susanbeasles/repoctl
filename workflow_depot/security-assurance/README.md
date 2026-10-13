# security-assurance

A reusable GitHub Actions security pipeline built as a set of custom composite actions, a fail-closed policy gate, and a signed evidence bundle. It is the `workflow_depot` role from the master directive: application repositories call it with a five-line workflow; all policy, tooling and evidence logic lives here.

**Read `docs/coverage-matrix.md` before anything else.** It states exactly which of the directive's domains execute here, which are declared as unavailable so the gate can see them, and what remains a gap.

## What a run looks like

```
S0 detect ──► S0 admit ×5 (git forensics, secrets, malware, assets, AI-injection) ──► S0 admission gate
                                                                                       │ PASS only
S2 analyze ×9 (semgrep, shellcheck, ecosystem SAST/SCA, SBOM+SCA, IaC, cache, DAST, API, declare) + codeql ×N
                                                                                       │
S3 policy gate (stages 0+2) ──► S4 AI review (advisory) ──► S5 attest SBOM, sign evidence bundle, final gate (all)
```

Every control writes one JSON result through `.github/scripts/result.py`. The gate (`gate.py`) evaluates every control in `policy/release-policy.yml` and fails if any gate-tier control is anything other than `PASS` or `NOT_APPLICABLE`-with-reason. Missing is `NOT_RUN`. Crashed is `TOOL_FAILURE`. Not possible in CI is `POLICY_UNAVAILABLE`. None of those are green.

## Adopting it in an application repo

1. Fork/copy this repo into your org, protect `main`, require the `Scanner qualification` workflow.
2. Copy `.github/workflows/caller-example.yml` into the app repo as `.github/workflows/security.yml`; replace `YOUR-ORG` and `PINNED_DEPOT_SHA` (full 40-char SHA, both places).
3. Enable GitHub Advanced Security on private repos, or expect `SAST-CODEQL` to block (it is deliberately not downgradable from a caller input).
4. Optional inputs, all documented in the caller example: vendored Semgrep rules, Rego policies, authorized DAST/API targets (require an `*_authorization_ref`), `ANTHROPIC_API_KEY` for the advisory reviewer.
5. The run uploads `security-evidence-<sha>` (400-day retention) containing every result, raw scanner output, `gate-all/gate-decision.json`, `evidence-bundle.tar.gz`, its Sigstore bundle and the SBOM attestation. Your deployment workflow should download it and run:
   ```
   cosign verify-blob --bundle evidence-bundle.sigstore.json \
     --certificate-identity-regexp '^https://github.com/YOUR-ORG/security-assurance/.github/workflows/security-assurance.yml@' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com evidence-bundle.tar.gz
   ```
   then check `gate-decision.json` has `decision: PASS` and `candidate.sha` equals the artifact you are about to deploy.

## Profiles

- `ci-baseline` (default): the seven controls that cannot execute in GitHub Actions (IAST, iOS dynamic, runtime Linux, FIM, APT hunting, fuzzing tier, formal verification) are recorded as `POLICY_UNAVAILABLE` and downgraded to report tier. The run can promote; their absence is on every summary.
- `strict`: those controls stay gate tier. Nothing promotes until their evidence is produced elsewhere and fed in as result files. Use it to prove fail-closed behaviour and once those controls exist.

## Repository layout

```
.github/workflows/security-assurance.yml   reusable workflow (workflow_call)
.github/workflows/caller-example.yml       thin caller for app repos
.github/workflows/scanner-qualification.yml depot self-test: gate fault injection, fixture detection, digest re-verification, YAML/pin lint, dogfood run
.github/actions/<name>/action.yml           one composite action per control group (28)
.github/scripts/                            result.py, gate.py, normalize.py, count_blocking.py, install_tool.py, detect_ecosystems.py, git_forensics.py, asset_scan.py, ai_injection_scan.py, phi_scrub.py, ai_review_call.py
policy/release-policy.yml                   control inventory, tiers, fail_on thresholds, stages
policy/tool-registry.yml                    pinned versions + SHA-256 of every binary, action SHAs, unqualified list
rules/yara/                                 vendored YARA-X rules (ruleset digest recorded in evidence)
qualification/                              fixtures.py (generated hostile/clean fixtures), test_gate.py (12 fault-injection cases), test_scanners.py
docs/coverage-matrix.md                     per-domain status + gap register
docs/threat-model.md                        the pipeline as an attack surface
docs/completion-matrix.md                   v3 factual status per directive item
rules/{semgrep,rego,yara,eslint,swiftlint,cargo-deny}  vendored, digest-recorded rule packs
qualification/run_local.py                  runs the real action steps end to end locally
```

## Maintenance model

- **Bumping a tool**: download the new release asset, compute SHA-256, cross-check the project's checksum file, update `policy/tool-registry.yml`, open a PR. `scanner-qualification` re-downloads every registry entry and fails on any digest mismatch.
- **Adding a control**: add the id to `release-policy.yml` (`tier`, `fail_on`, stage list), write an action that emits exactly that id via `result.py`, add a positive and negative case to `qualification/`. The gate ignores result files for ids the policy does not know.
- **Changing policy**: the policy file's SHA-256 is embedded in every result and in the gate decision; a policy change is visible in evidence by construction.
- **Rules**: YARA and Semgrep rules are hashed into the `ruleset_revision` field of the result. Vendor Semgrep rules in the app repo (`semgrep_rules_path`) to make that digest meaningful; registry packs are recorded as `registry(unpinned)@<timestamp>`.

## v3 changes

See `docs/completion-matrix.md` for the factual status of every item. Highlights: content inspection of caches/artifacts/archives/binaries (`cache_inspect.py`, `binary_inspect.py`); supply-chain analysis for node/python/rust/swift (`supply_chain.py`); shell security audit; bubblewrap sandbox for repository-controlled tooling (ESLint now runs with the depot's own pinned toolchain and config inside it); cargo-audit/cargo-deny/SwiftLint/cosign pinned by digest; offline Semgrep rule pack, Rego policies, SwiftLint security config, cargo-deny policy vendored under `rules/`; DAST/API/ESLint/Rust/Swift no longer `NOT_APPLICABLE` when applicable; signed external-evidence ingestion for IAST/MAST/FIM/runtime/APT/fuzz/formal/image-SBOM/provenance/cloud-posture; `verify_evidence.py` for delivery_control; Hypothesis fuzzing of all custom parsers emitted as `FUZZ-PARSERS`; `qualification/run_local.py` executes the real composite-action steps end to end without GitHub.

## v2 changes (corrective drop)

- `detect-ecosystems` rewritten as `detect_ecosystems.py` (the shell→Python boolean interpolation bug is gone; typed JSON, regression-tested).
- False-PASS path closed: `normalize.py` always writes a findings file and exits 3 on malformed output; every action derives status through `count_blocking.py` which returns `ERR` → `TOOL_FAILURE`; parse errors override exit-code verdicts.
- `ensure-results` action runs `if: always()` in every scanner job, so a tool-install/digest failure yields `TOOL_FAILURE` with a reason instead of a bare `NOT_RUN`.
- `gate.py` validates result structure; malformed results become `TOOL_FAILURE` (test 13).
- Project-controlled code execution is now opt-in: `SAST-ESLINT-SECURITY` is `NOT_APPLICABLE` unless `allow_project_tooling: "true"`; CodeQL never autobuilds — compiled languages need an explicit `codeql_build_command` or they are `POLICY_UNAVAILABLE`.
- AI review requires `ai_review_enabled: true` **and** `ai_review_approval_ref`; the payload is scrubbed (gitleaks + PHI patterns, path denylist) and refused on any hit; an egress receipt (destination, payload sha256, bytes, model, usage, approval) is written before the request leaves; the endpoint is hard allow-listed.
- OSV exit 128 maps to `INCONCLUSIVE` until verified on a runner.
- `actionlint` 1.7.12 passes on all three workflows; `bash -n` + `shellcheck -S error` pass on every composite run block; every local `uses:` path resolves.

## What is verified in this checkout vs. what needs a live run

Verified here (no GitHub runner was available): `test_gate.py` (14/14), `test_scanners.py` (55/55), `test_integrity.py` (29/29), `test_fuzz_parsers.py` (0 crashes), `run_local.py` end-to-end on hostile/clean repos, `actionlint` clean, every registry digest re-downloaded and matched, YAML of all 23 action/workflow files parses, all `uses:` pinned to SHAs, live command lines of gitleaks, trufflehog, shellcheck, yara-x, zizmor, syft, osv-scanner (reached the API and failed closed on blocked egress, as designed).

Needs the first real run: trivy/grype DB downloads, ClamAV `freshclam` egress, CodeQL on your GHAS entitlement, ZAP/schemathesis against a preview target, cosign keyless flow under the reusable-workflow identity, and the `${{ }}` plumbing between jobs. Run `scanner-qualification.yml` on the depot first; its `dogfood` job exercises the whole reusable workflow on this repository.

## HIPAA / SOC 2 notes

The evidence bundle is the SOC 2 CC7.1/CC8.1 artifact: who ran what, against which commit, with which tool versions, what it found, signed. Keep the 400-day retention. Never point `dast_target_url`/`api_target_url` at an environment that holds PHI; the actions require an authorization reference and the threat model assumes synthetic data. The AI reviewer sends source diffs to the model provider: enable it only with a BAA and zero-data-retention in place, record that in `ai_review_approval_ref`, and keep the egress receipts. Secrets found by scanners are fingerprinted, never printed.
