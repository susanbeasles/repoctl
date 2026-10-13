# Threat model: the pipeline as an attack surface

Scope: the reusable workflow, its composite actions, scripts, policy, and the GitHub Actions runtime they execute in. Deployment (`delivery_control`) is out of scope except where this pipeline hands it evidence.

## Assets
1. The promotion decision (`gate-decision.json`) and the signed evidence bundle.
2. The OIDC identity of the `evidence-sign` job (`…/security-assurance.yml@<ref>`).
3. Scanner integrity (binaries, rulesets, databases) and the policy file.
4. The optional `ANTHROPIC_API_KEY`.
5. Confidentiality of anything the scanners read (source, which in a HIPAA shop may include fixtures that must never contain PHI).

## Trust boundaries
| Boundary | Untrusted side | Trusted side | Enforcement |
|---|---|---|---|
| Candidate source → scanners | `src/` at `github.sha`, its history, `.gitattributes`, `.gitmodules`, hooks, symlinks, assets, docs, commit messages | depot scripts/actions at pinned `depot_ref` | Separate checkout; `persist-credentials: false`; `submodules: false`; git run with `GIT_CONFIG_GLOBAL=/dev/null` and hooks/filters disabled; `CHECKOUT-TREE-MISMATCH` fails if the working copy differs from the raw tree |
| Scanner job → evidence | result files produced by a job that touched untrusted code | gate job (never checks out `src/`) | Results carry `candidate.sha`/`repository`/`policy_revision`; gate rejects mismatches, duplicates, unknown control ids, stale results; result schema has no free-form fields that reach the gate's logic |
| Project tooling (Stage 2) → runner | `npm ci`, eslint plugins, build hooks | job boundary only | `--ignore-scripts`; ESLint plugin execution and compiled-language builds are **off by default** (`allow_project_tooling`, `codeql_build_command`) because in-job execution could forge evidence (GAP-EXEC-SANDBOX); jobs have `contents: read` only, no OIDC; each job is a fresh ephemeral runner |
| Scanner output → AI reviewer | findings, diff text | reviewer prompt | All content wrapped in `<untrusted_…>`; system prompt forbids following embedded instructions; output is `INCONCLUSIVE`/report tier and structurally cannot change the gate (`test_gate.py` case 11) |
| Depot → application repos | this repository | callers | Callers pin `depot_ref` to a full SHA; depot runs its own qualification workflow; actions pinned by SHA |
| Signing | evidence bundle | Sigstore/Fulcio | Only `evidence-sign` has `id-token: write`; it runs no scanner and never checks out `src/`; signature is verified in-job against the workflow identity before `EVIDENCE-SIGN` is emitted |

## Attacks considered and current disposition
| Attack | Disposition |
|---|---|
| PR adds `.github/workflows` that caches poisoned deps for `main` | `CACHE-TRUST` flags cache on `pull_request_target`, non-content-addressed keys, `restore-keys`; zizmor flags pwn-request patterns; scanner jobs restore no caches |
| Repo ships a smudge filter / hook to mutate files at checkout | Hooks/filters disabled via config; `.gitattributes filter=` is a high finding; tree-vs-checkout diff is critical |
| Symlink in tree pointing at runner secrets or `/etc` | `SYMLINK-ESCAPE` critical; `asset_scan`/`ai_injection_scan` skip symlinks |
| Executable or archive hidden under `.js`/`.md` name | Magic sniff in forensics (`BLOB-HIDDEN-*`), YARA `SUSP_Embedded_ELF_In_Text`, asset-scan `DISGUISED-EXECUTABLE` |
| Unicode tag characters / bidi / confusables in instructions, paths, source | `AI-UNICODE-TAGS` critical, `PATH-INVISIBLE-UNICODE`, `BLOB-INVISIBLE-UNICODE`, YARA `SUSP_Trojan_Source_Bidi` |
| Commit message or README instructs the AI reviewer to approve | Reviewer is advisory only; `COMMIT-MSG-INJECTION` and `AI-HIDDEN-COMMENT-INSTRUCTION` surface it |
| Code under review emits a fake `SAST-CODEQL.json` into `security-results/` | Results directory is created by the depot action in the runner's workspace, not inside `src/`; the gate's `unknown_results` and candidate binding catch extra/forged files; `SAST-CODEQL` is rebuilt from per-language members by the gate action itself |
| Scanner binary swapped by a compromised release | `install_tool.py` verifies SHA-256 against the committed registry; mismatch exits 3 |
| Scanner crashes or is skipped and the gate sees nothing | `NOT_RUN`/`TOOL_FAILURE` are blocking for gate-tier controls (cases 2–3); `ensure-results` records the cause |
| Scanner emits garbage and the action reads it as zero findings | `normalize.py` exits 3 and marks `parse_error`; `count_blocking.py` returns `ERR` → `TOOL_FAILURE`; gate schema validation (case 13) |
| Stale "green" evidence replayed against a new commit | SHA/repo binding and 24h freshness |
| Reviewer exfiltrates secrets/PHI via API call | Explicit opt-in + approval ref required; path denylist; gitleaks + PHI-pattern scrub refuses the send on any hit; endpoint hard allow-listed; egress receipt with payload sha256 written before the request; the AI job has no OIDC token. Network-level enforcement needs a self-hosted runner (GAP-AI-EGRESS-ENFORCE) |
| Runaway cost | Every job has `timeout-minutes`; scanners run under `timeout`; findings capped at 200 items / 2000 chars per field; AI diff capped at 200 kB and `max_tokens`; no retries; concurrency group per SHA |

## Residual risks (accepted until the linked gap is closed)
- Semgrep registry packs change under you unless rules are vendored (GAP-TOOL-PYHASH, see `semgrep_rules_path`).
- GitHub-hosted runners are shared infrastructure; VM-grade isolation for fuzzing/behavioral analysis is not available here (GAP-MAL-SANDBOX, GAP-FUZZ-TIER).
- A compromised depot commit compromises everything downstream. Mitigation: branch protection + required `scanner-qualification` + signed commits on the depot, and callers pinning full SHAs.
- Vulnerability databases (OSV, Trivy, Grype) are fetched at run time; the run records the DB timestamp but cannot pin it. Daily scheduled rescans are the compensating control.
