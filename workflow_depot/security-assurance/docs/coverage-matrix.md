# Security coverage matrix and gap register

Status vocabulary: **IMPLEMENTED** (runs in CI, qualified with fixtures or live tool test), **PARTIAL** (runs, with named blind spots), **DECLARED** (emits `POLICY_UNAVAILABLE`/`NOT_RUN` so the gate sees it; not executing), **GAP** (not represented by a control at all — listed below).

Every row maps to a control id in `policy/release-policy.yml`. A directive bullet that has no control id is in the gap register at the bottom, by design — nothing is silently omitted.

## Domains

| Dir. | Domain | Controls | Status | Tools | Blind spots recorded in evidence |
|---|---|---|---|---|---|
| A | SAST | `SAST-SEMGREP`, `SAST-CODEQL`, `SAST-SHELLCHECK`, `SAST-BANDIT`, `SAST-ESLINT-SECURITY`, `SAST-RUST`, `SAST-SWIFTLINT` | IMPLEMENTED (JS/TS, Python, shell, Actions, Docker, Terraform) · ESLint opt-in only (`allow_project_tooling`) · CodeQL compiled languages need `codeql_build_command` · DECLARED (Rust lints, Swift) | semgrep 1.180.0, CodeQL (security-extended), shellcheck 0.11.0, bandit 1.9.4, eslint-plugin-security (project-pinned) | Semgrep registry packs are not digest-pinned unless the caller vendors rules (`semgrep_rules_path`). CodeQL needs GHAS on private repos → `POLICY_UNAVAILABLE` (blocking). Infer/Joern/CPG not integrated (GAP-SAST-RESEARCH). |
| B | DAST | `DAST-ZAP`, `DAST-NUCLEI` | IMPLEMENTED when caller supplies authorized target · DECLARED (nuclei) | ZAP baseline (action v0.15.0) | Baseline = passive + light active + ajax spider. No authenticated crawl, request smuggling, cache deception, WebSocket (GAP-DAST-DEPTH). Refuses targets without `dast_authorization_ref`. |
| C | IAST | `IAST-RUNTIME` | DECLARED | — | Needs instrumented running app; commercial agents. |
| D | SCA | `SCA-OSV`, `SCA-TRIVY`, `SCA-GRYPE`, `SCA-NPM-AUDIT`, `SCA-PIP-AUDIT`, `SCA-LOCKFILE-INTEGRITY` | IMPLEMENTED (3 independent engines + lockfile policy) | osv-scanner 2.7.0, trivy 0.75.0, grype 0.120.1, npm, pip-audit 2.10.1 | No malicious-package intent detection, typosquat, maintainer-takeover feeds (GAP-SCA-MALICIOUS). No reachability for JS/Python (GAP-SCA-REACH). yarn/pnpm lock semantics not parsed by lockfile policy (GAP-SCA-YARNPNPM). |
| E | SBOM/provenance | `SBOM-SOURCE`, `SBOM-ATTEST`, `EVIDENCE-SIGN` | IMPLEMENTED (source SBOM, keyless Sigstore attestation + verification) | syft 1.54.1, cosign (installer v4.1.2) | Container/image SBOM and SLSA build provenance belong to the build pipeline (GAP-SBOM-IMAGE, GAP-SLSA-BUILD). |
| F | Malware | `MAL-CLAMAV`, `MAL-YARAX` | IMPLEMENTED | ClamAV (apt), yara-x 1.21.0 + `rules/yara` | ClamAV is distro-packaged, not digest-pinned in registry. YARA rule set is a small baseline; no behavioral sandbox, no runtime memory inspection (GAP-MAL-SANDBOX). |
| G | Git forensics | `SRC-GIT-FORENSICS` | IMPLEMENTED (custom, fixture-qualified) | `git_forensics.py` with locked-down git | Unreachable/dangling objects from other workspaces absent in a fresh clone (stated in evidence). Signature verification INCONCLUSIVE until a trusted keyring is provisioned (GAP-GIT-KEYRING). Force-push history requires server-side audit log (GAP-GIT-SERVERLOG). |
| H | Hostile assets | `ASSET-HOSTILE` | IMPLEMENTED (custom, fixture-qualified) | `asset_scan.py` | Structural only; no sandboxed rendering; WOFF2 tables not decompressed; no canonical-sanitized-output comparison yet (GAP-SVG-SANITIZE). |
| I | Cache poisoning | `CACHE-TRUST` | PARTIAL | `cache-policy` action | Scanner jobs restore no caches (structural fix). Caller workflows linted. Content verification of caches restored on trusted refs not implemented (GAP-CACHE-CONTENT). Docker layer / registry cache out of scope here (GAP-CACHE-OCI). |
| J | Secrets | `SEC-SECRETS-GITLEAKS`, `SEC-SECRETS-TRUFFLEHOG` | IMPLEMENTED (two engines, full history, allow-listed evidence fields) | gitleaks 8.30.1, trufflehog 3.99.2 | Verification disabled (no egress) so TruffleHog is report-tier. Secrets in images/binaries not covered. |
| K | IaC/cloud | `IAC-CHECKOV`, `IAC-TRIVY-CONFIG`, `IAC-ZIZMOR`, `IAC-CONFTEST` | IMPLEMENTED | checkov 3.3.28, trivy, zizmor 1.30.1, conftest 0.71.1 | Checkov severity is keyword-derived (no platform API). Live cloud posture (AWS config/IAM analysis) not run here (GAP-CLOUD-POSTURE). |
| L | API | `API-SCHEMATHESIS` | IMPLEMENTED when caller supplies schema + authorized target | schemathesis 4.31.0 | No BOLA/IDOR authorization matrix (GAP-API-AUTHZ). GraphQL only via schemathesis' GraphQL support. |
| M | Mobile | `MAST-DYNAMIC`, `SAST-SWIFTLINT` | DECLARED | — | Needs macOS/device host. |
| N | Runtime Linux | `RUNTIME-LINUX` | DECLARED | — | Falco/eBPF are runtime-host controls. |
| O | FIM | `FIM-BASELINE` | DECLARED | — | Runtime-host control. |
| P | APT hunting | `APT-HUNT` | DECLARED | — | No telemetry source. The pipeline does not pretend continuous detection exists. |
| Q | AI/agent | `AI-INJECTION`, `AI-REVIEW` | IMPLEMENTED (poisoning scanner, fixture-qualified; advisory reviewer: explicit opt-in + approval ref, PHI/secret scrub with refusal, path denylist, egress receipt, allow-listed endpoint) | `ai_injection_scan.py`, Claude via API | Heuristic; multilingual/paraphrased injection weak. Promptfoo/garak adversarial suites not integrated (GAP-AI-ADVERSARIAL). Reviewer is `INCONCLUSIVE`/report tier by construction. |
| R | Fuzzing/formal | `FUZZ-COVERAGE`, `FORMAL-VERIFY` | DECLARED | — | Needs VM-isolated scheduled tier (GAP-FUZZ-TIER). |
| S | ASPM | gate decision + evidence manifest + signed bundle | PARTIAL | `gate.py` | Normalized findings, dedup by control, candidate binding, freshness, policy revision, "clean vs never ran" distinction all present. No persistent store, SLA/exception expiry, EPSS/KEV enrichment, or dashboard (GAP-ASPM-STORE, GAP-INTEL-ENRICH). |

## Language matrix

| Ecosystem | Detect | SAST | SCA | Secrets | Malware/assets | Notes |
|---|---|---|---|---|---|---|
| JS/TS (npm) | yes | Semgrep, CodeQL, eslint-security (if configured) | OSV, Trivy, Grype, npm audit, lockfile policy | yes | yes | yarn/pnpm: SCA via OSV/Trivy/Grype only |
| Python | yes | Semgrep, CodeQL, Bandit | OSV, Trivy, Grype, pip-audit, lockfile policy | yes | yes | |
| Rust | yes | Semgrep, CodeQL (rust) | OSV, Trivy, Grype (Cargo.lock), lockfile policy | yes | yes | clippy/cargo-deny `NOT_RUN` (unqualified) |
| Swift | yes | — | OSV/Trivy where Package.resolved is supported | yes | yes | `POLICY_UNAVAILABLE` for SwiftLint/MobSF |
| Shell | yes | ShellCheck, Semgrep | — | yes | yes | |
| Linux/ELF | — | — | Trivy (OS pkgs in fs scans) | — | ClamAV, YARA-X, git forensics magic sniff | Runtime controls DECLARED |
| IaC (TF/HCL/Docker/Actions) | yes | Checkov, Trivy config, zizmor, Semgrep | — | yes | yes | |
| Data/config (JSON/YAML/TOML/XML/MD) | yes | Semgrep, AI-injection scan, asset scan (XML) | — | yes | yes | |
| Assets (SVG/images/fonts/archives/wasm) | yes | asset scan | — | — | asset scan, ClamAV, YARA-X | |
| AI artifacts (prompts, MCP, skills) | yes | AI-injection scan | — | yes | — | |

## Gap register

| Id | Gap | Why | Suggested path | Priority |
|---|---|---|---|---|
| GAP-TOOL-PYHASH | Python tools version-pinned, not hash-pinned | Needs full transitive hash set | `uv pip compile --generate-hashes` → `policy/requirements-tools.txt` + `--require-hashes` | High |
| GAP-SAST-RESEARCH | Infer/Joern/CPG/symbolic not integrated | Research-grade; needs FP evaluation first | Scheduled deep-scan tier, report tier only | Low |
| GAP-DAST-DEPTH | No authenticated crawl, smuggling, cache deception, WebSocket | Baseline scan only | ZAP full-scan + context file + auth script on preview env; nuclei with vendored, reviewed templates | Medium |
| GAP-SCA-MALICIOUS | No malicious-package / typosquat / maintainer-takeover intelligence | No qualified feed | Evaluate OSV malicious-package data (`MAL-*` ids are already surfaced by osv-scanner), GuardDog, Socket | High |
| GAP-SCA-REACH | No reachability for JS/Python | Tooling immature | CodeQL + dependency call-graph queries | Medium |
| GAP-SCA-YARNPNPM | Lockfile policy does not parse yarn/pnpm semantics | Not yet written | Extend `sca-scan` lockfile step | Medium |
| GAP-SBOM-IMAGE / GAP-SLSA-BUILD | No image SBOM or build provenance | Belongs to build pipeline | `syft` on image + `slsa-github-generator` in the build workflow; feed results as `SBOM-IMAGE`, `PROVENANCE-BUILD` controls | High |
| GAP-MAL-SANDBOX | No behavioral sandbox | Needs VM isolation | Scheduled tier on self-hosted ephemeral VMs (Firecracker/Kata), CAPE/Cuckoo-class | Low |
| GAP-GIT-KEYRING | Commit signatures not verified against a trusted keyring | Keyring not provisioned | Ship `policy/allowed-signers`; `gpg.ssh.allowedSignersFile` in forensics | High |
| GAP-GIT-SERVERLOG | Force-push / branch protection audit | Requires GitHub audit log API | Scheduled job with read-only audit-log token | Medium |
| GAP-SVG-SANITIZE | No canonical sanitized asset + diff | Not implemented | Add DOMPurify/svg-sanitizer canonicalization step producing an explicit transformation record | Medium |
| GAP-EXEC-SANDBOX | No sandboxed executor for project tooling (ESLint plugins, compiled builds) | Would let repository code tamper with evidence in-job | `docker run --network none --read-only` executor emitting raw output only; result emission from a separate job that re-verifies the depot tree digest | High |
| GAP-AI-EGRESS-ENFORCE | Egress allow-list is enforced in code, not at the network | GitHub-hosted runners cannot filter egress | Self-hosted runner with egress allow-list for `strict` profile | Medium |
| GAP-CACHE-CONTENT / GAP-CACHE-OCI | No content verification of restored caches; no OCI layer checks | Scanner jobs avoid caches entirely instead | For trusted-ref builds: hash node_modules against lockfile integrity map post-restore; `cosign verify` base images | Medium |
| GAP-CLOUD-POSTURE | No live AWS posture assessment | Needs authorized read-only role | Prowler/ScoutSuite via OIDC role in a separate workflow, feed as control | Medium |
| GAP-API-AUTHZ | No BOLA/IDOR matrix | Needs multi-identity test harness | Schemathesis with auth matrix + custom checks | Medium |
| GAP-AI-ADVERSARIAL | Promptfoo/garak suites not integrated | Needs target definition for your agents | Add `ai-adversarial` action against the AI reviewer and MCP configs | Medium |
| GAP-FUZZ-TIER | No fuzzing tier | VM isolation + runtime | Scheduled job on isolated runners; cargo-fuzz/Atheris/jsfuzz; report tier until FP-evaluated | Low |
| GAP-ASPM-STORE / GAP-INTEL-ENRICH | No persistent findings store, SLA, EPSS/KEV | Out of scope for a workflow | Export `gate-decision.json` + findings to DefectDojo / OpenSSF-compatible store; enrich with EPSS + KEV in the store | Medium |
| GAP-CLAMAV-PIN | ClamAV from apt, not digest-pinned | apt-signed only | Build pinned ClamAV container image, sign it, reference by digest | Low |

## What "clean" means in the evidence

`gate-decision.json` lists every policy control with one of seven verdicts. A control that never produced a result is `NOT_RUN`, never absent. A `PASS` with findings above the control's `fail_on` severity is reported as `FAIL`. Results for a different SHA or repository, or older than 24h, are `NOT_RUN`. `unknown_results` lists any result file the policy did not ask for.
