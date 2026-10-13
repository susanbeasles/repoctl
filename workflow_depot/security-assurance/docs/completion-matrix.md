# Completion matrix (v3)

Status vocabulary — **IMPLEMENTED+TESTED**: code exists and a qualification test or live tool execution in the development environment proves the positive and negative cases. **IMPLEMENTED, UNVERIFIED**: code exists, lints clean, but needs a real GitHub runner (network to vulnerability DBs, GitHub-hosted actions, OIDC, or a CPU the dev sandbox lacked). **EXTERNAL**: cannot execute in CI by nature; the pipeline has a signed-evidence ingestion contract for it and blocks (strict) or reports (ci-baseline) until evidence arrives. **GAP**: not represented.

| # | Priority / directive item | Status | Evidence |
|---|---|---|---|
| 1 | Content inspection of restored caches, installed trees, build artifacts, archives | IMPLEMENTED+TESTED | `cache_inspect.py` + `cache-content` action; `test_integrity.py` 5–7: cacache blob re-hash, node_modules vs lockfile, planted `.npmrc`, `.bin` escape, hidden ELF, tar traversal/link escape/embedded ELF, wheel RECORD mismatch; clean caches pass. Wired after `npm ci` in Stage 2 and over `~/.npm`, pip, uv, cargo caches. |
| 1 | Git objects | IMPLEMENTED+TESTED | `git_forensics.py` (fsck, replace refs, grafts, alternates, hooks, config, tree modes/paths/blobs, attributes, submodules, history, checkout-vs-tree); unreachable objects of other workspaces stated as a limitation. |
| 1 | SVG / XML / images / fonts / archives | IMPLEMENTED+TESTED | `asset_scan.py`; 12 positive rules; Hypothesis fuzzed (no crashes). |
| 1 | Hidden files | IMPLEMENTED+TESTED | `cache_inspect.py` HIDDEN-EXECUTABLE; `git_forensics.py` tree inventory; magic sniff everywhere. |
| 1 | Binary forensics (ELF/PE/Mach-O/Wasm) | IMPLEMENTED+TESTED | `binary_inspect.py`; RWX, exec stack, packing entropy, packer markers, embedded ELF, capability strings, Wasm host imports; `/bin/ls` clean; fuzzed. |
| 2 | Rust | IMPLEMENTED+TESTED (cargo-audit live: RUSTSEC-2020-0071 detected) / cargo-deny IMPLEMENTED, UNVERIFIED (needs cargo on PATH) | `sast-rust`, `supply_chain.py` rust (build.rs active code, proc-macro, [patch], source replacement, linker override, git deps, unsafe inventory), `rules/cargo-deny/deny.toml`. |
| 2 | Swift | IMPLEMENTED, UNVERIFIED (SwiftLint Linux binary installed + digest-verified; SIGILL on the dev sandbox CPU) / supply chain IMPLEMENTED+TESTED | `sast-swift` + `rules/swiftlint/security.yml`; `supply_chain.py` swift (binaryTarget w/o checksum, plugins, unsafeFlags, branch deps, missing Package.resolved, UserDefaults secrets, TLS weakening). |
| 2 | Python | IMPLEMENTED+TESTED | Bandit, pip-audit (live), Semgrep rules (live), supply chain (index override, typosquat, active setup.py), wheel RECORD verification. |
| 2 | Node.js | IMPLEMENTED+TESTED | ESLint-security with depot toolchain in sandbox (live; hostile project config proven not loaded), npm audit (pnpm/yarn paths UNVERIFIED), lockfile integrity, supply chain (lifecycle scripts, typosquat incl. transposition, dependency confusion, .npmrc tokens), node_modules drift. |
| 2 | Shell | IMPLEMENTED+TESTED | ShellCheck + `shell_audit.py` (curl\|sh, eval, rm -rf $VAR, reverse shells, persistence, anti-forensics, secrets on argv, inline shell in Makefiles/package.json/workflows); zsh flagged as uncovered by ShellCheck. |
| 3 | Isolated execution | IMPLEMENTED+TESTED (bubblewrap) | `sandbox_exec.sh` + `sandbox-exec` action: user/pid/net/ipc namespaces, ro source, scrubbed env, single rw out, rlimits, timeout 124, out symlinks stripped; `test_integrity.py` 7. Evidence dir, depot, tokens not mounted. ESLint runs through it. CodeQL compiled-language builds still require an explicit operator command (tracer cannot run inside bwrap) — documented. |
| 4 | NOT_APPLICABLE corrections | IMPLEMENTED+TESTED | DAST/API → POLICY_UNAVAILABLE (blocking) when a web framework/schema is detected; Conftest always runs with depot Rego; ESLint/Rust/Swift no longer NA when applicable; missing lockfile → FAIL. Gate test 5/6 enforce NA-with-reason. |
| 5 | SAST | IMPLEMENTED+TESTED (Semgrep offline rules live, Bandit, ShellCheck, ESLint) / CodeQL UNVERIFIED (GitHub-hosted) | |
| 5 | DAST / API | IMPLEMENTED, UNVERIFIED (ZAP action, Schemathesis need a target) | applicability logic tested. |
| 5 | SCA / SBOM / IaC | IMPLEMENTED (osv/trivy/grype/syft/checkov/zizmor/conftest live where offline-capable; DB-dependent ones UNVERIFIED here, fail closed) | Rego policies live-tested (7 denies on hostile, 0 on clean). |
| 5 | Malware | ClamAV IMPLEMENTED, UNVERIFIED (apt + freshclam need the runner) / YARA-X IMPLEMENTED+TESTED (live EICAR, bidi, embedded ELF, curl\|sh) | |
| 5 | Prompt injection | IMPLEMENTED+TESTED + fuzzed | |
| 5 | Fuzzing | FUZZ-PARSERS IMPLEMENTED+TESTED (Hypothesis over the pipeline's own parsers, emitted as a gate control) / FUZZ-COVERAGE EXTERNAL | |
| 5 | Supply chain / provenance | SBOM-SOURCE + attestation IMPLEMENTED (signing UNVERIFIED: needs OIDC) / SBOM-IMAGE, PROVENANCE-BUILD EXTERNAL via `external-evidence` | |
| 5 | IAST, MAST, FIM, runtime, APT, formal verification, cloud posture | EXTERNAL | `external_evidence.py` + `policy/external-identities.yml`; `test_integrity.py` 8: unsigned rejected, trusted key accepted, tampered rejected, ingested FAIL blocks under ci-baseline. |
| 6 | Qualification tests | IMPLEMENTED+TESTED | `test_gate.py` 14, `test_scanners.py` 55, `test_integrity.py` 29 (tampering, scanner compromise, install failure, cache poisoning, sandbox, external evidence, forged results), `test_fuzz_parsers.py` (~480 cases), `run_local.py` end-to-end: hostile repo FAILS stage 0; hostile manifests repo FAILS stage 0+2 on 18 controls; clean repo blocks only on network/runner-dependent controls. |
| 7 | Workflow validation | PARTIAL | actionlint clean (3 workflows + deep-scan), bash -n + shellcheck clean on 28 composite actions, every local `uses:` resolves, every SHA pinned, real action steps executed end to end locally. NOT verified: artifact propagation between jobs, matrix fan-out, OIDC signing, CodeQL/ZAP actions — require a GitHub runner. |
| 8 | workflow_depot / delivery_control compatibility | CONTRACT ONLY | No access to your repos. The contract is: reusable workflow + `security-evidence-<sha>` artifact + `verify_evidence.py` (what delivery_control runs) + `external-identities.yml`. No new deployment or authorization system was created; promotion stays with your existing identity. |

## Minimal real-world execution required to close "UNVERIFIED"
1. Push this depot; run `scanner-qualification.yml` (`unit` job proves the suites on a runner incl. bubblewrap/cosign).
2. `dogfood` job proves the reusable workflow, matrix fan-out, artifact merge, gate, keyless signing.
3. One Node app repo with the thin caller proves CodeQL (GHAS), OSV/Trivy/Grype DB egress, ClamAV freshclam, ESLint sandbox on ubuntu-24.04 AppArmor settings.
4. One Rust and one Swift repo prove cargo-deny (cargo present) and SwiftLint on runner CPUs.
5. A preview environment with `dast_authorization_ref` proves ZAP/Schemathesis.
