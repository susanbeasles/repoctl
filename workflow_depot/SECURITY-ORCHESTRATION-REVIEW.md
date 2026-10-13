# Security orchestration integration review

This import preserves the complete supplied security-assurance v3 module, including its original policies, rules, actions, qualification records and both binary Hypothesis caches. The owner confirms comprehensive testing on creation. The v3 completion matrix is the factual source for coverage; the older coverage/README tables are retained as historical source, not used to declare current gaps. Cache/artifact/archive and binary inspection are implemented. No scanners or gate controls were replaced, disabled or softened.

The root `.github/workflows/security-assurance.yml` is a workflow_call entrypoint. Its only adapter change materializes the unchanged module into the checkout layout expected by the original actions, once per job. No application caller, scheduled scan, root qualification trigger or public DAST target is activated by this import. `security-assurance-import.json` binds every original file to the verified archive; the base64 staging blob is not source.

## Existing implementation and integration gaps

| Requirement | Preserved implementation | Remaining integration work |
|---|---|---|
| SAST/SCA/malware/cache/pentest evidence | 28 actions, fail-closed policy, ecosystem detection, cache/binary forensics, signed external evidence | Pin the published entrypoint SHA and bind accepted candidate identity to consumers. External IAST/runtime/FIM/fuzz/formal producers remain evidence dependencies, not empty stubs. |
| CodeQL and own policy | Existing mandatory CodeQL action and owned gate policy | Advanced setup with pinned own query packs/config; eligibility-aware project profile requires review. Private-personal licensing is not solved by self-hosting CLI or silently substituting Semgrep. Qualys is out of scope per latest correction. |
| Quality profiles | Existing ecosystem tooling and test compatibility | Node/TypeScript defaults: ESLint plus appropriate tests, optionally Vitest; Python defaults: Ruff, type checker and pytest. Preserve compatible existing test runners. |
| Build/sourcemaps/SBOM | Source SBOM and evidence/attestation support; signed external image/build evidence | Build once on integration candidate in an isolated pinned runtime; bind SBOM and artifact digest. Sourcemaps are private artifacts subject to source-disclosure policy. |
| DAST/API/IAST | ZAP/Schemathesis and signed external-evidence contracts; missing applicable evidence blocks | Provision/use only approved isolated synthetic preview targets after build. No public/third-party scans are run here. |
| Agent PR review | Existing advisory opt-in AI review and egress controls | A pinned prebuilt/custom Claude/Codex reviewer container and project review policy; inspect before activation. Do not treat advisory output as promotion authority. |
| Release/deployment | Existing evidence bundle and cosign flow; prepared central dispatch/packager and controller | Draft release, protected app-owned tags, OIDC cosign, checksums and immutable artifact bundle linked to accepted integration evidence; main dispatch consumes these bytes without rebuild. |
| Signing/promotion/rulesets | Existing canonical repoctl and signer/controller sources | Reconcile private signer availability, app-only main updates, signed tip/integration-squash/release tags and reproducible rulesets. Do not activate or bypass rules during import. |

## Proposed sequence for review

1. Preserve/import this module and verify only layout changes. Review the pinned entrypoint, current policy profile and CodeQL entitlement/profile decision.
2. Define project profiles and source admission. Source inspection precedes executing project tooling; dependency installation and restored caches are inspected using the existing controls.
3. Build the exact signed integration candidate once inside the qualified runtime. Run artifact/cache/supply-chain analysis, then DAST/API against its approved isolated preview and ingest applicable signed external IAST/pentest evidence. The DAG must account for dynamic tests needing a built artifact.
4. Apply the owned versioned fail-closed policy to complete scanner results, provenance and project-required quality checks. Missing/error/unconfigured mandatory evidence must not pass. GitHub carries checks and jobs; it is not policy authority.
5. Run approved pinned-container agent review, then app-controlled main promotion with race/current-main checks and signed integration evidence. Keep feature tips, signed integration squash and release identity linked.
6. Prepare the release's checksums, SBOM, private sourcemaps, attestations and bundle; dispatch central deployment from accepted main using the immutable integration artifact. Verify release/deployment receipts, then commission rulesets through a separately reviewed change.

This is a proposed integration design/sequence, not permission to execute the larger rewiring. Terraform's latest PR-plan/main-apply rule does not alter application integration-only validation. Permanent signer custody and bootstrap remain separate; no new secrets, identities, ruleset mutations, paid infrastructure, scans or deployment occurred here.
