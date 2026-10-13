# Integration contract for workflow_depot / delivery_control

This depot never deploys, promotes, signs releases or approves. It produces evidence; your existing
`delivery_control` identity consumes it. Nothing here replaces that identity.

**Artifact**: `security-evidence-<sha>` (400-day retention) containing every `<CONTROL>.json`, `evidence/`,
`gate-all/gate-decision.json`, `gate-all/evidence-manifest.json`, `evidence-bundle.tar.gz`,
`evidence-bundle.sigstore.json`, `sbom.attestation.sigstore.json`, `candidate.json`.

**What delivery_control runs before promotion** (exact command, ships in this repo):
```
python3 .github/scripts/verify_evidence.py --dir security-evidence-<sha> --sha <sha> --repo <owner/repo> \
  --cosign-identity-regexp '^https://github.com/<ORG>/security-assurance/.github/workflows/security-assurance.yml@' --require-signature
```
Exit 0 ⇒ decision PASS, bound to that sha/repo, every result and evidence digest intact, bundle signature valid.

**External environments** (IAST, mobile lab, runtime Falco/FIM, threat hunting, fuzz VMs, formal verification,
image SBOM/provenance, cloud posture): write `<CONTROL>.json` in the `result.py` schema for this candidate sha,
tar them, sign with cosign (keyless identity or a key listed in `policy/external-identities.yml`), and pass the
paths via `external_evidence_tarball`/`external_evidence_bundle`. Verified results replace the
`POLICY_UNAVAILABLE` placeholders and are gate-tier under both profiles.

**Merging into an existing depot**: copy `.github/actions/*`, `.github/scripts/*`, `policy/`, `rules/`,
`qualification/` as-is; adapt `security-assurance.yml` to your checkout/artifact conventions (the only
coupling points are the `.security-depot/` checkout path and the `results-*` artifact pattern).
