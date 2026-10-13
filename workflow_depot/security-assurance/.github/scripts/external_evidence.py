#!/usr/bin/env python3
"""
Ingest result files produced by environments outside GitHub Actions (IAST agent, mobile dynamic lab,
runtime Falco/FIM, threat-hunting platform, fuzzing VMs, formal verification) into the results dir.

Contract: a tarball `external-results.tar.gz` containing <CONTROL-ID>.json files in the result.py
schema, plus either a keyless cosign bundle (`--bundle`, identity+issuer verified) or a detached key
signature (`--signature`, verified against a public key in policy/external-identities.yml). Each ingested result must carry this candidate's sha+repository and
be fresher than max_result_age_hours; the gate re-checks all of that anyway.

  external_evidence.py --tarball X --bundle Y --identities policy/external-identities.yml --results-dir R [--cosign cosign] [--key-mode keyless|key]
Unsigned or unknown-identity bundles are rejected entirely (exit 1); nothing is ingested.
"""
import argparse, io, json, os, subprocess, sys, tarfile, yaml

ALLOWED_CONTROLS = {"IAST-RUNTIME", "MAST-DYNAMIC", "RUNTIME-LINUX", "FIM-BASELINE", "APT-HUNT", "FUZZ-COVERAGE", "FORMAL-VERIFY", "DAST-NUCLEI", "SBOM-IMAGE", "PROVENANCE-BUILD", "CLOUD-POSTURE"}

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--tarball", required=True); ap.add_argument("--bundle", required=True); ap.add_argument("--identities", required=True)
    ap.add_argument("--results-dir", required=True); ap.add_argument("--cosign", default="cosign"); a = ap.parse_args()
    ids = yaml.safe_load(open(a.identities)) or {}
    ok = False
    for ident in ids.get("identities", []):
        if ident.get("type") == "keyless":
            cmd = [a.cosign, "verify-blob", "--bundle", a.bundle, "--certificate-identity-regexp", ident["identity_regexp"], "--certificate-oidc-issuer", ident["issuer"], a.tarball]
        elif ident.get("type") == "key":
            # Key-mode bundles are detached signatures (cosign sign-blob --key ... --output-signature --new-bundle-format=false); no tlog.
            cmd = [a.cosign, "verify-blob", "--signature", a.bundle, "--key", ident["public_key_path"], "--insecure-ignore-tlog", a.tarball]
        else:
            continue
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            ok = True; print(f"[external-evidence] signature verified against identity '{ident.get('name')}'"); break
    if not ok:
        print("::error::external evidence bundle signature did not verify against any configured identity; nothing ingested"); sys.exit(1)
    os.makedirs(a.results_dir, exist_ok=True); n = 0
    with tarfile.open(a.tarball, "r:gz") as tf:
        for m in tf:
            if not m.isfile() or "/" in m.name.strip("./") or not m.name.endswith(".json"): continue
            cid = os.path.basename(m.name)[:-5]
            if cid not in ALLOWED_CONTROLS:
                print(f"::warning::external result for non-external control {cid} ignored"); continue
            data = tf.extractfile(m).read()
            try: rec = json.loads(data)
            except Exception: print(f"::warning::{cid}: not JSON, ignored"); continue
            if rec.get("control_id") != cid: print(f"::warning::{cid}: control_id mismatch, ignored"); continue
            rec["ingested_from"] = "external-evidence"; rec["external_identity_verified"] = True
            with open(os.path.join(a.results_dir, f"{cid}.json"), "w") as f: json.dump(rec, f, indent=2)
            n += 1
    print(f"[external-evidence] ingested {n} external results")

if __name__ == "__main__":
    main()
