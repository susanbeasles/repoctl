#!/usr/bin/env python3
"""
Verify an evidence bundle: every file listed in evidence-bundle.sha256 and every result/evidence
digest in evidence-manifest.json must match the bytes on disk; gate-decision.json must bind the
expected sha/repository; optional cosign verification of the bundle signature.

  verify_evidence.py --dir security-results [--sha X] [--repo o/r] [--cosign-identity-regexp R] [--cosign-bin cosign]
Exit 0 only if everything verifies. This is what delivery_control runs before promotion.
"""
import argparse, hashlib, json, os, subprocess, sys

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--dir", required=True); ap.add_argument("--sha", default=""); ap.add_argument("--repo", default="")
    ap.add_argument("--cosign-identity-regexp", default=""); ap.add_argument("--cosign-bin", default="cosign"); ap.add_argument("--require-signature", action="store_true")
    a = ap.parse_args(); d = a.dir; errs = []
    gate = None
    for cand in ("gate-all/gate-decision.json", "gate-decision.json"):
        if os.path.exists(os.path.join(d, cand)):
            gate = json.load(open(os.path.join(d, cand))); break
    if not gate: errs.append("gate-decision.json missing")
    else:
        if gate.get("decision") != "PASS": errs.append(f"gate decision is {gate.get('decision')}")
        if a.sha and gate.get("candidate", {}).get("sha") != a.sha: errs.append("gate decision bound to a different sha")
        if a.repo and gate.get("candidate", {}).get("repository") != a.repo: errs.append("gate decision bound to a different repository")
    man = None
    for cand in ("gate-all/evidence-manifest.json", "evidence-manifest.json"):
        if os.path.exists(os.path.join(d, cand)):
            man = json.load(open(os.path.join(d, cand))); break
    if not man: errs.append("evidence-manifest.json missing")
    else:
        for e in man.get("entries", []):
            rf = e["result_file"]; p = rf if os.path.isabs(rf) else os.path.join(d, os.path.basename(rf))
            if not os.path.exists(p): p = os.path.join(d, rf)
            if not os.path.exists(p): errs.append(f"result file missing: {rf}"); continue
            if sha(p) != e["sha256"]: errs.append(f"result file tampered: {rf}")
            for ev in e.get("evidence", []):
                if ev.get("missing"): continue
                ep = ev["path"] if os.path.isabs(ev["path"]) else os.path.join(d, ev["path"])
                if not os.path.exists(ep):
                    alt = os.path.join(d, "evidence", os.path.basename(ev["path"]))
                    ep = alt if os.path.exists(alt) else ep
                if not os.path.exists(ep): errs.append(f"evidence missing: {ev['path']}"); continue
                if sha(ep) != ev["sha256"]: errs.append(f"evidence tampered: {ev['path']}")
    sums = os.path.join(d, "evidence-bundle.sha256")
    if os.path.exists(sums):
        for line in open(sums):
            h, _, rel = line.rstrip("\n").partition("  ")
            p = os.path.join(d, rel.lstrip("./"))
            if not os.path.exists(p): errs.append(f"bundle file missing: {rel}")
            elif sha(p) != h: errs.append(f"bundle file tampered: {rel}")
    bundle = os.path.join(d, "evidence-bundle.tar.gz"); sig = os.path.join(d, "evidence-bundle.sigstore.json")
    if a.cosign_identity_regexp:
        if not (os.path.exists(bundle) and os.path.exists(sig)): errs.append("signature or bundle missing")
        else:
            r = subprocess.run([a.cosign_bin, "verify-blob", "--bundle", sig, "--certificate-identity-regexp", a.cosign_identity_regexp,
                                "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", bundle], capture_output=True, text=True)
            if r.returncode != 0: errs.append("cosign verify-blob failed: " + (r.stderr or r.stdout)[-300:])
    elif a.require_signature: errs.append("signature verification required but no identity supplied")
    print("\n".join("VERIFY-FAIL: " + e for e in errs) if errs else f"VERIFY-OK: {d} bound to {gate.get('candidate', {}).get('repository')}@{gate.get('candidate', {}).get('sha', '')[:12]}")
    sys.exit(1 if errs else 0)

if __name__ == "__main__":
    main()
