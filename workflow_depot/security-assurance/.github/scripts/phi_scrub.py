#!/usr/bin/env python3
"""Pre-egress scrub for the AI reviewer payload. Exit 1 (refuse to send) on any secret or PHI-pattern hit.
Patterns are conservative on purpose: a false refusal costs an advisory review; a false send costs a HIPAA incident."""
import argparse, json, re, sys

PATTERNS = {
    "ssn": r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    "mrn_label": r"\b(MRN|medical record (no|number)|patient id)\b\s*[:#]?\s*\w{4,}",
    "dob_label": r"\b(DOB|date of birth)\b\s*[:#]?\s*\d{1,4}[-/]\d{1,2}[-/]\d{1,4}",
    "npi": r"\bNPI\b\s*[:#]?\s*\d{10}\b",
    "icd10_dense": r"(\b[A-TV-Z]\d{2}(\.\d{1,4})?\b[\s,;]+){5,}",
    "email_dense": r"([\w.+-]+@[\w-]+\.[\w.]+[\s,;]+){5,}",
    "phone_dense": r"(\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}[\s,;]+){5,}",
    "hl7": r"^MSH\|\^~\\&\|",
    "fhir_patient": r'"resourceType"\s*:\s*"(Patient|Observation|Encounter|Condition)"',
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--in", dest="inp", required=True); ap.add_argument("--out", required=True); ap.add_argument("--gitleaks-rc", type=int, default=0)
    a = ap.parse_args()
    txt = open(a.inp, errors="replace").read()
    hits = [{"pattern": k, "count": n} for k, p in PATTERNS.items() if (n := len(re.findall(p, txt, re.I | re.M)))]
    if a.gitleaks_rc == 2:
        hits.append({"pattern": "gitleaks-secret", "count": "see ai-review.scrub.gitleaks.json"})
    json.dump({"bytes": len(txt.encode()), "hits": hits, "refused": bool(hits)}, open(a.out, "w"), indent=2)
    print(f"[phi-scrub] {len(txt)} chars, {len(hits)} hit classes -> {'REFUSE' if hits else 'ok'}")
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
