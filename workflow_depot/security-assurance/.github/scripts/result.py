#!/usr/bin/env python3
"""
Normalized control-result emitter. Every security control in the pipeline
writes exactly one result file through this script, so the gate can reason
about controls uniformly and nothing can be "silently green".

Usage:
  result.py --control SAST-SEMGREP --status PASS --tool semgrep --tool-version 1.180.0 \
            [--tool-digest sha256:...] [--ruleset REV] [--db-revision REV] \
            [--reason "..."] [--findings-json findings.json] \
            [--evidence path ...] [--duration-s 12.3] [--coverage "..."]

Environment (populated by the workflow):
  RESULTS_DIR, GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_REF, GITHUB_RUN_ID,
  GITHUB_RUN_ATTEMPT, POLICY_REVISION, INPUT_TREE_DIGEST, CORRELATION_ID

Statuses (exactly one): PASS FAIL INCONCLUSIVE NOT_APPLICABLE NOT_RUN TOOL_FAILURE POLICY_UNAVAILABLE
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import sys

STATUSES = {"PASS", "FAIL", "INCONCLUSIVE", "NOT_APPLICABLE", "NOT_RUN", "TOOL_FAILURE", "POLICY_UNAVAILABLE"}
MAX_ITEMS = 200          # bounded output size
MAX_FIELD_CHARS = 2000   # per-string cap; prevents log/evidence flooding
SECRET_KEYS = {"secret", "secretparts", "raw", "rawv2", "match", "value", "token", "password", "key", "line_text", "snippet", "extradata"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scrub(obj):
    """Redact anything that looks like raw secret material and cap sizes."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k.lower() in SECRET_KEYS and v:
                out[k] = "redacted:sha256:" + hashlib.sha256(json.dumps(v, sort_keys=True).encode()).hexdigest()[:16]
            else:
                out[k] = scrub(v)
        return out
    if isinstance(obj, list):
        return [scrub(x) for x in obj[:MAX_ITEMS]]
    if isinstance(obj, str) and len(obj) > MAX_FIELD_CHARS:
        return obj[:MAX_FIELD_CHARS] + f"...[truncated {len(obj) - MAX_FIELD_CHARS} chars]"
    return obj


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--control", required=True)
    p.add_argument("--domain", default="")
    p.add_argument("--status", required=True, choices=sorted(STATUSES))
    p.add_argument("--tool", default="")
    p.add_argument("--tool-version", default="")
    p.add_argument("--tool-digest", default="")
    p.add_argument("--ruleset", default="")
    p.add_argument("--db-revision", default="")
    p.add_argument("--reason", default="")
    p.add_argument("--coverage", default="")
    p.add_argument("--findings-json", default="")
    p.add_argument("--evidence", nargs="*", default=[])
    p.add_argument("--duration-s", type=float, default=0.0)
    p.add_argument("--confidence", default="deterministic", choices=["deterministic", "heuristic", "model-generated"])
    a = p.parse_args()

    if a.status in {"NOT_APPLICABLE", "NOT_RUN", "TOOL_FAILURE", "POLICY_UNAVAILABLE", "INCONCLUSIVE"} and not a.reason:
        print(f"::error::{a.control}: status {a.status} requires --reason", file=sys.stderr)
        sys.exit(2)

    results_dir = os.environ.get("RESULTS_DIR", "security-results")
    os.makedirs(results_dir, exist_ok=True)

    findings = {"total": 0, "by_severity": {}, "items": []}
    if a.findings_json and os.path.exists(a.findings_json):
        with open(a.findings_json) as f:
            raw = json.load(f)
        items = raw.get("items", raw if isinstance(raw, list) else [])
        by_sev = {}
        for it in items:
            sev = str(it.get("severity", "unknown")).lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
        findings = {"total": len(items), "by_severity": by_sev, "items": scrub(items)}

    evidence = []
    for path in a.evidence:
        if os.path.isfile(path):
            evidence.append({"path": path, "sha256": sha256_file(path), "bytes": os.path.getsize(path)})
        else:
            evidence.append({"path": path, "missing": True})

    now = dt.datetime.now(dt.timezone.utc).isoformat()
    rec = {
        "schema_version": 1,
        "control_id": a.control,
        "domain": a.domain,
        "status": a.status,
        "reason": a.reason,
        "confidence": a.confidence,
        "coverage": a.coverage,
        "tool": {
            "name": a.tool, "version": a.tool_version, "digest": a.tool_digest,
            "ruleset_revision": a.ruleset, "db_revision": a.db_revision,
        },
        "candidate": {
            "repository": os.environ.get("GITHUB_REPOSITORY", ""),
            "sha": os.environ.get("GITHUB_SHA", ""),
            "ref": os.environ.get("GITHUB_REF", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "input_tree_digest": os.environ.get("INPUT_TREE_DIGEST", ""),
        },
        "policy_revision": os.environ.get("POLICY_REVISION", ""),
        "correlation_id": os.environ.get("CORRELATION_ID", ""),
        "findings": findings,
        "evidence": evidence,
        "resources": {"duration_s": a.duration_s},
        "finished_at": now,
    }
    out = os.path.join(results_dir, f"{a.control}.json")
    with open(out, "w") as f:
        json.dump(rec, f, indent=2, sort_keys=True)
    print(f"[result] {a.control}: {a.status} ({findings['total']} findings) -> {out}")
    # Expose to the workflow without failing the step; the gate decides.
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"status={a.status}\n")


if __name__ == "__main__":
    main()
