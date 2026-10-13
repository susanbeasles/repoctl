#!/usr/bin/env python3
"""
Stage 3 gate: evaluates every control in release-policy.yml against the
normalized result files. Default-deny, fail-closed.

  gate.py --policy policy/release-policy.yml --results security-results \
          --profile ci-baseline --stage all --sha <sha> --repo <owner/repo> \
          --out gate-out/

Exit 0 only when every gate-tier control is PASS or NOT_APPLICABLE(with reason).
Writes gate-decision.json, evidence-manifest.json (sha256 of every result and
evidence file) and summary.md.

Deliberately simple and dependency-light so it can itself be audited.
"""
import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("::error::PyYAML is required (preinstalled on GitHub-hosted runners)", file=sys.stderr)
    sys.exit(2)

OK_STATUSES = {"PASS", "NOT_APPLICABLE"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def schema_errors(rec):
    """Minimal structural validation; anything off-shape is a TOOL_FAILURE, not a crash and not a PASS."""
    errs = []
    if not isinstance(rec, dict):
        return ["not an object"]
    if rec.get("status") not in {"PASS", "FAIL", "INCONCLUSIVE", "NOT_APPLICABLE", "NOT_RUN", "TOOL_FAILURE", "POLICY_UNAVAILABLE"}:
        errs.append(f"status {rec.get('status')!r}")
    if not isinstance(rec.get("candidate"), dict):
        errs.append("candidate missing")
    f = rec.get("findings")
    if not isinstance(f, dict) or not isinstance(f.get("by_severity", {}), dict) or not isinstance(f.get("items", []), list):
        errs.append("findings malformed")
    elif any(not isinstance(v, int) or v < 0 for v in f.get("by_severity", {}).values()):
        errs.append("by_severity values must be non-negative ints")
    if not isinstance(rec.get("finished_at", ""), str):
        errs.append("finished_at not a string")
    return errs


def load_results(results_dir):
    out = {}
    for path in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
        try:
            with open(path) as f:
                rec = json.load(f)
        except Exception as e:  # malformed evidence is a failure, not a skip
            out[os.path.basename(path)] = {"status": "TOOL_FAILURE", "reason": f"unparseable result: {e}", "_path": path}
            continue
        cid = rec.get("control_id") or os.path.basename(path).removesuffix(".json")
        bad = schema_errors(rec)
        if bad:
            rec = {"control_id": cid, "status": "TOOL_FAILURE", "reason": "result schema invalid: " + "; ".join(bad),
                   "candidate": rec.get("candidate", {}) if isinstance(rec.get("candidate"), dict) else {}, "findings": {"by_severity": {}}}
        if cid in out:
            rec["status"] = "TOOL_FAILURE"
            rec["reason"] = f"duplicate result for {cid}"
        rec["_path"] = path
        out[cid] = rec
    return out


def effective_tier(ctrl, profile, rec=None):
    tier = ctrl.get("tier", "gate")
    if profile == "ci-baseline" and ctrl.get("unavailable_in_ci"):
        # A signed external result makes the control a real gate again; a POLICY_UNAVAILABLE placeholder stays report-tier.
        if rec and rec.get("ingested_from") == "external-evidence":
            return tier
        return "report"
    return tier


def evaluate_control(ctrl, rec, args, policy):
    """Return (verdict, detail). verdict in {PASS, NOT_APPLICABLE, FAIL, NOT_RUN, TOOL_FAILURE, ...}"""
    if rec is None:
        return "NOT_RUN", "no result file produced"
    status = rec.get("status", "NOT_RUN")
    detail = rec.get("reason", "")

    # Candidate binding: a result for the wrong commit is no result at all.
    if policy.get("require_candidate_match", True):
        cand = rec.get("candidate", {})
        if args.sha and cand.get("sha") != args.sha:
            return "NOT_RUN", f"result bound to sha {cand.get('sha', '')[:12]!r}, gate is {args.sha[:12]!r}"
        if args.repo and cand.get("repository") != args.repo:
            return "NOT_RUN", f"result bound to repository {cand.get('repository')!r}, gate is {args.repo!r}"

    # Freshness.
    max_age = policy.get("max_result_age_hours")
    if max_age and rec.get("finished_at"):
        try:
            fin = dt.datetime.fromisoformat(rec["finished_at"])
            age_h = (dt.datetime.now(dt.timezone.utc) - fin).total_seconds() / 3600
            if age_h > max_age:
                return "NOT_RUN", f"result is {age_h:.1f}h old (max {max_age}h)"
        except ValueError:
            return "TOOL_FAILURE", "unparseable finished_at"

    if status == "NOT_APPLICABLE" and not detail:
        return "TOOL_FAILURE", "NOT_APPLICABLE without a reason is not accepted"

    # Severity threshold: a PASS with findings above fail_on is a FAIL regardless
    # of what the tool's exit code said.
    fail_on = {s.lower() for s in ctrl.get("fail_on", [])}
    by_sev = {k.lower(): v for k, v in rec.get("findings", {}).get("by_severity", {}).items()}
    hits = {s: n for s, n in by_sev.items() if s in fail_on and n > 0}
    if status == "PASS" and hits:
        return "FAIL", f"findings at blocking severity: {hits}"
    if status == "FAIL" and not hits and fail_on:
        # Tool said FAIL but nothing at a blocking severity: keep FAIL (tool's
        # judgement wins; we never upgrade), note it for the operator.
        detail = (detail + " | tool reported FAIL; no findings at blocking severity").strip(" |")
    return status, detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--stage", default="all", help="'all' or comma-separated stage numbers from the policy, e.g. 0,2")
    ap.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    ap.add_argument("--out", default="gate-out")
    args = ap.parse_args()

    with open(args.policy) as f:
        policy = yaml.safe_load(f)
    profile = args.profile or policy.get("default_profile", "ci-baseline")
    policy_rev = sha256_file(args.policy)
    os.makedirs(args.out, exist_ok=True)

    controls = policy["controls"]
    if args.stage != "all":
        wanted = set()
        for st in args.stage.split(","):
            wanted |= set(policy["stages"][int(st)])
        controls = [c for c in controls if c["id"] in wanted]

    results = load_results(args.results)
    rows, blocking, manifest = [], [], []
    for ctrl in controls:
        cid = ctrl["id"]
        rec = results.get(cid)
        tier = effective_tier(ctrl, profile, rec)
        verdict, detail = evaluate_control(ctrl, rec, args, policy)
        is_block = tier == "gate" and verdict not in OK_STATUSES
        if is_block:
            blocking.append(cid)
        tool = rec.get("tool", {}) if rec else {}
        rows.append({
            "control": cid, "domain": ctrl.get("domain", ""), "tier": tier,
            "verdict": verdict, "blocking": is_block, "detail": detail,
            "tool": f"{tool.get('name', '')} {tool.get('version', '')}".strip(),
            "findings": (rec or {}).get("findings", {}).get("by_severity", {}),
        })
        if rec:
            manifest.append({"control": cid, "result_file": rec["_path"], "sha256": sha256_file(rec["_path"]),
                             "evidence": rec.get("evidence", [])})

    # Results on disk that the policy does not know about are suspicious: a
    # scanner emitting a control the policy never asked for could be an attempt
    # to look "covered". Record and surface them; never count them.
    unknown = sorted(set(results) - {c["id"] for c in policy["controls"]})

    decision = {
        "schema_version": 1,
        "decision": "FAIL" if blocking else "PASS",
        "profile": profile,
        "stage": args.stage,
        "policy_id": policy.get("policy_id"),
        "policy_revision": policy_rev,
        "candidate": {"repository": args.repo, "sha": args.sha,
                      "run_id": os.environ.get("GITHUB_RUN_ID", ""),
                      "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "")},
        "blocking_controls": blocking,
        "unknown_results": unknown,
        "controls": rows,
        "evaluated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    with open(os.path.join(args.out, "gate-decision.json"), "w") as f:
        json.dump(decision, f, indent=2, sort_keys=True)
    with open(os.path.join(args.out, "evidence-manifest.json"), "w") as f:
        json.dump({"policy_revision": policy_rev, "candidate": decision["candidate"], "entries": manifest},
                  f, indent=2, sort_keys=True)

    # Human summary (also written to the GitHub job summary when available).
    icon = {"PASS": "✅", "NOT_APPLICABLE": "➖", "FAIL": "❌", "NOT_RUN": "⛔", "TOOL_FAILURE": "💥",
            "POLICY_UNAVAILABLE": "🚫", "INCONCLUSIVE": "❓"}
    lines = [f"## Security gate: **{decision['decision']}** (profile `{profile}`, stage `{args.stage}`)",
             f"Candidate `{args.repo}@{args.sha[:12]}` · policy `{policy_rev[:12]}`", "",
             "| Control | Dom | Tier | Verdict | Tool | Findings | Detail |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        fx = ", ".join(f"{k}:{v}" for k, v in sorted(r["findings"].items())) or "-"
        lines.append(f"| `{r['control']}` | {r['domain']} | {r['tier']} | {icon.get(r['verdict'], '')} {r['verdict']}"
                     f"{' **BLOCKING**' if r['blocking'] else ''} | {r['tool'] or '-'} | {fx} | {r['detail'][:160]} |")
    if unknown:
        lines += ["", f"⚠️ Results present for controls not in policy (ignored): {', '.join(unknown)}"]
    lines += ["", f"Blocking: {', '.join(blocking) if blocking else 'none'}"]
    summary = "\n".join(lines)
    with open(os.path.join(args.out, "summary.md"), "w") as f:
        f.write(summary + "\n")
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(summary + "\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"decision={decision['decision']}\n")

    sys.exit(1 if blocking else 0)


if __name__ == "__main__":
    main()
