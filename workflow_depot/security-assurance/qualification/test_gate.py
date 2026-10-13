#!/usr/bin/env python3
"""
Failure-injection tests for the gate (deliverable 14). Run: python3 qualification/test_gate.py

Each case builds a results directory, runs gate.py, and asserts the exit code
and blocking set. A green run here is the evidence that the gate fails closed.
"""
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, ".github", "scripts", "gate.py")
POLICY = os.path.join(ROOT, "policy", "release-policy.yml")
SHA, REPO = "a" * 40, "org/app"


def all_gate_controls(profile):
    pol = yaml.safe_load(open(POLICY))
    out = []
    for c in pol["controls"]:
        tier = c.get("tier", "gate")
        if profile == "ci-baseline" and c.get("unavailable_in_ci"):
            tier = "report"
        if tier == "gate":
            out.append(c["id"])
    return out, [c["id"] for c in pol["controls"]]


def result(cid, status="PASS", reason="", sha=SHA, repo=REPO, by_sev=None, age_h=0):
    fin = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=age_h)
    return {"schema_version": 1, "control_id": cid, "status": status, "reason": reason,
            "candidate": {"sha": sha, "repository": repo}, "tool": {"name": "t", "version": "1"},
            "findings": {"total": sum((by_sev or {}).values()), "by_severity": by_sev or {}, "items": []},
            "evidence": [], "finished_at": fin.isoformat()}


def run(results, profile="ci-baseline", stage="all"):
    d = tempfile.mkdtemp()
    rd = os.path.join(d, "results")
    os.makedirs(rd)
    for r in results:
        with open(os.path.join(rd, f"{r['control_id']}.json"), "w") as f:
            json.dump(r, f)
    p = subprocess.run([sys.executable, GATE, "--policy", POLICY, "--results", rd, "--profile", profile,
                        "--stage", stage, "--sha", SHA, "--repo", REPO, "--out", os.path.join(d, "out")],
                       capture_output=True, text=True)
    dec = json.load(open(os.path.join(d, "out", "gate-decision.json")))
    shutil.rmtree(d)
    return p.returncode, dec


def full_pass(profile):
    gate_ids, all_ids = all_gate_controls(profile)
    res = []
    for cid in all_ids:
        if cid in gate_ids:
            res.append(result(cid))
        else:
            res.append(result(cid, "POLICY_UNAVAILABLE", "not executable in CI"))
    return res


def test(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    return cond


def main():
    ok = True
    # 1. Complete, all-PASS set promotes (sanity).
    rc, d = run(full_pass("ci-baseline"))
    ok &= test("all gate controls PASS -> gate PASS", rc == 0 and d["decision"] == "PASS")

    # 2. One missing gate control -> NOT_RUN -> FAIL.
    res = [r for r in full_pass("ci-baseline") if r["control_id"] != "SCA-OSV"]
    rc, d = run(res)
    ok &= test("missing SCA-OSV -> NOT_RUN blocks", rc == 1 and d["blocking_controls"] == ["SCA-OSV"])

    # 3. TOOL_FAILURE never passes.
    res = full_pass("ci-baseline")
    res = [result("MAL-CLAMAV", "TOOL_FAILURE", "clamscan crashed") if r["control_id"] == "MAL-CLAMAV" else r for r in res]
    rc, d = run(res)
    ok &= test("TOOL_FAILURE blocks", rc == 1 and "MAL-CLAMAV" in d["blocking_controls"])

    # 4. PASS status but findings at blocking severity -> FAIL.
    res = full_pass("ci-baseline")
    res = [result("SAST-SEMGREP", "PASS", by_sev={"high": 2}) if r["control_id"] == "SAST-SEMGREP" else r for r in res]
    rc, d = run(res)
    ok &= test("PASS with high findings -> FAIL", rc == 1 and "SAST-SEMGREP" in d["blocking_controls"])

    # 5. NOT_APPLICABLE without reason is rejected.
    res = full_pass("ci-baseline")
    res = [result("DAST-ZAP", "NOT_APPLICABLE", "") if r["control_id"] == "DAST-ZAP" else r for r in res]
    rc, d = run(res)
    ok &= test("NOT_APPLICABLE without reason blocks", rc == 1 and "DAST-ZAP" in d["blocking_controls"])

    # 6. NOT_APPLICABLE with reason is accepted.
    res = full_pass("ci-baseline")
    res = [result("DAST-ZAP", "NOT_APPLICABLE", "no authorized target supplied") if r["control_id"] == "DAST-ZAP" else r for r in res]
    rc, d = run(res)
    ok &= test("NOT_APPLICABLE with reason passes", rc == 0)

    # 7. Result bound to another commit is treated as absent.
    res = full_pass("ci-baseline")
    res = [result("SEC-SECRETS-GITLEAKS", sha="b" * 40) if r["control_id"] == "SEC-SECRETS-GITLEAKS" else r for r in res]
    rc, d = run(res)
    ok &= test("wrong-SHA result blocks", rc == 1 and "SEC-SECRETS-GITLEAKS" in d["blocking_controls"])

    # 8. Stale result is treated as absent.
    res = full_pass("ci-baseline")
    res = [result("SBOM-SOURCE", age_h=48) if r["control_id"] == "SBOM-SOURCE" else r for r in res]
    rc, d = run(res)
    ok &= test("stale result (48h) blocks", rc == 1 and "SBOM-SOURCE" in d["blocking_controls"])

    # 9. Strict profile: POLICY_UNAVAILABLE controls block.
    rc, d = run(full_pass("ci-baseline"), profile="strict")
    ok &= test("strict profile: POLICY_UNAVAILABLE blocks", rc == 1 and "IAST-RUNTIME" in d["blocking_controls"])

    # 10. Unknown control results are ignored (cannot buy coverage).
    res = full_pass("ci-baseline") + [result("TOTALLY-MADE-UP")]
    rc, d = run(res)
    ok &= test("unknown control ignored and surfaced", rc == 0 and d["unknown_results"] == ["TOTALLY-MADE-UP"])

    # 11. AI-REVIEW can never flip the decision either way.
    res = [r for r in full_pass("ci-baseline") if r["control_id"] != "SCA-OSV"] + [result("AI-REVIEW", "PASS")]
    rc, d = run(res)
    ok &= test("AI-REVIEW PASS cannot rescue a missing gate control", rc == 1)

    # 12. Stage-scoped evaluation only considers that stage.
    res = [result(c) for c in yaml.safe_load(open(POLICY))["stages"][0]]
    rc, d = run(res, stage="0")
    ok &= test("stage 0 evaluation with only stage-0 results passes", rc == 0)

    # 13. Schema-invalid result is TOOL_FAILURE, not a crash and not a PASS.
    res = full_pass("ci-baseline")
    res = [{**result("SCA-OSV"), "findings": {"by_severity": "nope"}} if r["control_id"] == "SCA-OSV" else r for r in res]
    rc, d = run(res)
    row = [c for c in d["controls"] if c["control"] == "SCA-OSV"][0]
    ok &= test("schema-invalid result -> TOOL_FAILURE blocks", rc == 1 and row["verdict"] == "TOOL_FAILURE")

    # 14. Multi-stage selection.
    res = [result(c) for c in yaml.safe_load(open(POLICY))["stages"][0] + yaml.safe_load(open(POLICY))["stages"][2]]
    res = [result(c, "POLICY_UNAVAILABLE", "n/a") if c in ("IAST-RUNTIME","MAST-DYNAMIC","RUNTIME-LINUX","FIM-BASELINE","APT-HUNT","FUZZ-COVERAGE","FORMAL-VERIFY") else result(c) for c in yaml.safe_load(open(POLICY))["stages"][0] + yaml.safe_load(open(POLICY))["stages"][2]]
    rc, d = run(res, stage="0,2")
    ok &= test("stage '0,2' evaluation passes with only those stages present", rc == 0)

    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
