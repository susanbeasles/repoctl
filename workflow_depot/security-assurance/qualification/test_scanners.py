#!/usr/bin/env python3
"""
Positive/negative detection tests for the custom scanners (deliverables 3, 15).
Run: python3 qualification/test_scanners.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, ".github", "scripts")


def run(script, *args):
    subprocess.run([sys.executable, os.path.join(S, script), *args], check=True, capture_output=True)


def rules(path):
    return {i["rule"] for i in json.load(open(path))["items"]}


def blocking(path):
    return [i for i in json.load(open(path))["items"] if i["severity"] in ("critical", "high")]


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    return cond


def main():
    d = tempfile.mkdtemp()
    subprocess.run([sys.executable, os.path.join(ROOT, "qualification", "fixtures.py"), d], check=True, capture_output=True)
    ok = True

    run("asset_scan.py", "--root", f"{d}/positive", "--out", f"{d}/a_pos.json")
    r = rules(f"{d}/a_pos.json")
    for expect in ["XML-DTD", "SVG-SCRIPT", "SVG-EVENT-HANDLER", "SVG-DANGEROUS-URI", "SVG-FOREIGNOBJECT", "SVG-ANIMATE-HREF",
                   "SVG-STYLE-URL", "SVG-EXTERNAL-REF", "IMG-TRAILING-DATA", "IMG-EMBEDDED-EXECUTABLE", "MAGIC-MISMATCH", "DISGUISED-EXECUTABLE"]:
        ok &= check(f"asset_scan detects {expect}", expect in r)
    run("asset_scan.py", "--root", f"{d}/negative", "--out", f"{d}/a_neg.json")
    ok &= check("asset_scan clean on negative", not blocking(f"{d}/a_neg.json"))

    run("ai_injection_scan.py", "--root", f"{d}/positive", "--out", f"{d}/i_pos.json")
    r = rules(f"{d}/i_pos.json")
    for expect in ["AI-UNICODE-TAGS", "AI-BIDI-OVERRIDE", "AI-HIDDEN-COMMENT-INSTRUCTION", "AI-IMAGE-EXFIL",
                   "AI-MCP-DESCRIPTION-INJECTION", "AI-MCP-FETCH-EXEC"]:
        ok &= check(f"ai_injection_scan detects {expect}", expect in r)
    run("ai_injection_scan.py", "--root", f"{d}/negative", "--out", f"{d}/i_neg.json")
    ok &= check("ai_injection_scan clean on negative", not blocking(f"{d}/i_neg.json"))

    run("git_forensics.py", "--repo", f"{d}/hostile-repo", "--out", f"{d}/g_pos.json")
    r = rules(f"{d}/g_pos.json")
    for expect in ["GIT-CONFIG", "SYMLINK-ESCAPE", "PATH-CONFUSABLE", "PATH-CASE-COLLISION", "GITATTR-FILTER",
                   "COMMIT-MSG-INJECTION", "CHECKOUT-TREE-MISMATCH", "BLOB-HIDDEN-EXECUTABLE", "BLOB-HIDDEN-ARCHIVE"]:
        ok &= check(f"git_forensics detects {expect}", expect in r)
    run("git_forensics.py", "--repo", f"{d}/clean-repo", "--out", f"{d}/g_neg.json")
    ok &= check("git_forensics clean on negative", not blocking(f"{d}/g_neg.json"))

    # normalizer smoke: every converter accepts an empty input without crashing
    for tool in ["gitleaks", "trufflehog", "semgrep", "shellcheck", "bandit", "osv", "trivy", "grype", "checkov", "zizmor", "npm-audit", "pip-audit", "zap"]:
        open(f"{d}/empty.json", "w").write("")
        run("normalize.py", "--tool", tool, "--in", f"{d}/empty.json", "--out", f"{d}/n.json")
        ok &= check(f"normalize {tool} handles empty input", json.load(open(f"{d}/n.json"))["items"] == [])

    # result.py: statuses needing a reason are rejected without one; secrets are scrubbed
    env = {**os.environ, "RESULTS_DIR": f"{d}/res", "GITHUB_SHA": "x" * 40, "GITHUB_REPOSITORY": "o/r"}
    p = subprocess.run([sys.executable, f"{S}/result.py", "--control", "T", "--status", "NOT_RUN"], env=env, capture_output=True)
    ok &= check("result.py rejects NOT_RUN without reason", p.returncode == 2)
    json.dump({"items": [{"severity": "high", "rule": "x", "path": "p", "message": "m", "Secret": "hunter2"}]}, open(f"{d}/f.json", "w"))
    subprocess.run([sys.executable, f"{S}/result.py", "--control", "T", "--status", "FAIL", "--findings-json", f"{d}/f.json"], env=env, check=True, capture_output=True)
    ok &= check("result.py scrubs secret values", "hunter2" not in open(f"{d}/res/T.json").read())

    # v2: ecosystem detection runs as real Python (regression for the shell-boolean interpolation bug)
    env2 = {**os.environ, "GITHUB_OUTPUT": f"{d}/gho"}
    subprocess.run([sys.executable, f"{S}/detect_ecosystems.py", "--repo", f"{d}/hostile-repo", "--out", f"{d}/eco.json"], env=env2, check=True, capture_output=True)
    eco = json.load(open(f"{d}/eco.json"))
    ok &= check("detect_ecosystems produces typed JSON booleans", eco["node"] is False and isinstance(eco["codeql_languages"], list))
    ok &= check("detect_ecosystems writes GITHUB_OUTPUT", "codeql_languages=" in open(f"{d}/gho").read())

    # v2: malformed scanner output can never become zero findings / PASS
    open(f"{d}/garbage.json", "w").write("this is not json {{{")
    p = subprocess.run([sys.executable, f"{S}/normalize.py", "--tool", "trivy", "--in", f"{d}/garbage.json", "--out", f"{d}/g.json"], capture_output=True)
    ok &= check("normalize exits non-zero on garbage", p.returncode == 3)
    ok &= check("normalize still writes a findings file with parse_error", json.load(open(f"{d}/g.json"))["parse_error"] is not None)
    cb = subprocess.run([sys.executable, f"{S}/count_blocking.py", f"{d}/g.json"], capture_output=True, text=True).stdout.strip()
    ok &= check("count_blocking reports ERR for parse_error", cb == "ERR")
    cb = subprocess.run([sys.executable, f"{S}/count_blocking.py", f"{d}/does-not-exist.json"], capture_output=True, text=True).stdout.strip()
    ok &= check("count_blocking reports ERR for missing file", cb == "ERR")

    # v2: PHI/secret scrub refuses egress
    open(f"{d}/phi.txt", "w").write('+patient = {"ssn":"123-45-6789"}\n')
    p = subprocess.run([sys.executable, f"{S}/phi_scrub.py", "--in", f"{d}/phi.txt", "--out", f"{d}/phi.json"], capture_output=True)
    ok &= check("phi_scrub refuses SSN", p.returncode == 1)
    open(f"{d}/ok.txt", "w").write("+const x = 1;\n")
    p = subprocess.run([sys.executable, f"{S}/phi_scrub.py", "--in", f"{d}/ok.txt", "--out", f"{d}/ok.json"], capture_output=True)
    ok &= check("phi_scrub passes clean diff", p.returncode == 0)
    p = subprocess.run([sys.executable, f"{S}/phi_scrub.py", "--in", f"{d}/ok.txt", "--out", f"{d}/ok2.json", "--gitleaks-rc", "2"], capture_output=True)
    ok &= check("phi_scrub refuses on gitleaks hit", p.returncode == 1)
    p = subprocess.run([sys.executable, f"{S}/ai_review_call.py", "--diff", f"{d}/ok.txt", "--results", f"{d}/res", "--out", f"{d}/o.json", "--model", "m",
                        "--endpoint", "https://evil.example/v1", "--receipt", f"{d}/r.json", "--approval", "X"], capture_output=True)
    ok &= check("ai_review_call refuses non-allow-listed endpoint", p.returncode == 2)

    shutil.rmtree(d)
    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
