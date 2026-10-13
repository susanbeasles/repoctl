#!/usr/bin/env python3
"""Adversarial qualification: evidence tampering, scanner compromise (digest mismatch), failed tool install,
cache poisoning fixtures, sandbox boundary, external-evidence signature gate, false-PASS via forged results."""
import json, os, shutil, subprocess, sys, tempfile, hashlib, yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); S = os.path.join(ROOT, ".github", "scripts")
ok = True
def check(n, c):
    global ok; print(("PASS " if c else "FAIL ") + n); ok = ok and c
def py(script, *a, env=None, inp=None):
    return subprocess.run([sys.executable, os.path.join(S, script), *a], capture_output=True, text=True, env={**os.environ, **(env or {})}, input=inp)

d = tempfile.mkdtemp()
subprocess.run([sys.executable, os.path.join(ROOT, "qualification", "fixtures.py"), d], check=True, capture_output=True)

# ---- 1. scanner compromise: registry digest mismatch refuses install ----
reg = yaml.safe_load(open(os.path.join(ROOT, "policy", "tool-registry.yml")))
reg["tools"]["shellcheck"]["sha256"] = "0" * 64
bad = os.path.join(d, "bad-registry.yml"); yaml.safe_dump(reg, open(bad, "w"))
r = py("install_tool.py", "--registry", bad, "--tool", "shellcheck", "--dest", os.path.join(d, "t"))
check("install_tool refuses digest mismatch (exit 3)", r.returncode == 3 and not os.path.exists(os.path.join(d, "t", "bin", "shellcheck")))
r = py("install_tool.py", "--registry", bad, "--tool", "not-a-tool", "--dest", os.path.join(d, "t"))
check("install_tool refuses unregistered tool", r.returncode == 2)

# ---- 2. failed tool install => ensure_results emits TOOL_FAILURE with reason ----
rd = os.path.join(d, "res"); env = {"RESULTS_DIR": rd, "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": "o/r"}
py("ensure_results.py", "SAST-SHELLCHECK SEC-SECRETS-GITLEAKS", "failure", env=env)
rec = json.load(open(os.path.join(rd, "SAST-SHELLCHECK.json")))
check("ensure_results fills missing control as TOOL_FAILURE", rec["status"] == "TOOL_FAILURE" and "without producing" in rec["reason"])

# ---- 3. evidence tampering detected by verify_evidence ----
ed = os.path.join(d, "ev"); os.makedirs(os.path.join(ed, "evidence"))
json.dump({"items": []}, open(os.path.join(ed, "evidence", "x.findings.json"), "w"))
py("result.py", "--control", "SCA-OSV", "--status", "PASS", "--tool", "t", "--evidence", os.path.join(ed, "evidence", "x.findings.json"), env={"RESULTS_DIR": ed, "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": "o/r"})
pol = os.path.join(ROOT, "policy", "release-policy.yml")
subprocess.run([sys.executable, os.path.join(S, "gate.py"), "--policy", pol, "--results", ed, "--stage", "2", "--sha", "a" * 40, "--repo", "o/r", "--out", os.path.join(ed, "gate-all")], capture_output=True)
# make it a passing bundle artificially: only SCA-OSV present, so decision FAIL; verify checks digests regardless
r = py("verify_evidence.py", "--dir", ed, "--sha", "a" * 40, "--repo", "o/r")
before = r.stdout
open(os.path.join(ed, "evidence", "x.findings.json"), "a").write(" ")
r2 = py("verify_evidence.py", "--dir", ed, "--sha", "a" * 40, "--repo", "o/r")
check("verify_evidence detects evidence tampering", "evidence tampered" in r2.stdout and "evidence tampered" not in before)
open(os.path.join(ed, "SCA-OSV.json"), "a").write("\n")
r3 = py("verify_evidence.py", "--dir", ed, "--sha", "a" * 40, "--repo", "o/r")
check("verify_evidence detects result-file tampering", "result file tampered" in r3.stdout)
r4 = py("verify_evidence.py", "--dir", ed, "--sha", "b" * 40, "--repo", "o/r")
check("verify_evidence rejects wrong sha", "different sha" in r4.stdout)

# ---- 4. forged result for an unknown control cannot buy coverage; forged PASS for a real control with wrong sha is NOT_RUN ----
fd = os.path.join(d, "forge"); os.makedirs(fd)
json.dump({"control_id": "MAL-CLAMAV", "status": "PASS", "candidate": {"sha": "c" * 40, "repository": "o/r"}, "findings": {"by_severity": {}, "items": []}, "finished_at": "2099-01-01T00:00:00+00:00", "tool": {}}, open(os.path.join(fd, "MAL-CLAMAV.json"), "w"))
r = subprocess.run([sys.executable, os.path.join(S, "gate.py"), "--policy", pol, "--results", fd, "--stage", "0", "--sha", "a" * 40, "--repo", "o/r", "--out", os.path.join(fd, "g")], capture_output=True, text=True)
dec = json.load(open(os.path.join(fd, "g", "gate-decision.json"))); row = [c for c in dec["controls"] if c["control"] == "MAL-CLAMAV"][0]
check("forged PASS bound to another sha is NOT_RUN and blocks", row["verdict"] == "NOT_RUN" and r.returncode == 1)

# ---- 5. cache poisoning fixtures are detected; clean caches pass ----
def cache(root, kind, lock=""):
    out = os.path.join(d, "c.json"); py("cache_inspect.py", "--root", root, "--kind", kind, "--out", out, *(["--lockfile", lock] if lock else [])); return {i["rule"] for i in json.load(open(out))["items"] if i["severity"] in ("critical", "high")}
check("cacache blob tamper detected", "CACACHE-CONTENT-MISMATCH" in cache(f"{d}/caches/npm-cacache", "npm-cacache"))
nm = cache(f"{d}/caches/project/node_modules", "node_modules", f"{d}/caches/project/package-lock.json")
check("node_modules drift/plant/escape detected", {"NODE_MODULES-VERSION-MISMATCH", "NODE_MODULES-NOT-IN-LOCKFILE", "NODE_MODULES-RC-FILE", "NODE_MODULES-BIN-ESCAPE", "HIDDEN-EXECUTABLE"} <= nm)
check("tarball traversal/link-escape/embedded-ELF/rc detected", {"ARCHIVE-TRAVERSAL", "ARCHIVE-LINK-ESCAPE", "ARCHIVE-EMBEDDED-EXECUTABLE", "NPM-TARBALL-RC-FILE"} <= cache(f"{d}/caches/artifacts", "artifacts"))
check("wheel RECORD mismatch detected", "WHEEL-RECORD-MISMATCH" in cache(f"{d}/caches/pip-cache", "pip-cache"))
check("clean caches have no blocking findings", not cache(f"{d}/caches/clean-artifacts", "artifacts") and not cache(f"{d}/caches/clean-pip-cache", "pip-cache"))

# ---- 6. binary forensics / supply chain / shell detect fixtures ----
out = os.path.join(d, "b.json"); py("binary_inspect.py", "--root", f"{d}/binaries", "--out", out); rules = {i["rule"] for i in json.load(open(out))["items"]}
check("binary forensics detects RWX, packing, packer marker, embedded ELF, wasm host imports", {"ELF-RWX-SEGMENT", "ELF-PACKED-SEGMENT", "BIN-PACKER-MARKER", "BIN-EMBEDDED-ELF", "WASM-HOST-IMPORTS"} <= rules)
for eco, expect in (("node", {"NPM-LIFECYCLE-NETWORK-OR-EVAL", "NPMRC-INLINE-TOKEN", "TYPOSQUAT-CANDIDATE", "NPM-NON-REGISTRY-DEP"}), ("rust", {"RUST-BUILD-SCRIPT-ACTIVE", "CARGO-LINKER-RUNNER-OVERRIDE", "CARGO-SOURCE-REPLACEMENT", "TYPOSQUAT-CANDIDATE", "RUST-GIT-DEP"}),
                    ("swift", {"SWIFT-BINARY-TARGET", "SWIFT-BRANCH-DEP", "SWIFT-UNSAFE-FLAGS", "SWIFT-INSECURE-STORAGE"}), ("python", {"PIP-INDEX-OVERRIDE", "TYPOSQUAT-CANDIDATE", "SETUP-PY-ACTIVE-CODE"})):
    out = os.path.join(d, f"s-{eco}.json"); py("supply_chain.py", "--repo", f"{d}/manifests/{eco}", "--out", out); rules = {i["rule"] for i in json.load(open(out))["items"]}
    check(f"supply_chain {eco} detects {sorted(expect)}", expect <= rules)
out = os.path.join(d, "sh.json"); py("shell_audit.py", "--root", f"{d}/manifests/shell", "--out", out); items = json.load(open(out))["items"]
check("shell_audit detects curl|sh, eval, rm -rf $VAR, reverse shell, anti-forensics", {"SH-FETCH-PIPE-SHELL", "SH-EVAL-VARIABLE", "SH-RM-RF-UNQUOTED-VAR", "SH-REVERSE-SHELL", "SH-HISTORY-TAMPER"} <= {i["rule"] for i in items})
check("shell_audit clean script has no blocking findings", not [i for i in items if i["path"] == "ok.sh" and i["severity"] in ("critical", "high")])

# ---- 7. sandbox boundary (skipped if bwrap unavailable) ----
if shutil.which("bwrap"):
    sb = os.path.join(d, "sb"); os.makedirs(f"{sb}/src"); open(f"{sb}/src/a", "w").write("x"); os.makedirs(f"{sb}/out")
    r = subprocess.run([os.path.join(S, "sandbox_exec.sh"), "--src", f"{sb}/src", "--out", f"{sb}/out", "--timeout", "20", "--", "/bin/sh", "-c",
                        'echo "T=[$GITHUB_TOKEN][$HOME]"; touch /work/x 2>/dev/null && echo WRITABLE; ls /home/claude >/dev/null 2>&1 && echo DEPOT-VISIBLE; cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d " "; ln -s /etc/passwd /out/esc; echo done > /out/ok'],
                       capture_output=True, text=True, env={**os.environ, "GITHUB_TOKEN": "leak"})
    check("sandbox scrubs env, ro source, no depot, only lo", "T=[][/home/sandbox]" in r.stdout and "WRITABLE" not in r.stdout and "DEPOT-VISIBLE" not in r.stdout and "eth" not in r.stdout and "lo" in r.stdout)
    check("sandbox strips symlinks from out", not os.path.lexists(f"{sb}/out/esc") and os.path.exists(f"{sb}/out/ok"))
    r = subprocess.run([os.path.join(S, "sandbox_exec.sh"), "--src", f"{sb}/src", "--out", f"{sb}/out", "--timeout", "2", "--", "/bin/sh", "-c", "sleep 20"], capture_output=True)
    check("sandbox enforces timeout (124)", r.returncode == 124)
else:
    print("SKIP sandbox tests (bwrap not installed)")

# ---- 8. external evidence: unsigned / unknown identity rejected; key-signed accepted (needs cosign) ----
cosign = shutil.which("cosign") or os.path.join(os.environ.get("RUNNER_TEMP", "/tmp/rt"), "tools", "bin", "cosign")
if os.path.exists(cosign):
    xd = os.path.join(d, "ext"); os.makedirs(xd)
    json.dump({"control_id": "FIM-BASELINE", "status": "PASS", "candidate": {"sha": "a" * 40, "repository": "o/r"}, "findings": {"by_severity": {}, "items": []}, "finished_at": "2026-10-12T00:00:00+00:00", "tool": {"name": "fim"}}, open(f"{xd}/FIM-BASELINE.json", "w"))
    subprocess.run(["tar", "-czf", f"{xd}/external-results.tar.gz", "-C", xd, "FIM-BASELINE.json"], check=True)
    subprocess.run([cosign, "generate-key-pair"], cwd=xd, capture_output=True, env={**os.environ, "COSIGN_PASSWORD": ""})
    subprocess.run([cosign, "sign-blob", "--yes", "--key", f"{xd}/cosign.key", "--output-signature", f"{xd}/b.json", "--use-signing-config=false", "--tlog-upload=false", "--new-bundle-format=false", f"{xd}/external-results.tar.gz"], capture_output=True, env={**os.environ, "COSIGN_PASSWORD": ""})
    ids_none = os.path.join(d, "ids0.yml"); open(ids_none, "w").write("identities: []\n")
    r = py("external_evidence.py", "--tarball", f"{xd}/external-results.tar.gz", "--bundle", f"{xd}/b.json", "--identities", ids_none, "--results-dir", f"{xd}/r0", "--cosign", cosign)
    check("external evidence rejected with no trusted identities", r.returncode == 1 and not os.path.exists(f"{xd}/r0/FIM-BASELINE.json"))
    ids = os.path.join(d, "ids.yml"); yaml.safe_dump({"identities": [{"name": "lab", "type": "key", "public_key_path": f"{xd}/cosign.pub"}]}, open(ids, "w"))
    r = py("external_evidence.py", "--tarball", f"{xd}/external-results.tar.gz", "--bundle", f"{xd}/b.json", "--identities", ids, "--results-dir", f"{xd}/r1", "--cosign", cosign, env={"COSIGN_PASSWORD": ""})
    acc = os.path.exists(f"{xd}/r1/FIM-BASELINE.json") and json.load(open(f"{xd}/r1/FIM-BASELINE.json")).get("ingested_from") == "external-evidence"
    check("external evidence accepted with trusted key and marked ingested", r.returncode == 0 and acc)
    if acc:
        subprocess.run(["tar", "-czf", f"{xd}/t2.tar.gz", "-C", xd, "FIM-BASELINE.json"], check=True); open(f"{xd}/t2.tar.gz", "ab").write(b"x")
        r = py("external_evidence.py", "--tarball", f"{xd}/t2.tar.gz", "--bundle", f"{xd}/b.json", "--identities", ids, "--results-dir", f"{xd}/r2", "--cosign", cosign)
        check("tampered external bundle rejected", r.returncode == 1)
        # gate: ingested external result is evaluated as a real gate under ci-baseline
        gd = os.path.join(d, "gext"); os.makedirs(gd); shutil.copy(f"{xd}/r1/FIM-BASELINE.json", gd)
        bad = json.load(open(f"{gd}/FIM-BASELINE.json")); bad["status"] = "FAIL"; json.dump(bad, open(f"{gd}/FIM-BASELINE.json", "w"))
        r = subprocess.run([sys.executable, os.path.join(S, "gate.py"), "--policy", pol, "--results", gd, "--stage", "2", "--sha", "a" * 40, "--repo", "o/r", "--out", f"{gd}/g"], capture_output=True, text=True)
        dec = json.load(open(f"{gd}/g/gate-decision.json")); row = [c for c in dec["controls"] if c["control"] == "FIM-BASELINE"][0]
        check("ingested external FAIL is gate-tier under ci-baseline", row["tier"] == "gate" and row["blocking"])
else:
    print("SKIP external-evidence tests (cosign not installed)")

shutil.rmtree(d); print("\nALL PASS" if ok else "\nFAILURES PRESENT"); sys.exit(0 if ok else 1)
