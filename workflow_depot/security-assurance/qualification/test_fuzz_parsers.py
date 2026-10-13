#!/usr/bin/env python3
"""
FUZZ-PARSERS: Hypothesis-driven fuzzing of the pipeline's own parsers. Hostile input must never
crash a scanner (which would become TOOL_FAILURE, acceptable) in an uncaught way, and must never
make normalize.py report zero findings for non-empty garbage (false PASS). Emits a FUZZ-PARSERS
result into $RESULTS_DIR when run with --emit.
  python3 qualification/test_fuzz_parsers.py [--emit] [--examples 300]
"""
import json, os, subprocess, sys, tempfile, argparse
from hypothesis import given, settings, strategies as st, HealthCheck
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); S = os.path.join(ROOT, ".github", "scripts")
ap = argparse.ArgumentParser(); ap.add_argument("--emit", action="store_true"); ap.add_argument("--examples", type=int, default=200); A = ap.parse_args()
d = tempfile.mkdtemp(); stats = {"cases": 0, "crashes": []}
SET = settings(max_examples=A.examples, deadline=None, suppress_health_check=list(HealthCheck))

def run(script, *args):
    r = subprocess.run([sys.executable, os.path.join(S, script), *args], capture_output=True, text=True, timeout=60)
    stats["cases"] += 1
    if r.returncode not in (0, 3) or "Traceback" in r.stderr:
        stats["crashes"].append({"script": script, "rc": r.returncode, "err": r.stderr[-300:]})
    return r

svg_bits = st.sampled_from(["<svg", "<script>", "onload=", "javascript:", "<!DOCTYPE", "<!ENTITY", "xlink:href=", "data:image/svg+xml;base64,", "<foreignObject", "</svg>", "&#x3c;", "\u202e", "\U000E0041", "<set attributeName='href'", "<style>@import", ">" , "\"", "'", "\n"])

@SET
@given(st.lists(svg_bits | st.binary(max_size=64).map(lambda b: b.decode("latin-1")), max_size=60))
def fuzz_asset(parts):
    for name, data in (("x.svg", "".join(parts).encode("utf-8", "surrogateescape")), ("x.png", b"\x89PNG\r\n\x1a\n" + "".join(parts).encode("latin-1", "replace")), ("x.zip", b"PK\x03\x04" + "".join(parts).encode("latin-1", "replace")), ("x.ttf", b"\x00\x01\x00\x00" + "".join(parts).encode("latin-1", "replace"))):
        root = tempfile.mkdtemp(dir=d); open(os.path.join(root, name), "wb").write(data)
        r = run("asset_scan.py", "--root", root, "--out", os.path.join(root, "o.json"))
        assert os.path.exists(os.path.join(root, "o.json")), "asset_scan must always write output"

@SET
@given(st.binary(min_size=1, max_size=4096))
def fuzz_binary(data):
    root = tempfile.mkdtemp(dir=d)
    for magic in (b"\x7fELF\x02\x01\x01", b"\x7fELF\x01\x01\x01", b"MZ\x90\x00", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\x00asm\x01\x00\x00\x00"):
        open(os.path.join(root, magic[:2].hex()), "wb").write(magic + data)
    run("binary_inspect.py", "--root", root, "--out", os.path.join(root, "o.json"))
    assert os.path.exists(os.path.join(root, "o.json"))

@SET
@given(st.binary(min_size=1, max_size=2048))
def fuzz_cache(data):
    root = tempfile.mkdtemp(dir=d)
    open(os.path.join(root, "x.tgz"), "wb").write(b"\x1f\x8b" + data); open(os.path.join(root, "y.zip"), "wb").write(b"PK\x03\x04" + data); open(os.path.join(root, "z.whl"), "wb").write(b"PK\x03\x04" + data)
    run("cache_inspect.py", "--root", root, "--kind", "artifacts", "--out", os.path.join(root, "o.json"))
    assert os.path.exists(os.path.join(root, "o.json"))

@SET
@given(st.text(max_size=400), st.sampled_from(["gitleaks", "trufflehog", "semgrep", "shellcheck", "bandit", "osv", "trivy", "grype", "checkov", "zizmor", "npm-audit", "pip-audit", "zap"]))
def fuzz_normalize(text, tool):
    p = os.path.join(d, "n.in"); open(p, "w").write(text); out = os.path.join(d, "n.out")
    r = run("normalize.py", "--tool", tool, "--in", p, "--out", out)
    res = json.load(open(out))
    if text.strip() and r.returncode == 0:
        # exit 0 with non-empty input means it parsed as JSON/NDJSON; ensure it was valid JSON, never garbage-as-zero
        try: json.loads(text)
        except Exception:
            assert all(l.strip() == "" or json.loads(l) is not None for l in text.splitlines()), "garbage accepted as zero findings"
    if r.returncode == 3: assert res.get("parse_error"), "exit 3 must record parse_error"

@SET
@given(st.text(max_size=600))
def fuzz_injection(text):
    root = tempfile.mkdtemp(dir=d); open(os.path.join(root, "AGENTS.md"), "w", encoding="utf-8", errors="surrogateescape").write(text); open(os.path.join(root, ".mcp.json"), "w", errors="surrogateescape").write(text)
    run("ai_injection_scan.py", "--root", root, "--out", os.path.join(root, "o.json")); assert os.path.exists(os.path.join(root, "o.json"))

for f in (fuzz_asset, fuzz_binary, fuzz_cache, fuzz_normalize, fuzz_injection):
    f()
ok = not stats["crashes"]
print(f"[fuzz-parsers] {stats['cases']} cases, {len(stats['crashes'])} crashes -> {'PASS' if ok else 'FAIL'}")
for c in stats["crashes"][:5]: print("  CRASH", c)
if A.emit:
    ev = os.path.join(os.environ.get("RESULTS_DIR", "security-results"), "evidence"); os.makedirs(ev, exist_ok=True)
    json.dump({"items": [{"severity": "high", "rule": "PARSER-CRASH", "path": c["script"], "message": c["err"][-160:]} for c in stats["crashes"]], "cases": stats["cases"]}, open(os.path.join(ev, "fuzz-parsers.findings.json"), "w"))
    subprocess.run([sys.executable, os.path.join(S, "result.py"), "--control", "FUZZ-PARSERS", "--domain", "R", "--status", "PASS" if ok else "FAIL", "--tool", "hypothesis", "--tool-version", "6.169.0",
                    "--reason", f"{stats['cases']} fuzz cases over asset/binary/cache/normalize/injection parsers, {len(stats['crashes'])} crashes", "--findings-json", os.path.join(ev, "fuzz-parsers.findings.json"), "--evidence", os.path.join(ev, "fuzz-parsers.findings.json")], check=True)
sys.exit(0 if ok else 1)
