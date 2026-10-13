#!/usr/bin/env python3
"""
Local end-to-end executor. Runs the depot's composite actions exactly as written in their
action.yml (same bash, same scripts, same policy) against a checkout, resolving GitHub
expressions (${{ inputs.* }}, ${{ steps.*.outputs.* }}, ${{ github.action_path }},
${{ runner.temp }}), recursively executing local `uses:` steps, and skipping third-party
`uses:` (CodeQL, ZAP) with a recorded reason. Then it runs the gate.

  run_local.py --repo <checkout> --out <dir> [--profile ci-baseline] [--stage0-only] [--skip NAME,...]

This is NOT GitHub Actions: it proves the actions' shell, tools, normalisers, result schema
and gate logic cooperate end to end. actionlint + a real runner still verify the workflow
file, artifact propagation and OIDC signing.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTIONS = os.path.join(ROOT, ".github", "actions")


class Ctx:
    def __init__(self, workspace, results, temp, env):
        self.workspace, self.results, self.temp, self.env = workspace, results, temp, env
        self.log = []


def resolve(expr, inputs, steps, action_path, ctx):
    def sub(m):
        e = m.group(1).strip()
        if e.startswith("inputs."):
            return str(inputs.get(e[7:], ""))
        if e == "github.action_path":
            return action_path
        if e == "runner.temp":
            return ctx.temp
        if e == "job.status":
            return "success"
        sm = re.match(r"steps\.([\w-]+)\.outputs\.([\w-]+)", e)
        if sm:
            return steps.get(sm.group(1), {}).get(sm.group(2), "")
        # inputs.x == 'true' && 'a' || 'b'
        tm = re.match(r"inputs\.(\w+)\s*==\s*'([^']*)'\s*&&\s*'([^']*)'\s*\|\|\s*'([^']*)'", e)
        if tm:
            return tm.group(3) if str(inputs.get(tm.group(1), "")) == tm.group(2) else tm.group(4)
        return ""
    return re.sub(r"\$\{\{(.*?)\}\}", sub, expr)


def cond(expr, inputs, steps, ctx):
    if not expr:
        return True
    e = expr.strip()
    m = re.match(r"inputs\.(\w+)\s*(==|!=)\s*'([^']*)'$", e)
    if m:
        v = str(inputs.get(m.group(1), ""))
        return (v == m.group(3)) if m.group(2) == "==" else (v != m.group(3))
    m = re.match(r"steps\.([\w-]+)\.outputs\.([\w-]+)\s*==\s*'([^']*)'$", e)
    if m:
        return steps.get(m.group(1), {}).get(m.group(2), "") == m.group(3)
    if "&&" in e:
        return all(cond(p, inputs, steps, ctx) for p in e.split("&&"))
    m = re.match(r"steps\.([\w-]+)\.outcome\s*==\s*'success'$", e)
    if m:
        return steps.get(m.group(1), {}).get("__outcome", "") == "success"
    return True


def run_action(name, inputs, ctx, depth=0):
    path = os.path.join(ACTIONS, name)
    spec = yaml.safe_load(open(os.path.join(path, "action.yml")))
    steps = {}
    outputs = {}
    for i, st in enumerate(spec["runs"]["steps"]):
        sid = st.get("id", f"s{i}")
        if not cond(st.get("if", ""), inputs, steps, ctx):
            steps[sid] = {"__outcome": "skipped"}
            continue
        if "uses" in st:
            u = st["uses"]
            if u.startswith("./.security-depot/.github/actions/"):
                sub = u.rsplit("/", 1)[1]
                sub_inputs = {k: resolve(str(v), inputs, steps, path, ctx) for k, v in (st.get("with") or {}).items()}
                out = run_action(sub, sub_inputs, ctx, depth + 1)
                steps[sid] = {**out, "__outcome": "success"}
            else:
                ctx.log.append(f"{'  ' * depth}SKIP third-party uses: {u} (needs GitHub runner)")
                steps[sid] = {"__outcome": "skipped-external"}
            continue
        script = resolve(st["run"], inputs, steps, path, ctx)
        gh_out = tempfile.NamedTemporaryFile("w", delete=False, suffix=".out").name
        gh_env = tempfile.NamedTemporaryFile("w", delete=False, suffix=".env").name
        env = {**os.environ, **ctx.env, "GITHUB_OUTPUT": gh_out, "GITHUB_ENV": gh_env, "GITHUB_PATH": os.path.join(ctx.temp, "path"),
               "RUNNER_TEMP": ctx.temp, "RESULTS_DIR": ctx.results, "GITHUB_ACTION_PATH": path}
        env["PATH"] = os.path.join(ctx.temp, "tools", "bin") + ":" + env["PATH"]
        for k, v in (st.get("env") or {}).items():
            env[k] = resolve(str(v), inputs, steps, path, ctx)
        wd = resolve(st.get("working-directory", ctx.workspace), inputs, steps, path, ctx)
        r = subprocess.run(["bash", "-e", "-c", script], cwd=wd, env=env, capture_output=True, text=True)
        tail = (r.stdout + r.stderr)[-1500:]
        ctx.log.append(f"{'  ' * depth}{name}/{sid}: rc={r.returncode}\n{tail}")
        outs = {}
        for line in open(gh_out):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                outs[k] = v
        for line in open(gh_env):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                ctx.env[k] = v
        steps[sid] = {**outs, "__outcome": "success" if r.returncode == 0 else "failure"}
        if r.returncode != 0 and depth == 0:
            ctx.log.append(f"  !! step failed (continuing; gate will see missing/failed results)")
    for k, v in (spec.get("outputs") or {}).items():
        outputs[k] = resolve(str(v.get("value", "")), inputs, steps, path, ctx)
    return outputs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--profile", default="ci-baseline")
    ap.add_argument("--skip", default="")
    ap.add_argument("--stages", default="0,2")
    a = ap.parse_args()
    skip = set(filter(None, a.skip.split(",")))
    out = os.path.abspath(a.out)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    ws = os.path.join(out, "workspace")
    os.makedirs(ws)
    src = os.path.join(ws, "src")
    subprocess.run(["git", "clone", "-q", a.repo, src], check=True)
    os.symlink(ROOT, os.path.join(ws, ".security-depot"))
    results = os.path.join(out, "security-results")
    temp = os.path.join(out, "temp")
    os.makedirs(temp)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=src, capture_output=True, text=True).stdout.strip()
    tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=src, capture_output=True, text=True).stdout.strip()
    pol = subprocess.run(["sha256sum", os.path.join(ROOT, "policy", "release-policy.yml")], capture_output=True, text=True).stdout.split()[0]
    ctx = Ctx(ws, results, temp, {"GITHUB_SHA": sha, "GITHUB_REPOSITORY": "local/fixture", "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ID": "local",
                                   "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push", "POLICY_REVISION": pol, "INPUT_TREE_DIGEST": tree, "CORRELATION_ID": "local-1",
                                   "HOME": os.path.join(temp, "home")})
    os.makedirs(ctx.env["HOME"], exist_ok=True)
    det = run_action("detect-ecosystems", {"source_path": "src"}, ctx)
    eco = json.loads(det.get("matrix") or "{}")
    plan = [
        ("git-forensics", {"source_path": "src"}), ("secrets-scan", {"source_path": "src"}),
        ("malware-scan", {"source_path": "src", "rules_path": ".security-depot/rules/yara", "allow_freshclam": "false"}),
        ("asset-scan", {"source_path": "src"}), ("ai-injection-scan", {"source_path": "src"}), ("binary-forensics", {"source_path": "src"}),
        ("supply-chain", {"source_path": "src", "base_ref": ""}),
        ("sast-shellcheck", {"source_path": "src", "applicable": str(eco.get("shell", False)).lower()}),
    ]
    if "2" in a.stages.split(","):
        plan += [
            ("sast-semgrep", {"source_path": "src", "rules_path": "", "use_registry": "false"}),
            ("sast-ecosystem", {"source_path": "src", "ecosystems": json.dumps(eco)}),
            ("sast-rust", {"source_path": "src", "applicable": str(eco.get("rust", False)).lower()}),
            ("sast-swift", {"source_path": "src", "applicable": str(eco.get("swift", False)).lower()}),
            ("sbom-generate", {"source_path": "src"}),
            ("iac-scan", {"source_path": "src", "rego_policy_path": ""}),
            ("cache-policy", {"source_path": "src", "cache_mode": "none"}),
            ("cache-content", {"specs": f"{src}:generic", "rules_path": ".security-depot/rules/yara"}),
            ("dast-zap", {"target_url": "", "authorization_ref": "", "web_app_detected": str(eco.get("web_app", False)).lower()}),
            ("api-schemathesis", {"source_path": "src", "schema_path": "", "target_url": "", "authorization_ref": "", "api_detected": str(eco.get("openapi", False) or eco.get("web_app", False)).lower()}),
            ("declare-unavailable", {}),
        ]
    for name, inputs in plan:
        if name in skip:
            ctx.log.append(f"SKIP {name} (requested)")
            continue
        try:
            outs = run_action(name, inputs, ctx)
            if name == "sbom-generate" and "sca-scan" not in skip and "2" in a.stages:
                run_action("sca-scan", {"source_path": "src", "sbom_path": outs.get("cyclonedx", "")}, ctx)
        except Exception as e:
            ctx.log.append(f"!! {name} raised {type(e).__name__}: {e}")
    # merge codeql placeholder + gate
    subprocess.run([sys.executable, os.path.join(ROOT, ".github", "scripts", "ensure_results.py"),
                    "SAST-CODEQL" if not eco.get("codeql_languages") else " ".join(f"SAST-CODEQL-{l}" for l in eco["codeql_languages"]), "local-no-codeql"],
                   env={**os.environ, "RESULTS_DIR": results, **ctx.env}, capture_output=True)
    gate_out = os.path.join(results, "gate-local")
    r = subprocess.run([sys.executable, os.path.join(ROOT, ".github", "scripts", "gate.py"), "--policy", os.path.join(ROOT, "policy", "release-policy.yml"),
                        "--results", results, "--profile", a.profile, "--stage", a.stages, "--sha", sha, "--repo", "local/fixture", "--out", gate_out],
                       capture_output=True, text=True, env={**os.environ, **ctx.env})
    with open(os.path.join(out, "run.log"), "w") as f:
        f.write("\n".join(ctx.log))
    print(r.stdout[-6000:])
    print(f"gate exit={r.returncode}; log: {out}/run.log")
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
