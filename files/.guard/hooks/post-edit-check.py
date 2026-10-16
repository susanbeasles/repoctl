#!/usr/bin/env python3
"""PostToolUse on Write/Edit: run .guard/checks/on-edit for the touched file(s); exit 2 with output so the agent fixes it now."""
import json, os, re, subprocess, sys
try: d = json.load(sys.stdin)
except Exception: sys.exit(0)  # nothing to check; post-tool cannot undo anyway
root = os.environ.get("CLAUDE_PROJECT_DIR") or subprocess.run(["git","rev-parse","--show-toplevel"],capture_output=True,text=True).stdout.strip() or os.getcwd()
inp = d.get("tool_input") or d.get("toolArgs") or {}
if isinstance(inp, str):
    try: inp = json.loads(inp)
    except Exception: inp = {"command": inp}
paths = []
fp = inp.get("file_path") or inp.get("notebook_path") or inp.get("path")
if fp: paths.append(fp)
paths += [a or b for a, b in re.findall(r"^\*\*\* (?:Add|Update) File: (.+)$|^\*\*\* Move to: (.+)$", inp.get("command") or "", re.M)]
check = os.path.join(root, ".guard", "checks", "on-edit")
if not os.path.isfile(check):
    sys.stderr.write("agent-guard: missing required check script\n"); sys.exit(2)
bad = []
for p in paths:
    ap = p if os.path.isabs(p) else os.path.join(d.get("cwd") or root, p)
    if not os.path.isfile(ap): continue
    r = subprocess.run(["bash", check, ap], capture_output=True, text=True, cwd=root, timeout=110)
    if r.returncode != 0:
        bad.append(f"== {os.path.relpath(ap, root)} ==\n" + "\n".join((r.stdout + r.stderr).splitlines()[-60:]))
if bad:
    sys.stderr.write("AGENT-GUARD: checks failed. Fix these before doing anything else:\n" + "\n".join(bad) + "\n")
    sys.exit(2)
