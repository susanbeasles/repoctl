#!/usr/bin/env python3
"""Stop: run .guard/checks/on-stop; if it fails, send the agent back once. Honors stop_hook_active so it cannot loop.
This is a convenience, not the gate: CI is the gate."""
import json, os, subprocess, sys
try: d = json.load(sys.stdin)
except Exception: sys.exit(0)
if d.get("stop_hook_active"): sys.exit(0)
root = os.environ.get("CLAUDE_PROJECT_DIR") or subprocess.run(["git","rev-parse","--show-toplevel"],capture_output=True,text=True).stdout.strip() or os.getcwd()
check = os.path.join(root, ".guard", "checks", "on-stop")
if not os.path.isfile(check):
    sys.stderr.write("agent-guard: missing required check script\n"); sys.exit(2)
r = subprocess.run(["bash", check], capture_output=True, text=True, cwd=root, timeout=590)
if r.returncode != 0:
    sys.stderr.write("AGENT-GUARD: the completion gate failed. You are not done. Fix the failures below, then stop again.\n"
                     + "\n".join((r.stdout + r.stderr).splitlines()[-80:]) + "\n")
    sys.exit(2)
