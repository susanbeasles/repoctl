#!/usr/bin/env python3
"""Print the number of findings at the given severities, or ERR if the findings file is missing/malformed/has a parse_error."""
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    if d.get("parse_error"):
        print("ERR"); sys.exit(0)
    sevs = set((sys.argv[2] if len(sys.argv) > 2 else "critical,high").split(","))
    print(sum(1 for i in d["items"] if str(i.get("severity", "")).lower() in sevs))
except Exception:
    print("ERR")
