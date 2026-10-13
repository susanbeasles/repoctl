#!/usr/bin/env python3
"""Emit TOOL_FAILURE for every expected control id that has no result file. Used by the ensure-results action and tests."""
import os, subprocess, sys
def main():
    results = os.environ.get("RESULTS_DIR", "security-results"); os.makedirs(results, exist_ok=True)
    expected = sys.argv[1].split(); status = sys.argv[2] if len(sys.argv) > 2 else "unknown"; n = 0
    for c in expected:
        if not os.path.exists(os.path.join(results, f"{c}.json")):
            subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "result.py"), "--control", c, "--status", "TOOL_FAILURE", "--tool", "unknown",
                            "--reason", f"job ended ({status}) without producing a result for {c}; likely tool install/digest failure or step error - see job log"], check=True); n += 1
    print(f"[ensure-results] filled {n} missing results")
if __name__ == "__main__":
    main()
