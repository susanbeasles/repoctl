#!/usr/bin/env python3
"""
Normalize a scanner's native output into {"items":[{severity, rule, path, message, ...}]}.

  normalize.py --tool gitleaks --in gitleaks.json --out findings.json

Severity vocabulary: critical | high | medium | low | info | unknown.
Raw secret values are never copied; result.py additionally scrubs by key name.
"""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET


def cvss_to_sev(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def load_json(path):
    with open(path) as f:
        txt = f.read().strip()
    if not txt:
        return None
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        pass
    recs = []  # NDJSON: every non-empty line must be a JSON object; otherwise the output is garbage, not "no findings"
    for l in txt.splitlines():
        if l.strip():
            recs.append(json.loads(l))
    if not recs:
        raise ValueError("non-empty output is neither JSON nor NDJSON")
    return recs


def gitleaks(d):
    return [{"severity": "high", "rule": r.get("RuleID", ""), "path": r.get("File", ""), "line": r.get("StartLine"),
             "message": r.get("Description", ""), "fingerprint": r.get("Fingerprint", "")[:80], "commit": r.get("Commit", "")[:12]}
            for r in (d or [])]


def trufflehog(d):
    out = []
    for r in (d or []):
        meta = r.get("SourceMetadata", {}).get("Data", {})
        loc = meta.get("Git") or meta.get("Filesystem") or {}
        out.append({"severity": "critical" if r.get("Verified") else "medium", "rule": r.get("DetectorName", ""),
                    "path": loc.get("file", ""), "line": loc.get("line"), "commit": str(loc.get("commit", ""))[:12],
                    "message": "verified live credential" if r.get("Verified") else "unverified candidate secret"})
    return out


def semgrep(d):
    m = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return [{"severity": m.get(r.get("extra", {}).get("severity", ""), "unknown"), "rule": r.get("check_id", ""),
             "path": r.get("path", ""), "line": r.get("start", {}).get("line"),
             "message": r.get("extra", {}).get("message", "")[:300],
             "cwe": r.get("extra", {}).get("metadata", {}).get("cwe", "")}
            for r in (d or {}).get("results", [])]


def shellcheck(d):
    m = {"error": "high", "warning": "medium", "info": "low", "style": "info"}
    return [{"severity": m.get(r.get("level"), "unknown"), "rule": f"SC{r.get('code')}", "path": r.get("file", ""),
             "line": r.get("line"), "message": r.get("message", "")} for r in (d or [])]


def bandit(d):
    return [{"severity": r.get("issue_severity", "").lower(), "confidence": r.get("issue_confidence", "").lower(),
             "rule": r.get("test_id", ""), "path": r.get("filename", ""), "line": r.get("line_number"),
             "message": r.get("issue_text", ""), "cwe": (r.get("issue_cwe") or {}).get("id")} for r in (d or {}).get("results", [])]


def osv(d):
    out = []
    for res in (d or {}).get("results", []):
        src = res.get("source", {}).get("path", "")
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            maxsev = {}
            for g in pkg.get("groups", []):
                for vid in g.get("ids", []):
                    maxsev[vid] = g.get("max_severity")
            for v in pkg.get("vulnerabilities", []):
                sev = cvss_to_sev(maxsev.get(v.get("id")))
                if sev == "unknown":
                    sev = str(v.get("database_specific", {}).get("severity", "unknown")).lower()
                out.append({"severity": sev, "rule": v.get("id", ""), "path": src,
                            "package": f"{p.get('ecosystem', '')}:{p.get('name', '')}@{p.get('version', '')}",
                            "message": v.get("summary", "")[:200], "aliases": v.get("aliases", [])[:5]})
    return out


def trivy(d):
    out = []
    for res in (d or {}).get("Results", []):
        tgt = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            out.append({"severity": v.get("Severity", "unknown").lower(), "rule": v.get("VulnerabilityID", ""), "path": tgt,
                        "package": f"{v.get('PkgName', '')}@{v.get('InstalledVersion', '')}", "fixed": v.get("FixedVersion", ""),
                        "message": v.get("Title", "")[:200]})
        for m in res.get("Misconfigurations", []) or []:
            out.append({"severity": m.get("Severity", "unknown").lower(), "rule": m.get("ID", ""), "path": tgt,
                        "line": (m.get("CauseMetadata") or {}).get("StartLine"), "message": m.get("Title", "")[:200]})
        for s in res.get("Secrets", []) or []:
            out.append({"severity": s.get("Severity", "high").lower(), "rule": s.get("RuleID", ""), "path": tgt,
                        "line": s.get("StartLine"), "message": s.get("Title", "")})
    return out


def grype(d):
    return [{"severity": m.get("vulnerability", {}).get("severity", "unknown").lower(), "rule": m.get("vulnerability", {}).get("id", ""),
             "package": f"{m.get('artifact', {}).get('name', '')}@{m.get('artifact', {}).get('version', '')}",
             "path": ";".join(l.get("path", "") for l in m.get("artifact", {}).get("locations", [])[:1]),
             "message": (m.get("vulnerability", {}).get("description") or "")[:200]} for m in (d or {}).get("matches", [])]


HIGH_IAC = re.compile(r"(public|0\.0\.0\.0|\*|wildcard|unencrypted|encrypt|secret|password|privileged|root|admin|"
                      r"no.?auth|allow all|logging.*disabled|mfa|host network|docker\.sock)", re.I)


def checkov(d):
    out = []
    blocks = d if isinstance(d, list) else [d]
    for b in blocks:
        for r in (b or {}).get("results", {}).get("failed_checks", []):
            sev = (r.get("severity") or "").lower() or ("high" if HIGH_IAC.search(r.get("check_name", "")) else "medium")
            out.append({"severity": sev, "rule": r.get("check_id", ""), "path": r.get("file_path", ""),
                        "line": (r.get("file_line_range") or [None])[0], "resource": r.get("resource", ""),
                        "message": r.get("check_name", "")})
    return out


def zizmor(d):
    out = []
    for r in (d or []):
        det = r.get("determinations", {})
        sev = det.get("severity", "unknown").lower()
        sev = {"informational": "info"}.get(sev, sev)
        loc = (r.get("locations") or [{}])[0].get("symbolic", {})
        out.append({"severity": sev, "confidence": det.get("confidence", "").lower(), "rule": r.get("ident", ""),
                    "path": loc.get("key", {}).get("path", "") if isinstance(loc.get("key"), dict) else str(loc.get("key", "")),
                    "message": r.get("desc", "")})
    return out


def npm_audit(d):
    return [{"severity": v.get("severity", "unknown"), "rule": "npm-audit", "package": f"{name}@{v.get('range', '')}",
             "path": "package-lock.json", "message": "; ".join(str(x.get("title", x)) if isinstance(x, dict) else str(x) for x in v.get("via", [])[:3])[:200],
             "fix_available": bool(v.get("fixAvailable"))} for name, v in (d or {}).get("vulnerabilities", {}).items()]


def pip_audit(d):
    out = []
    for dep in (d or {}).get("dependencies", []):
        for v in dep.get("vulns", []):
            out.append({"severity": "medium", "rule": v.get("id", ""), "package": f"{dep.get('name')}@{dep.get('version')}",
                        "path": "requirements", "message": (v.get("description") or "")[:200], "fix": v.get("fix_versions", [])})
    return out


def zap(d):
    m = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    out = []
    for site in (d or {}).get("site", []):
        for a in site.get("alerts", []):
            out.append({"severity": m.get(str(a.get("riskcode")), "unknown"), "rule": a.get("pluginid", ""),
                        "path": site.get("@name", ""), "message": a.get("name", ""), "cwe": a.get("cweid"),
                        "instances": len(a.get("instances", []))})
    return out


def clamav_text(path):
    out = []
    with open(path, errors="replace") as f:
        for line in f:
            if line.rstrip().endswith(" FOUND"):
                p, sig = line.rsplit(":", 1)
                out.append({"severity": "critical", "rule": sig.strip().removesuffix(" FOUND"), "path": p.strip(), "message": "signature match"})
    return out


def yarax_text(path):
    out = []
    with open(path, errors="replace") as f:
        for line in f:
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and not line.startswith(("warning", "error", "[")):
                rule, p = parts
                sev = "critical" if "eicar" in rule.lower() or rule.lower().startswith(("mal_", "malware")) else "high"
                out.append({"severity": sev, "rule": rule, "path": p, "message": "YARA-X rule match"})
    return out


def junit_failures(path):
    out = []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return out
    for tc in root.iter("testcase"):
        for kind in ("failure", "error"):
            for f in tc.findall(kind):
                out.append({"severity": "high", "rule": tc.get("name", ""), "path": tc.get("classname", ""),
                            "message": (f.get("message") or "")[:300]})
    return out


CONVERTERS = {"gitleaks": gitleaks, "trufflehog": trufflehog, "semgrep": semgrep, "shellcheck": shellcheck, "bandit": bandit,
              "osv": osv, "trivy": trivy, "grype": grype, "checkov": checkov, "zizmor": zizmor, "npm-audit": npm_audit,
              "pip-audit": pip_audit, "zap": zap}
TEXT_CONVERTERS = {"clamav": clamav_text, "yarax": yarax_text, "junit": junit_failures}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True, choices=sorted(CONVERTERS) + sorted(TEXT_CONVERTERS))
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    err = None
    try:
        items = TEXT_CONVERTERS[a.tool](a.inp) if a.tool in TEXT_CONVERTERS else CONVERTERS[a.tool](load_json(a.inp))
    except FileNotFoundError:
        items, err = [], "scanner produced no output file"
    except Exception as e:  # malformed output is a tool failure, never an empty PASS
        items, err = [], f"unparseable scanner output: {type(e).__name__}: {str(e)[:200]}"
    with open(a.out, "w") as f:  # ALWAYS written so callers can rely on it
        json.dump({"items": items, "parse_error": err}, f, indent=2)
    print(f"[normalize] {a.tool}: {len(items)} findings" + (f" PARSE_ERROR: {err}" if err else ""))
    sys.exit(3 if err else 0)


if __name__ == "__main__":
    main()
