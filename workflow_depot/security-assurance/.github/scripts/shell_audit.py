#!/usr/bin/env python3
"""
Shell security audit for bash/sh/zsh scripts, sourced files and inline
scripts in CI/Makefiles/package.json. Complements ShellCheck (which is about
correctness) with security semantics.

  shell_audit.py --root <dir> --out findings.json
"""
import argparse
import json
import os
import re

SHEBANG = re.compile(rb"^#!\s*(/usr/bin/env\s+)?(bash|sh|zsh|ksh|dash)\b")
RULES = [
    ("critical", "SH-FETCH-PIPE-SHELL", r"\b(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", "remote content piped into a shell"),
    ("critical", "SH-FETCH-EVAL", r"\beval\s+[\"']?\$\((curl|wget)\b", "eval of fetched content"),
    ("high", "SH-EVAL-VARIABLE", r"\beval\s+[\"']?\$\{?[A-Za-z_]", "eval of a variable (command injection sink)"),
    ("high", "SH-RM-RF-UNQUOTED-VAR", r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+\$\{?[A-Za-z_][A-Za-z0-9_]*\}?(/|\s|$)", "rm -rf with an unquoted variable path (empty var => rm -rf /)"),
    ("high", "SH-SOURCE-REMOTE", r"\b(source|\.)\s+<\((curl|wget)", "sourcing remote content"),
    ("high", "SH-SOURCE-VARIABLE", r"^\s*(source|\.)\s+\$", "sourcing a path from a variable"),
    ("high", "SH-SUDO-NOPASSWD-WRITE", r"(NOPASSWD|/etc/sudoers)", "sudoers manipulation"),
    ("high", "SH-CHMOD-777", r"\bchmod\s+(-R\s+)?(777|a\+rwx|o\+w)\b", "world-writable permissions"),
    ("high", "SH-SETUID", r"\bchmod\s+(-R\s+)?[ug]\+s\b|\bchmod\s+[42]7[0-7][0-7]\b", "setuid/setgid bit set"),
    ("high", "SH-DEV-TCP", r"/dev/(tcp|udp)/", "bash network device (reverse shell idiom)"),
    ("high", "SH-REVERSE-SHELL", r"\b(nc|ncat|netcat)\b[^\n]*-e\s+/bin/(ba)?sh|bash\s+-i\s*>&\s*/dev/tcp", "reverse shell"),
    ("high", "SH-BASE64-EXEC", r"base64\s+(-d|--decode)[^\n|]*\|\s*(ba)?sh|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64", "decode-and-execute"),
    ("high", "SH-CRON-PERSISTENCE", r"(crontab\s+-|/etc/cron\.|systemctl\s+enable|/etc/rc\.local|\.bashrc|\.profile)", "persistence mechanism written"),
    ("high", "SH-SSH-KEY-WRITE", r"authorized_keys", "ssh authorized_keys manipulation"),
    ("high", "SH-HISTORY-TAMPER", r"(unset\s+HISTFILE|HISTSIZE=0|history\s+-c|shred\s)", "anti-forensics"),
    ("medium", "SH-NO-STRICT-MODE", None, "script lacks set -e/-u/-o pipefail"),
    ("medium", "SH-UNQUOTED-CMD-SUBST-ARG", r"\b(rm|mv|cp|chmod|chown)\s+[^\n\"']*\$\([^)]*\)", "unquoted command substitution in a destructive command"),
    ("medium", "SH-TMP-PREDICTABLE", r"(>|<|\s)/tmp/[A-Za-z0-9_.-]+(\s|$)", "predictable /tmp path (symlink race); use mktemp"),
    ("medium", "SH-SECRET-IN-ARG", r"(--password|--token|-p\s*['\"]?[^\s'\"]{6,}|password=)[^\n]*", "secret passed on the command line (visible in ps/history)"),
    ("medium", "SH-ENV-SECRET-ECHO", r"\becho\b[^\n]*\$\{?[A-Z_]*(TOKEN|SECRET|PASSWORD|KEY)[A-Z_]*\}?", "secret echoed to stdout/log"),
    ("medium", "SH-INSECURE-DOWNLOAD", r"\b(curl|wget)\b[^\n]*\s(-k|--insecure|--no-check-certificate)\b|\bcurl\b[^\n]*\shttp://", "TLS verification disabled or plaintext download"),
    ("low", "SH-ZSH", None, "zsh script: ShellCheck does not analyse zsh"),
]


def strict_mode(text):
    return bool(re.search(r"set\s+-[a-zA-Z]*[eu]|set\s+-o\s+(errexit|nounset|pipefail)|^\s*#\s*shellcheck\s+disable=SC2317", text, re.M))


def scan_text(text, rel, F, is_zsh=False, inline=False):
    for sev, rule, pat, msg in RULES:
        if pat is None:
            continue
        for m in re.finditer(pat, text, re.M):
            line = text.count("\n", 0, m.start()) + 1
            F.append({"severity": sev, "rule": rule, "path": rel, "line": line, "message": msg, "excerpt": m.group(0)[:120]})
    if not inline and not strict_mode(text) and len(text.splitlines()) > 5:
        F.append({"severity": "medium", "rule": "SH-NO-STRICT-MODE", "path": rel, "message": "script lacks set -e/-u/-o pipefail"})
    if is_zsh:
        F.append({"severity": "low", "rule": "SH-ZSH", "path": rel, "message": "zsh script: ShellCheck does not analyse zsh"})
    if re.search(r"[\u202a-\u202e\u2066-\u2069\u200b-\u200d]", text):
        F.append({"severity": "high", "rule": "SH-INVISIBLE-UNICODE", "path": rel, "message": "bidi/zero-width characters in script"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    F = []
    n = 0
    for dp, dns, fns in os.walk(a.root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules", "target", ".venv", "venv")]
        for fn in fns:
            p = os.path.join(dp, fn)
            if os.path.islink(p) or os.path.getsize(p) > 2_000_000:
                continue
            rel = os.path.relpath(p, a.root)
            with open(p, "rb") as f:
                head = f.read(256)
            ext = os.path.splitext(fn)[1].lower()
            is_shell = ext in (".sh", ".bash", ".zsh", ".ksh", ".bashrc", ".zshrc", ".profile") or bool(SHEBANG.match(head)) or fn in (".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile", ".zshenv")
            if is_shell:
                text = open(p, errors="replace").read()
                scan_text(text, rel, F, is_zsh=(ext == ".zsh" or b"zsh" in head[:40] or fn.startswith(".zsh")))
                n += 1
            elif fn in ("Makefile", "Justfile", "Dockerfile") or fn.endswith((".mk", "Dockerfile")):
                text = open(p, errors="replace").read()
                scan_text(text, rel, F, inline=True)
            elif fn == "package.json":
                try:
                    for k, v in json.load(open(p)).get("scripts", {}).items():
                        scan_text(v, f"{rel}#scripts.{k}", F, inline=True)
                except Exception:
                    pass
            elif rel.startswith(".github/workflows") and ext in (".yml", ".yaml"):
                text = open(p, errors="replace").read()
                for m in re.finditer(r"run:\s*\|?\s*\n((?:[ \t]+.*\n)+)|run:\s*(.+)", text):
                    scan_text(m.group(1) or m.group(2), rel, F, inline=True)
    with open(a.out, "w") as f:
        json.dump({"items": F, "scripts": n}, f, indent=2)
    print(f"[shell-audit] {n} scripts, {len(F)} findings")


if __name__ == "__main__":
    main()
