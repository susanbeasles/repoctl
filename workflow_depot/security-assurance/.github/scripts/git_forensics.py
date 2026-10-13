#!/usr/bin/env python3
"""
Git database and repository forensics (domain G).

Runs git with a locked-down configuration (no hooks, no filters, no fsmonitor,
no global/system config) and inspects the RAW object database and HEAD tree,
not the working copy. Emits a findings JSON for result.py.

  git_forensics.py --repo <path> --out findings.json [--max-blob-bytes N]

Limitations reported in the findings:
  * A fresh CI clone cannot contain unreachable/dangling objects from another
    workspace; we report that as a limitation rather than pretending coverage.
  * Signature verification needs a trusted keyring; without one it is INCONCLUSIVE.
"""
import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import unicodedata

GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_LFS_SKIP_SMUDGE": "1",
    "LC_ALL": "C.UTF-8",
}
SAFE_GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "filter.lfs.smudge=", "-c", "filter.lfs.clean=", "-c", "filter.lfs.process=",
            "-c", "filter.lfs.required=false", "-c", "core.pager=cat", "-c", "diff.external="]

MAGIC = [
    (b"\x7fELF", "elf"), (b"MZ", "pe"), (b"\xfe\xed\xfa\xce", "macho"), (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"), (b"\xca\xfe\xba\xbe", "macho-fat/java-class"), (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"), (b"\x00asm", "wasm"),
    (b"\xfd7zXZ\x00", "xz"), (b"BZh", "bzip2"), (b"#!", "script"),
]
SOURCE_EXT = {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".py", ".rs", ".swift", ".sh", ".md", ".json",
              ".yml", ".yaml", ".toml", ".txt", ".html", ".css", ".svg", ".xml", ".sql", ".tf", ".hcl"}
BINARY_OK_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".pdf",
                 ".mp4", ".mp3", ".wasm", ".jar", ".zip", ".gz", ".tgz", ".xz", ".bz2", ".7z", ".tar"}
DANGEROUS_CONFIG_KEYS = re.compile(
    r"^(core\.(hookspath|fsmonitor|sshcommand|editor|pager|askpass|gitproxy|alternaterefscommand)|"
    r"filter\..*\.(clean|smudge|process)|diff\..*\.(command|textconv)|merge\..*\.driver|"
    r"alias\.|include\.path|includeif\.|url\..*\.insteadof|credential\.helper|gpg\.program|"
    r"uploadpack\.|receive\.|remote\..*\.(uploadpack|receivepack|proxy)|sendemail\.|"
    r"http\..*\.(proxy|sslcainfo|sslcert|sslkey)|safe\.directory)", re.I)
INJECTION_PHRASES = re.compile(
    r"(ignore (all |any )?(previous|prior|above|earlier) (instructions|messages|context)|"
    r"you are now|system prompt|do not (tell|inform) the user|<\|im_start\|>|\[INST\]|"
    r"###\s*(system|instruction)|\bSYSTEM:\s)", re.I)
CONFUSABLE_RANGES = [(0x0400, 0x04FF), (0x0370, 0x03FF), (0x2010, 0x2015), (0xFF01, 0xFF5E), (0x0530, 0x058F)]
INVISIBLE = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
             0x2066, 0x2067, 0x2068, 0x2069}


def git(args, cwd, check=False, binary=False):
    r = subprocess.run(SAFE_GIT + args, cwd=cwd, env=GIT_ENV, capture_output=True, timeout=600)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.decode(errors='replace')[:500]}")
    return r.returncode, (r.stdout if binary else r.stdout.decode(errors="replace")), r.stderr.decode(errors="replace")


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def sniff(data):
    for magic, kind in MAGIC:
        if data.startswith(magic):
            return kind
    return None


class Findings:
    def __init__(self):
        self.items = []
        self.limitations = []

    def add(self, severity, rule, path, message, **extra):
        self.items.append({"severity": severity, "rule": rule, "path": path, "message": message, **extra})


def check_structure(repo, F):
    rc, out, err = git(["fsck", "--full", "--strict", "--no-dangling"], repo)
    if rc != 0:
        F.add("critical", "GIT-FSCK", ".git", "git fsck reported structural errors", output=(out + err)[:2000])
    gitdir = git(["rev-parse", "--git-dir"], repo)[1].strip()
    gitdir = gitdir if os.path.isabs(gitdir) else os.path.join(repo, gitdir)
    for rel, sev, msg in [
        ("objects/info/alternates", "critical", "alternate object directory configured (objects sourced outside this repo)"),
        ("info/grafts", "critical", "graft file present (history rewriting)"),
        ("shallow", "low", "shallow clone: history before the boundary was not inspected"),
    ]:
        if os.path.exists(os.path.join(gitdir, rel)):
            F.add(sev, "GIT-DB-STATE", f".git/{rel}", msg)
    # replace refs rewrite objects transparently; never acceptable in a candidate
    rc, out, _ = git(["for-each-ref", "refs/replace/"], repo)
    if out.strip():
        F.add("critical", "GIT-REPLACE-REFS", ".git/refs/replace", "replace refs present", refs=out.strip()[:500])
    # hooks that are not the shipped samples
    hooks = os.path.join(gitdir, "hooks")
    if os.path.isdir(hooks):
        real = [h for h in os.listdir(hooks) if not h.endswith(".sample")]
        if real:
            F.add("critical", "GIT-HOOKS", ".git/hooks", "executable hooks present in clone", hooks=real)
    # repo-level config keys that change git behaviour
    rc, out, _ = git(["config", "--local", "--list"], repo)
    for line in out.splitlines():
        key = line.split("=", 1)[0]
        if DANGEROUS_CONFIG_KEYS.match(key):
            F.add("critical", "GIT-CONFIG", ".git/config", f"behaviour-altering config key: {key}")
    rc, out, _ = git(["for-each-ref", "refs/notes/"], repo)
    if out.strip():
        F.add("low", "GIT-NOTES", ".git/refs/notes", "git notes present (inspect for hidden instructions)")
    F.limitations.append("Unreachable/dangling objects from other workspaces are not present in a fresh clone and were not inspected.")
    rc, out, _ = git(["count-objects", "-v"], repo)
    return dict(l.split(": ") for l in out.splitlines() if ": " in l)


def check_tree(repo, F, max_blob):
    rc, out, _ = git(["ls-tree", "-r", "-l", "-z", "HEAD"], repo, check=True)
    entries = []
    for rec in out.split("\0"):
        if not rec:
            continue
        meta, path = rec.split("\t", 1)
        mode, otype, oid, size = meta.split()
        entries.append((mode, otype, oid, int(size) if size != "-" else 0, path))

    lower_seen, nfc_seen = {}, {}
    for mode, otype, oid, size, path in entries:
        base = os.path.basename(path)
        ext = os.path.splitext(base)[1].lower()
        # path-level checks
        if any(ord(c) in INVISIBLE for c in path):
            F.add("critical", "PATH-INVISIBLE-UNICODE", path, "invisible/bidi code point in path")
        if any(any(lo <= ord(c) <= hi for lo, hi in CONFUSABLE_RANGES) for c in path):
            F.add("high", "PATH-CONFUSABLE", path, "confusable non-Latin script in path")
        if path.lower() in lower_seen and lower_seen[path.lower()] != path:
            F.add("high", "PATH-CASE-COLLISION", path, f"case-collides with {lower_seen[path.lower()]}")
        lower_seen[path.lower()] = path
        nfc = unicodedata.normalize("NFC", path)
        if nfc in nfc_seen and nfc_seen[nfc] != path:
            F.add("high", "PATH-NORMALIZATION-COLLISION", path, f"NFC-collides with {nfc_seen[nfc]}")
        nfc_seen[nfc] = path
        if ".git/" in path + "/" and path.split("/")[0] != ".git" and "/.git/" in "/" + path:
            F.add("high", "PATH-NESTED-GITDIR", path, "nested .git directory in tree")
        # mode-level checks
        if mode == "120000":
            target = git(["cat-file", "-p", oid], repo)[1]
            norm = os.path.normpath(os.path.join(os.path.dirname(path), target))
            if target.startswith("/") or norm.startswith(".."):
                F.add("critical", "SYMLINK-ESCAPE", path, f"symlink target escapes repository: {target}")
            else:
                F.add("low", "SYMLINK", path, f"symlink -> {target}")
            continue
        if mode == "160000":
            F.add("high", "SUBMODULE", path, "submodule gitlink (not recursed; pin and review .gitmodules)")
            continue
        if mode == "100755" and ext in SOURCE_EXT - {".sh"}:
            F.add("medium", "MODE-EXECUTABLE-SOURCE", path, "executable bit on non-script source file")
        if size > 20 * 1024 * 1024:
            F.add("medium", "BLOB-LARGE", path, f"large object ({size} bytes)")
        # content-level checks (bounded)
        if otype != "blob" or size == 0 or size > max_blob:
            continue
        rc, data, _ = git(["cat-file", "blob", oid], repo, binary=True)
        head = data[:16]
        kind = sniff(head)
        if kind == "script" and mode != "100755" and ext not in {".sh", ".py", ".rb", ".pl"}:
            pass
        if kind in {"elf", "pe", "macho", "macho-fat/java-class", "wasm"} and ext not in BINARY_OK_EXT:
            F.add("high", "BLOB-HIDDEN-EXECUTABLE", path, f"{kind} executable content under non-binary name")
        if kind in {"zip", "gzip", "7z", "rar", "xz", "bzip2"} and ext not in BINARY_OK_EXT:
            F.add("high", "BLOB-HIDDEN-ARCHIVE", path, f"{kind} archive content under non-archive name")
        if ext in SOURCE_EXT and size > 64 * 1024:
            e = entropy(data[:256 * 1024])
            if e > 7.3:
                F.add("high", "BLOB-HIGH-ENTROPY", path, f"source-named blob with entropy {e:.2f} (packed/encoded payload?)")
        if ext in SOURCE_EXT:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                F.add("medium", "BLOB-NOT-UTF8", path, "source-named blob is not valid UTF-8")
                continue
            if any(ord(c) in INVISIBLE for c in text[:200000]):
                F.add("high", "BLOB-INVISIBLE-UNICODE", path, "invisible/bidi code points in source (Trojan Source class)")
            if re.search(r"(?:[A-Za-z0-9+/]{4}){200,}={0,2}", text):
                F.add("medium", "BLOB-BASE64-PAYLOAD", path, "large base64 run (>800 chars) in source")
        if base in {"LICENSE", "README", "README.md"}:
            continue
    # LFS pointers
    for mode, otype, oid, size, path in entries:
        if otype == "blob" and 100 < size < 300:
            data = git(["cat-file", "blob", oid], repo, binary=True)[1]
            if data.startswith(b"version https://git-lfs.github.com/spec/v1"):
                F.add("medium", "LFS-POINTER", path, "LFS pointer (content fetched out-of-band; not scanned here)")
    return len(entries)


def check_attributes_and_modules(repo, F):
    for mode, otype, oid, size, path in []:
        pass
    rc, out, _ = git(["ls-files", "-z", "--", ".gitattributes", "*/.gitattributes", ".gitmodules", ".lfsconfig"], repo)
    for path in filter(None, out.split("\0")):
        text = git(["show", f"HEAD:{path}"], repo)[1]
        if path.endswith(".gitattributes") and re.search(r"\bfilter=", text):
            F.add("high", "GITATTR-FILTER", path, "clean/smudge filter attribute (requires runner-side driver; inspect)")
        if path.endswith(".gitattributes") and re.search(r"\b(diff|merge)=", text):
            F.add("low", "GITATTR-DRIVER", path, "custom diff/merge driver attribute")
        if path == ".gitmodules":
            for m in re.finditer(r"url\s*=\s*(\S+)", text):
                url = m.group(1)
                sev = "critical" if re.match(r"(file:|/|\.\./|[a-z]:\\)", url, re.I) else "medium"
                F.add(sev, "GITMODULES-URL", path, f"submodule url {url}")
        if path == ".lfsconfig":
            F.add("high", "LFSCONFIG", path, ".lfsconfig present (can redirect LFS fetches)")


def check_history(repo, F, max_commits=500):
    rc, out, _ = git(["log", f"--max-count={max_commits}", "--format=%H%x00%B%x00%an <%ae>%x00%G?%x1e"], repo)
    unsigned = 0
    for rec in filter(None, out.split("\x1e")):
        parts = rec.strip("\n").split("\0")
        if len(parts) < 4:
            continue
        sha, msg, author, sigstatus = parts[0].strip(), parts[1], parts[2], parts[3].strip()
        if INJECTION_PHRASES.search(msg):
            F.add("high", "COMMIT-MSG-INJECTION", sha[:12], "commit message contains instruction-injection phrasing")
        if any(ord(c) in INVISIBLE for c in msg):
            F.add("high", "COMMIT-MSG-INVISIBLE", sha[:12], "invisible/bidi code points in commit message")
        if sigstatus in ("N", ""):
            unsigned += 1
    if unsigned:
        F.add("low", "COMMIT-UNSIGNED", "history", f"{unsigned} of the last {max_commits} commits unsigned or unverifiable")
    F.limitations.append("Signature verification ran without a provisioned trusted keyring; signed status is INCONCLUSIVE.")


def check_checkout_matches_tree(repo, F):
    # Working copy must equal the raw tree: catches smudge filters, post-checkout
    # mutation, and anything that edited files between checkout and scan.
    rc, out, _ = git(["diff", "--no-ext-diff", "--exit-code", "--stat", "HEAD", "--"], repo)
    rc2, out2, _ = git(["status", "--porcelain", "--untracked-files=all", "--ignored=no"], repo)
    if rc != 0 or out2.strip():
        F.add("critical", "CHECKOUT-TREE-MISMATCH", ".", "working copy differs from HEAD tree",
              diff=out[:1500], status=out2[:1500])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-blob-bytes", type=int, default=50 * 1024 * 1024)
    a = ap.parse_args()
    F = Findings()
    stats = {}
    try:
        stats["objects"] = check_structure(a.repo, F)
        stats["tree_entries"] = check_tree(a.repo, F, a.max_blob_bytes)
        check_attributes_and_modules(a.repo, F)
        check_history(a.repo, F)
        check_checkout_matches_tree(a.repo, F)
        head = git(["rev-parse", "HEAD"], a.repo)[1].strip()
        tree = git(["rev-parse", "HEAD^{tree}"], a.repo)[1].strip()
    except Exception as e:
        F.add("critical", "FORENSICS-ERROR", ".", f"forensics aborted: {e}")
        head = tree = ""
    with open(a.out, "w") as f:
        json.dump({"items": F.items, "limitations": F.limitations, "stats": stats, "head": head, "tree": tree},
                  f, indent=2)
    print(f"[git-forensics] {len(F.items)} findings; head={head[:12]} tree={tree[:12]}")
    sys.exit(0)


if __name__ == "__main__":
    main()
