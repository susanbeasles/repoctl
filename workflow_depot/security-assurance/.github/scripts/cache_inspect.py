#!/usr/bin/env python3
"""
Content inspection of restored dependency caches, installed dependency trees,
build artifacts and archives (domain I). Nothing here is a workflow lint: every
check reads bytes.

  cache_inspect.py --root <dir> --kind npm-cacache|node_modules|pip-cache|cargo-registry|uv-cache|artifacts|generic \
                   [--lockfile package-lock.json] --out findings.json

Checks (all kinds): magic/extension mismatch, ELF/PE/Mach-O/Wasm anywhere a
binary is not expected, archives (tar/tgz/zip/whl/crate/tgz) walked member by
member for traversal, absolute paths, symlinks/hardlinks escaping, setuid bits,
embedded executables, nested archives, decompression ratio, hidden files that
are executable, world-writable or setuid files, dangling/escaping symlinks.
npm-cacache: index entries vs content-addressed blobs re-hashed (integrity
recomputed from content, not trusted from the index).
node_modules: every package's version matches the lockfile; packages present
that the lockfile does not list; lifecycle scripts; .bin shims pointing outside
the tree; .npmrc/.yarnrc planted inside packages.
pip-cache / uv-cache: wheel RECORD hashes recomputed; sdist members checked.
cargo-registry: .crate archives walked; build.rs and proc-macro inventory.
"""
import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import zipfile

EXEC_MAGIC = [b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\x00asm"]
ARCHIVE_MAGIC = [b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"\xfd7zXZ", b"BZh"]
BINARY_OK_EXT = {".node", ".so", ".dylib", ".dll", ".wasm", ".pyd", ".exe", ".a", ".o", ".rlib"}
ARCHIVE_EXT = {".tgz", ".tar.gz", ".tar", ".zip", ".whl", ".crate", ".gz", ".jar", ".tar.xz", ".xz", ".tbz", ".tar.bz2"}
SKIP = {".git"}
MAX_MEMBERS = 20000
MAX_RATIO = 100
MAX_SIZE = 200 * 1024 * 1024


class F:
    def __init__(self):
        self.items = []
        self.stats = {"files": 0, "archives": 0, "members": 0}

    def add(self, sev, rule, path, msg, **x):
        self.items.append({"severity": sev, "rule": rule, "path": path, "message": msg, **x})


def sniff(head):
    for m in EXEC_MAGIC:
        if head.startswith(m):
            return "executable"
    for m in ARCHIVE_MAGIC:
        if head.startswith(m):
            return "archive"
    return None


def ssri(data, alg="sha512"):
    return f"{alg}-" + base64.b64encode(hashlib.new(alg, data).digest()).decode()


def check_member_name(name, rel, F):
    if name.startswith("/") or name.startswith("\\") or re.match(r"[A-Za-z]:[\\/]", name):
        F.add("critical", "ARCHIVE-ABSOLUTE-PATH", rel, f"member {name}")
        return False
    if ".." in name.replace("\\", "/").split("/"):
        F.add("critical", "ARCHIVE-TRAVERSAL", rel, f"member {name}")
        return False
    return True


def walk_tar(data, rel, F, context):
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except Exception as e:
        F.add("medium", "ARCHIVE-MALFORMED", rel, f"tar: {e}")
        return
    total = 0
    with tf:
        for i, m in enumerate(tf):
            if i >= MAX_MEMBERS:
                F.add("high", "ARCHIVE-MEMBER-FLOOD", rel, f">{MAX_MEMBERS} members")
                break
            F.stats["members"] += 1
            check_member_name(m.name, rel, F)
            if m.issym() or m.islnk():
                tgt = m.linkname
                base = os.path.dirname(m.name)
                norm = os.path.normpath(os.path.join(base, tgt)) if not tgt.startswith("/") else tgt
                if tgt.startswith("/") or norm.startswith(".."):
                    F.add("critical", "ARCHIVE-LINK-ESCAPE", rel, f"{'symlink' if m.issym() else 'hardlink'} {m.name} -> {tgt}")
                continue
            if m.isdev():
                F.add("critical", "ARCHIVE-DEVICE-NODE", rel, f"device member {m.name}")
            if m.mode & (stat.S_ISUID | stat.S_ISGID):
                F.add("high", "ARCHIVE-SETUID", rel, f"setuid/setgid member {m.name}")
            if m.isfile():
                total += m.size
                if m.size > MAX_SIZE:
                    F.add("high", "ARCHIVE-MEMBER-HUGE", rel, f"{m.name} {m.size} bytes")
                    continue
                try:
                    head = tf.extractfile(m).read(8)
                except Exception:
                    continue
                kind = sniff(head)
                ext = os.path.splitext(m.name)[1].lower()
                if kind == "executable" and ext not in BINARY_OK_EXT:
                    F.add("high", "ARCHIVE-EMBEDDED-EXECUTABLE", rel, f"{m.name} is an executable under a non-binary name")
                if kind == "archive" and not any(m.name.lower().endswith(e) for e in ARCHIVE_EXT):
                    F.add("medium", "ARCHIVE-NESTED-DISGUISED", rel, f"{m.name} is an archive under a non-archive name")
                if context == "npm" and os.path.basename(m.name) in (".npmrc", ".yarnrc", ".yarnrc.yml"):
                    F.add("critical", "NPM-TARBALL-RC-FILE", rel, f"{m.name} inside package tarball (registry/auth redirection)")
                if context == "npm" and m.name.endswith("package/package.json"):
                    try:
                        pj = json.loads(tf.extractfile(m).read())
                        for k in ("preinstall", "install", "postinstall", "prepare"):
                            if k in pj.get("scripts", {}):
                                F.add("medium", "NPM-TARBALL-LIFECYCLE-SCRIPT", rel, f"{k}: {pj['scripts'][k][:120]}")
                    except Exception:
                        pass
    if len(data) and total / max(len(data), 1) > MAX_RATIO and total > 50_000_000:
        F.add("high", "ARCHIVE-BOMB-RATIO", rel, f"ratio {total // max(len(data), 1)}:1")


def walk_zip(data, rel, F, context):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        F.add("medium", "ARCHIVE-MALFORMED", rel, f"zip: {e}")
        return
    total = 0
    records = None
    with zf:
        for i, info in enumerate(zf.infolist()):
            if i >= MAX_MEMBERS:
                F.add("high", "ARCHIVE-MEMBER-FLOOD", rel, f">{MAX_MEMBERS} members")
                break
            F.stats["members"] += 1
            n = info.filename
            check_member_name(n, rel, F)
            mode = (info.external_attr >> 16)
            if mode & 0o170000 == 0o120000:
                F.add("high", "ARCHIVE-SYMLINK", rel, f"symlink member {n}")
                continue
            if mode & (stat.S_ISUID | stat.S_ISGID):
                F.add("high", "ARCHIVE-SETUID", rel, f"setuid/setgid member {n}")
            total += info.file_size
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO and info.file_size > 10_000_000:
                F.add("high", "ARCHIVE-BOMB-RATIO", rel, f"{n} ratio {info.file_size // info.compress_size}:1")
            if info.is_dir() or info.file_size > MAX_SIZE:
                continue
            try:
                head = zf.open(info).read(8)
            except Exception:
                continue
            kind = sniff(head)
            ext = os.path.splitext(n)[1].lower()
            if kind == "executable" and ext not in BINARY_OK_EXT:
                F.add("high", "ARCHIVE-EMBEDDED-EXECUTABLE", rel, f"{n} is an executable under a non-binary name")
            if kind == "archive" and not any(n.lower().endswith(e) for e in ARCHIVE_EXT):
                F.add("medium", "ARCHIVE-NESTED-DISGUISED", rel, f"{n} is an archive under a non-archive name")
            if context == "wheel" and n.endswith(".dist-info/RECORD"):
                records = zf.open(info).read().decode(errors="replace")
        if context == "wheel" and records:
            verify_wheel_record(zf, records, rel, F)
        elif context == "wheel":
            F.add("high", "WHEEL-NO-RECORD", rel, "wheel without RECORD (cannot verify member hashes)")


def verify_wheel_record(zf, records, rel, F):
    names = set(zf.namelist())
    bad = 0
    for row in csv.reader(io.StringIO(records)):
        if len(row) < 2 or not row[1]:
            continue
        path, digest = row[0], row[1]
        if path not in names:
            continue
        alg, b64 = digest.split("=", 1)
        try:
            actual = base64.urlsafe_b64encode(hashlib.new(alg, zf.open(path).read()).digest()).rstrip(b"=").decode()
        except Exception:
            continue
        if actual != b64:
            bad += 1
            F.add("critical", "WHEEL-RECORD-MISMATCH", rel, f"{path}: RECORD hash does not match content")
    for n in names:
        if not n.endswith("/") and not n.endswith("RECORD") and n not in {r[0] for r in csv.reader(io.StringIO(records)) if r}:
            F.add("high", "WHEEL-UNLISTED-MEMBER", rel, f"{n} not in RECORD")


def inspect_file(path, rel, F, kind):
    F.stats["files"] += 1
    try:
        st = os.lstat(path)
    except OSError:
        return
    if stat.S_ISLNK(st.st_mode):
        tgt = os.readlink(path)
        norm = os.path.normpath(os.path.join(os.path.dirname(path), tgt))
        root = os.path.abspath(ROOT)
        if tgt.startswith("/") and not os.path.abspath(tgt).startswith(root) or not os.path.abspath(norm).startswith(root):
            F.add("critical", "SYMLINK-ESCAPE", rel, f"-> {tgt}")
        return
    if not stat.S_ISREG(st.st_mode):
        return
    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
        F.add("critical", "FILE-SETUID", rel, "setuid/setgid bit")
    if st.st_mode & stat.S_IWOTH:
        F.add("medium", "FILE-WORLD-WRITABLE", rel, "world-writable")
    base = os.path.basename(rel)
    if st.st_size == 0:
        return
    with open(path, "rb") as f:
        head = f.read(8)
    k = sniff(head)
    ext = os.path.splitext(base)[1].lower()
    if base.startswith(".") and (st.st_mode & stat.S_IXUSR or k == "executable"):
        F.add("high", "HIDDEN-EXECUTABLE", rel, "hidden file is executable")
    if k == "executable" and ext not in BINARY_OK_EXT and kind != "artifacts":
        F.add("high", "UNEXPECTED-EXECUTABLE", rel, "executable content under non-binary name")
    is_archive = any(rel.lower().endswith(e) for e in ARCHIVE_EXT) or k == "archive"
    if is_archive and st.st_size <= MAX_SIZE:
        F.stats["archives"] += 1
        with open(path, "rb") as f:
            data = f.read()
        ctx = "wheel" if rel.endswith(".whl") else "npm" if (rel.endswith(".tgz") or kind == "npm-cacache") else "crate" if rel.endswith(".crate") else "generic"
        if head.startswith(b"PK"):
            walk_zip(data, rel, F, ctx)
        else:
            walk_tar(data, rel, F, ctx)


def npm_cacache(root, F):
    """Re-hash every content blob and check it against the index entry's integrity."""
    idx = os.path.join(root, "index-v5")
    content = os.path.join(root, "content-v2")
    if not os.path.isdir(idx) or not os.path.isdir(content):
        F.add("medium", "CACACHE-LAYOUT", root, "not an npm cacache layout (index-v5/content-v2 missing)")
        return
    n = 0
    for dp, _, fns in os.walk(idx):
        for fn in fns:
            with open(os.path.join(dp, fn), errors="replace") as f:
                for line in f:
                    if "\t" not in line:
                        continue
                    h, body = line.rstrip("\n").split("\t", 1)
                    try:
                        entry = json.loads(body)
                    except Exception:
                        F.add("medium", "CACACHE-INDEX-MALFORMED", fn, "unparseable index line")
                        continue
                    if hashlib.sha1(body.encode()).hexdigest() != h:
                        F.add("critical", "CACACHE-INDEX-TAMPERED", fn, f"index line hash mismatch for {entry.get('key', '')[:80]}")
                    integ = entry.get("integrity") or ""
                    if not integ.startswith("sha512-") and not integ.startswith("sha256-"):
                        continue
                    alg, b64 = integ.split("-", 1)
                    hexd = base64.b64decode(b64 + "===").hex()
                    blob = os.path.join(content, alg, hexd[:2], hexd[2:4], hexd[4:])
                    if not os.path.exists(blob):
                        continue
                    with open(blob, "rb") as bf:
                        actual = ssri(bf.read(), alg)
                    n += 1
                    if actual != integ:
                        F.add("critical", "CACACHE-CONTENT-MISMATCH", blob, f"blob does not match its integrity {integ[:24]}… (key {entry.get('key', '')[:60]})")
    F.stats["cacache_entries_verified"] = n


def node_modules(root, lockfile, F):
    lock = {}
    if lockfile and os.path.exists(lockfile):
        try:
            lock = json.load(open(lockfile)).get("packages", {})
        except Exception:
            F.add("high", "LOCKFILE-MALFORMED", lockfile, "cannot parse package-lock.json")
    hidden = os.path.join(root, ".package-lock.json")
    installed = {}
    if os.path.exists(hidden):
        try:
            installed = json.load(open(hidden)).get("packages", {})
        except Exception:
            F.add("high", "HIDDEN-LOCKFILE-MALFORMED", hidden, "node_modules/.package-lock.json unparseable")
    parent = os.path.dirname(root)
    for dp, dns, fns in os.walk(root):
        if "package.json" in fns and dp != root:
            rel = os.path.relpath(dp, parent)
            try:
                pj = json.load(open(os.path.join(dp, "package.json")))
            except Exception:
                F.add("medium", "PKG-JSON-MALFORMED", rel, "unparseable package.json")
                continue
            ver = pj.get("version")
            if lock:
                if rel not in lock:
                    F.add("high", "NODE_MODULES-NOT-IN-LOCKFILE", rel, f"installed {pj.get('name')}@{ver} is not in package-lock.json")
                elif lock[rel].get("version") not in (None, ver):
                    F.add("critical", "NODE_MODULES-VERSION-MISMATCH", rel, f"installed {ver}, lockfile {lock[rel].get('version')}")
                elif installed and rel in installed and installed[rel].get("integrity") and lock[rel].get("integrity") and installed[rel]["integrity"] != lock[rel]["integrity"]:
                    F.add("critical", "NODE_MODULES-INTEGRITY-MISMATCH", rel, "hidden lockfile integrity differs from package-lock.json")
            for k in ("preinstall", "install", "postinstall"):
                if k in pj.get("scripts", {}):
                    F.add("medium", "NODE_MODULES-LIFECYCLE-SCRIPT", rel, f"{k}: {pj['scripts'][k][:120]}")
        for fn in fns:
            if fn in (".npmrc", ".yarnrc", ".yarnrc.yml"):
                F.add("critical", "NODE_MODULES-RC-FILE", os.path.relpath(os.path.join(dp, fn), parent), "registry/auth config planted inside node_modules")
    binsdir = os.path.join(root, ".bin")
    if os.path.isdir(binsdir):
        for fn in os.listdir(binsdir):
            p = os.path.join(binsdir, fn)
            if os.path.islink(p):
                tgt = os.path.normpath(os.path.join(binsdir, os.readlink(p)))
                if not os.path.abspath(tgt).startswith(os.path.abspath(root)):
                    F.add("critical", "NODE_MODULES-BIN-ESCAPE", f"node_modules/.bin/{fn}", f"-> {os.readlink(p)}")


def cargo_registry(root, F):
    for dp, _, fns in os.walk(root):
        for fn in fns:
            if fn == "Cargo.toml" and os.path.dirname(dp).endswith("src"):
                try:
                    import tomllib
                    t = tomllib.load(open(os.path.join(dp, fn), "rb"))
                except Exception:
                    continue
                rel = os.path.relpath(dp, root)
                if t.get("package", {}).get("build") or os.path.exists(os.path.join(dp, "build.rs")):
                    F.add("low", "CRATE-BUILD-SCRIPT", rel, "crate has build.rs (executes at build time)")
                if t.get("lib", {}).get("proc-macro"):
                    F.add("low", "CRATE-PROC-MACRO", rel, "proc-macro crate (executes at compile time)")


def main():
    global ROOT
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--kind", default="generic", choices=["npm-cacache", "node_modules", "pip-cache", "uv-cache", "cargo-registry", "artifacts", "generic"])
    ap.add_argument("--lockfile", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-files", type=int, default=200000)
    a = ap.parse_args()
    ROOT = a.root
    F_ = F()
    if not os.path.isdir(a.root):
        F_.add("info", "CACHE-ABSENT", a.root, "directory does not exist (nothing restored)")
    else:
        n = 0
        for dp, dns, fns in os.walk(a.root):
            dns[:] = [d for d in dns if d not in SKIP]
            for fn in fns:
                p = os.path.join(dp, fn)
                try:
                    inspect_file(p, os.path.relpath(p, a.root), F_, a.kind)
                except Exception as e:
                    F_.add("medium", "INSPECT-ERROR", os.path.relpath(p, a.root), f"{type(e).__name__}: {str(e)[:120]}")
                n += 1
                if n >= a.max_files:
                    F_.add("medium", "FILE-LIMIT", a.root, f"stopped after {a.max_files} files")
                    break
            else:
                continue
            break
        if a.kind == "npm-cacache":
            npm_cacache(a.root, F_)
        elif a.kind == "node_modules":
            node_modules(a.root, a.lockfile, F_)
        elif a.kind == "cargo-registry":
            cargo_registry(a.root, F_)
    with open(a.out, "w") as f:
        json.dump({"items": F_.items, "stats": F_.stats, "kind": a.kind, "root": a.root}, f, indent=2)
    print(f"[cache-inspect] {a.kind} {a.root}: {F_.stats} -> {len(F_.items)} findings")


if __name__ == "__main__":
    main()
