#!/usr/bin/env python3
"""
Supply-chain analysis that no CVE scanner performs (domain D):
  * lifecycle/install scripts in package.json and in every lockfile entry
  * typosquat distance against a vendored popular-package list (npm + PyPI + crates)
  * dependency confusion: scoped/private-looking names without a pinned registry, .npmrc / pip.conf / cargo config
    registry overrides, always-auth, insteadOf rewrites
  * lockfile drift vs base commit: newly introduced packages, resolved-host changes, integrity changes without version change,
    major version jumps, switch from registry to git/url source
  * Rust: build.rs / proc-macro / unsafe inventory, git/path/patch sources, [patch] overrides
  * Swift: Package.swift plugins, binaryTarget URLs/checksums, unsafeFlags, macro targets; Package.resolved pins
  * Python: requirements without hashes, VCS/url/editable, index-url overrides, pyproject build backends

  supply_chain.py --repo <path> [--base-ref <sha>] --out findings.json
"""
import argparse
import json
import os
import re
import subprocess
import sys

POPULAR = {
    "npm": ["react", "react-dom", "lodash", "express", "axios", "next", "typescript", "eslint", "prettier", "jest", "vite", "webpack", "babel", "chalk",
            "commander", "moment", "dayjs", "uuid", "dotenv", "cors", "body-parser", "mongoose", "pg", "redis", "socket.io", "zod", "prisma", "tailwindcss",
            "vue", "angular", "svelte", "rxjs", "node-fetch", "yargs", "minimist", "debug", "winston", "pino", "bcrypt", "jsonwebtoken", "passport", "helmet",
            "sequelize", "knex", "ws", "graphql", "apollo-server", "styled-components", "classnames", "immer", "redux", "mobx", "lodash-es", "underscore",
            "esbuild", "rollup", "ts-node", "nodemon", "concurrently", "cross-env", "rimraf", "glob", "fs-extra", "semver", "colors", "ua-parser-js", "event-stream"],
    "pypi": ["requests", "numpy", "pandas", "flask", "django", "fastapi", "pytest", "boto3", "sqlalchemy", "pydantic", "urllib3", "certifi", "setuptools",
             "pip", "wheel", "cryptography", "pyyaml", "jinja2", "click", "httpx", "aiohttp", "scipy", "matplotlib", "pillow", "psycopg2", "pymongo", "redis",
             "celery", "uvicorn", "gunicorn", "python-dotenv", "colorama", "tqdm", "scikit-learn", "torch", "tensorflow", "transformers", "openai", "anthropic"],
    "crates": ["serde", "tokio", "syn", "quote", "rand", "libc", "log", "clap", "regex", "anyhow", "thiserror", "reqwest", "hyper", "axum", "actix-web",
               "serde_json", "chrono", "once_cell", "lazy_static", "futures", "bytes", "tracing", "uuid", "base64", "sha2", "ring", "rustls", "openssl"],
}
MAJOR_SCRIPT_PAT = re.compile(r"(curl|wget|node -e|eval|bash -c|sh -c|powershell|base64|\|\s*sh|\|\s*bash|http://|https://)", re.I)
INJECTION_SCRIPT = re.compile(r"(\$\(|`|\\x[0-9a-f]{2}|fromCharCode|atob\()", re.I)


def lev(a, b):
    """Damerau-Levenshtein (adjacent transposition counts as one edit: lodahs ~ lodash)."""
    if abs(len(a) - len(b)) > 2:
        return 99
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


class F:
    def __init__(self):
        self.items = []

    def add(self, sev, rule, path, msg, **x):
        self.items.append({"severity": sev, "rule": rule, "path": path, "message": msg, **x})


def typosquat(name, eco, F, path):
    base = name.split("/")[-1].lower()
    if base in POPULAR[eco]:
        return
    for p in POPULAR[eco]:
        d = lev(base, p)
        if 0 < d <= 1 or (d == 2 and len(p) >= 8):
            F.add("high", "TYPOSQUAT-CANDIDATE", path, f"{name} is within edit distance {d} of popular package {p}")
            return
    if re.sub(r"[-_.]", "", base) in {re.sub(r"[-_.]", "", p) for p in POPULAR[eco]} and base not in POPULAR[eco]:
        F.add("high", "TYPOSQUAT-SEPARATOR", path, f"{name} differs from a popular package only by separators")


def git_show(repo, ref, path):
    r = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "show", f"{ref}:{path}"], cwd=repo, capture_output=True)
    return r.stdout.decode(errors="replace") if r.returncode == 0 else None


def node(repo, base, F):
    pj_path = os.path.join(repo, "package.json")
    if not os.path.exists(pj_path):
        return
    try:
        pj = json.load(open(pj_path))
    except Exception:
        F.add("high", "PKG-JSON-MALFORMED", "package.json", "unparseable")
        return
    for k, v in pj.get("scripts", {}).items():
        if k in ("preinstall", "install", "postinstall", "prepare", "prepublish") and MAJOR_SCRIPT_PAT.search(v):
            F.add("high", "NPM-LIFECYCLE-NETWORK-OR-EVAL", "package.json", f"{k}: {v[:120]}")
        if INJECTION_SCRIPT.search(v):
            F.add("medium", "NPM-SCRIPT-OBFUSCATION", "package.json", f"{k}: {v[:120]}")
    deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {}), **pj.get("optionalDependencies", {})}
    for name, spec in deps.items():
        typosquat(name, "npm", F, "package.json")
        if re.match(r"(git\+|github:|https?://|file:|link:)", str(spec)):
            F.add("high", "NPM-NON-REGISTRY-DEP", "package.json", f"{name}: {spec}")
        if str(spec) in ("*", "latest", "") or str(spec).startswith(">"):
            F.add("medium", "NPM-UNBOUNDED-RANGE", "package.json", f"{name}: {spec!r}")
    npmrc = os.path.join(repo, ".npmrc")
    if os.path.exists(npmrc):
        t = open(npmrc, errors="replace").read()
        if re.search(r"^\s*registry\s*=\s*(?!https://registry\.npmjs\.org)", t, re.M):
            F.add("high", "NPMRC-REGISTRY-OVERRIDE", ".npmrc", "default registry overridden")
        if re.search(r"_authToken\s*=\s*(?!\$\{)", t):
            F.add("critical", "NPMRC-INLINE-TOKEN", ".npmrc", "literal auth token in .npmrc")
        if "always-auth" in t:
            F.add("medium", "NPMRC-ALWAYS-AUTH", ".npmrc", "always-auth set")
        if re.search(r"ignore-scripts\s*=\s*false", t):
            F.add("medium", "NPMRC-SCRIPTS-ENABLED", ".npmrc", "ignore-scripts explicitly disabled")
    scoped = [n for n in deps if n.startswith("@")]
    scopes = {n.split("/")[0] for n in scoped}
    if scopes and os.path.exists(npmrc):
        t = open(npmrc, errors="replace").read()
        for sc in scopes:
            if f"{sc}:registry" not in t:
                F.add("medium", "DEP-CONFUSION-SCOPE-UNPINNED", "package.json", f"scope {sc} has no scoped registry in .npmrc (dependency-confusion exposure if private)")
    elif scopes:
        F.add("medium", "DEP-CONFUSION-NO-NPMRC", "package.json", f"scoped deps {sorted(scopes)} without .npmrc scope→registry pins")
    lock_path = os.path.join(repo, "package-lock.json")
    if os.path.exists(lock_path):
        try:
            lock = json.load(open(lock_path)).get("packages", {})
        except Exception:
            F.add("high", "LOCKFILE-MALFORMED", "package-lock.json", "unparseable")
            lock = {}
        for p, m in lock.items():
            if m.get("hasInstallScript"):
                F.add("medium", "LOCK-INSTALL-SCRIPT", "package-lock.json", f"{p} declares install scripts")
            nm = p.split("node_modules/")[-1]
            if nm and nm != p:
                typosquat(nm, "npm", F, "package-lock.json")
        if base:
            old = git_show(repo, base, "package-lock.json")
            if old:
                try:
                    oldp = json.loads(old).get("packages", {})
                except Exception:
                    oldp = {}
                for p, m in lock.items():
                    if not p:
                        continue
                    o = oldp.get(p)
                    host = (re.match(r"\w+://([^/]+)/", m.get("resolved", "") or "") or [None, None])[1]
                    if o is None:
                        F.add("low", "LOCK-NEW-PACKAGE", "package-lock.json", f"+ {p}@{m.get('version')} from {host}")
                        continue
                    ohost = (re.match(r"\w+://([^/]+)/", o.get("resolved", "") or "") or [None, None])[1]
                    if ohost and host and ohost != host:
                        F.add("critical", "LOCK-RESOLVED-HOST-CHANGED", "package-lock.json", f"{p}: {ohost} -> {host}")
                    if o.get("version") == m.get("version") and o.get("integrity") and m.get("integrity") and o["integrity"] != m["integrity"]:
                        F.add("critical", "LOCK-INTEGRITY-CHANGED-SAME-VERSION", "package-lock.json", f"{p}@{m.get('version')} integrity changed without a version change")
                    ov, nv = (o.get("version") or "0").split(".")[0], (m.get("version") or "0").split(".")[0]
                    if ov.isdigit() and nv.isdigit() and int(nv) > int(ov) + 1:
                        F.add("medium", "LOCK-MAJOR-JUMP", "package-lock.json", f"{p}: {o.get('version')} -> {m.get('version')}")
                    if (o.get("resolved") or "").startswith("https://") and (m.get("resolved") or "").startswith(("git", "http://", "file:")):
                        F.add("critical", "LOCK-SOURCE-DOWNGRADE", "package-lock.json", f"{p}: registry -> {m.get('resolved')[:60]}")


def python(repo, base, F):
    for rf in [f for f in os.listdir(repo) if re.match(r"requirements.*\.txt$", f)]:
        t = open(os.path.join(repo, rf), errors="replace").read()
        if re.search(r"^\s*(-i|--index-url|--extra-index-url)\s", t, re.M):
            F.add("high", "PIP-INDEX-OVERRIDE", rf, "index-url/extra-index-url in requirements (dependency-confusion vector)")
        for line in t.splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.-]+)", line)
            if m and not line.strip().startswith(("-", "#")):
                typosquat(m.group(1), "pypi", F, rf)
    for cfg in ("pip.conf", ".pip/pip.conf", "setup.cfg", "pyproject.toml"):
        p = os.path.join(repo, cfg)
        if os.path.exists(p):
            t = open(p, errors="replace").read()
            if re.search(r"(index-url|extra-index-url|index_url)\s*=", t) and "pypi.org" not in t:
                F.add("high", "PIP-INDEX-OVERRIDE", cfg, "custom package index configured")
            if cfg == "pyproject.toml":
                m = re.search(r'build-backend\s*=\s*"([^"]+)"', t)
                if m and m.group(1).split(".")[0] not in ("setuptools", "hatchling", "flit_core", "poetry", "pdm", "maturin", "scikit_build_core", "meson_python", "uv_build"):
                    F.add("high", "PY-UNKNOWN-BUILD-BACKEND", cfg, f"build-backend {m.group(1)} (executes at build time)")
                if "[tool.uv.sources]" in t or "[tool.poetry.source]" in t or "[[tool.poetry.source]]" in t:
                    F.add("medium", "PY-CUSTOM-SOURCE", cfg, "custom package source declared")
                for name in re.findall(r'"([A-Za-z0-9_.-]+)\s*[<>=!~\[]', t):
                    typosquat(name, "pypi", F, cfg)
    for py in ("setup.py",):
        p = os.path.join(repo, py)
        if os.path.exists(p):
            t = open(p, errors="replace").read()
            if re.search(r"(os\.system|subprocess|urllib|requests\.|socket|base64\.b64decode|exec\(|eval\()", t):
                F.add("critical", "SETUP-PY-ACTIVE-CODE", py, "setup.py performs network/exec/decode operations at install time")


def rust(repo, base, F):
    ct = os.path.join(repo, "Cargo.toml")
    if not os.path.exists(ct):
        return
    try:
        import tomllib
        t = tomllib.load(open(ct, "rb"))
    except Exception:
        F.add("high", "CARGO-TOML-MALFORMED", "Cargo.toml", "unparseable")
        return
    if t.get("package", {}).get("build") or os.path.exists(os.path.join(repo, "build.rs")):
        F.add("low", "RUST-BUILD-SCRIPT", "Cargo.toml", "build.rs present (compile-time code execution)")
        bs = open(os.path.join(repo, t.get("package", {}).get("build", "build.rs")), errors="replace").read() if os.path.exists(os.path.join(repo, t.get("package", {}).get("build", "build.rs"))) else ""
        if re.search(r"(std::net|reqwest|ureq|Command::new|std::process|include_bytes!\(\s*\"/)", bs):
            F.add("critical", "RUST-BUILD-SCRIPT-ACTIVE", "build.rs", "build script spawns processes or uses the network")
    if t.get("lib", {}).get("proc-macro"):
        F.add("low", "RUST-PROC-MACRO", "Cargo.toml", "crate is a proc-macro (compile-time code execution)")
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in t.get(section, {}).items():
            typosquat(name, "crates", F, "Cargo.toml")
            if isinstance(spec, dict):
                if "git" in spec:
                    F.add("high", "RUST-GIT-DEP", "Cargo.toml", f"{name} from git {spec['git']}" + ("" if spec.get("rev") else " (no rev pin)"))
                if "path" in spec and ".." in spec["path"]:
                    F.add("medium", "RUST-PATH-DEP-ESCAPE", "Cargo.toml", f"{name} path {spec['path']}")
                if spec.get("registry"):
                    F.add("medium", "RUST-ALT-REGISTRY", "Cargo.toml", f"{name} registry {spec['registry']}")
    if t.get("patch"):
        F.add("high", "RUST-PATCH-OVERRIDE", "Cargo.toml", f"[patch] overrides: {list(t['patch'].keys())}")
    for cfg in (".cargo/config.toml", ".cargo/config"):
        p = os.path.join(repo, cfg)
        if os.path.exists(p):
            tt = open(p, errors="replace").read()
            if re.search(r"\[source\.", tt) or "replace-with" in tt:
                F.add("high", "CARGO-SOURCE-REPLACEMENT", cfg, "crates.io source replaced")
            if re.search(r"\[target\..*\]\s*\n\s*(linker|runner)\s*=", tt) or re.search(r"^(linker|runner)\s*=", tt, re.M):
                F.add("critical", "CARGO-LINKER-RUNNER-OVERRIDE", cfg, "custom linker/runner (executes arbitrary binary at build)")
            if "rustflags" in tt and re.search(r"-C\s*link-arg", tt):
                F.add("medium", "CARGO-RUSTFLAGS-LINKARG", cfg, "custom link args")
            if re.search(r"^\[net\]|git-fetch-with-cli", tt, re.M):
                F.add("low", "CARGO-NET-CONFIG", cfg, "[net] configuration present")
    unsafe_n = 0
    for dp, dns, fns in os.walk(repo):
        dns[:] = [d for d in dns if d not in (".git", "target")]
        for fn in fns:
            if fn.endswith(".rs"):
                try:
                    src = open(os.path.join(dp, fn), errors="replace").read()
                except Exception:
                    continue
                n = len(re.findall(r"\bunsafe\s*\{", src))
                unsafe_n += n
                if re.search(r"#!\[allow\(unsafe_code\)\]|#!\[allow\(clippy::", src):
                    F.add("low", "RUST-LINT-ALLOW", os.path.relpath(os.path.join(dp, fn), repo), "crate-level lint allow")
                if re.search(r"std::mem::transmute|from_raw_parts_mut|set_len\(", src):
                    F.add("medium", "RUST-UNSAFE-PRIMITIVE", os.path.relpath(os.path.join(dp, fn), repo), "transmute/from_raw_parts_mut/set_len")
    if unsafe_n:
        F.add("low", "RUST-UNSAFE-BLOCKS", "src", f"{unsafe_n} unsafe blocks (inventory; review each)")
    cl = os.path.join(repo, "Cargo.lock")
    if os.path.exists(cl) and base:
        old = git_show(repo, base, "Cargo.lock")
        if old:
            def parse(txt):
                return {m.group(1): (m.group(2), m.group(3)) for m in re.finditer(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"(?:\nsource = "([^"]+)")?', txt)}
            o, n = parse(old), parse(open(cl).read())
            for name, (ver, src) in n.items():
                if name in o and o[name][1] and src and o[name][1] != src and "registry+" in o[name][1]:
                    F.add("critical", "CARGO-LOCK-SOURCE-CHANGED", "Cargo.lock", f"{name}: {o[name][1][:40]} -> {src[:40]}")
                if name not in o and src and src.startswith("git+"):
                    F.add("high", "CARGO-LOCK-NEW-GIT-DEP", "Cargo.lock", f"+ {name} from {src[:60]}")


def swift(repo, base, F):
    ps = os.path.join(repo, "Package.swift")
    if not os.path.exists(ps):
        return
    t = open(ps, errors="replace").read()
    for m in re.finditer(r"\.binaryTarget\s*\(\s*name:\s*\"([^\"]+)\"\s*,\s*url:\s*\"([^\"]+)\"(?:\s*,\s*checksum:\s*\"([^\"]+)\")?", t):
        name, url, chk = m.groups()
        F.add("high" if not chk else "medium", "SWIFT-BINARY-TARGET", "Package.swift", f"{name} from {url}" + ("" if chk else " WITHOUT checksum"))
    for m in re.finditer(r"\.binaryTarget\s*\(\s*name:\s*\"([^\"]+)\"\s*,\s*path:\s*\"([^\"]+)\"", t):
        F.add("high", "SWIFT-BINARY-TARGET-LOCAL", "Package.swift", f"{m.group(1)} from local path {m.group(2)} (prebuilt binary in tree)")
    for m in re.finditer(r"\.(plugin|macro)\s*\(\s*name:\s*\"([^\"]+)\"", t):
        F.add("medium", "SWIFT-" + m.group(1).upper() + "-TARGET", "Package.swift", f"{m.group(2)} executes at build/compile time")
    if re.search(r"unsafeFlags\s*\(", t):
        F.add("high", "SWIFT-UNSAFE-FLAGS", "Package.swift", "unsafeFlags in settings")
    for m in re.finditer(r"\.package\s*\(\s*(?:url:\s*\"([^\"]+)\"|path:\s*\"([^\"]+)\")\s*,?\s*(?:branch:\s*\"([^\"]+)\"|\.branch\(\"([^\"]+)\"\)|revision:|exact:|from:|\"[0-9])?", t):
        url, path, br1, br2 = m.groups()
        if br1 or br2:
            F.add("high", "SWIFT-BRANCH-DEP", "Package.swift", f"{url or path} tracks branch {br1 or br2} (unpinned)")
        if url and not url.startswith("https://"):
            F.add("medium", "SWIFT-DEP-INSECURE-URL", "Package.swift", url)
        if path and ".." in path:
            F.add("medium", "SWIFT-PATH-DEP-ESCAPE", "Package.swift", path)
    pr = os.path.join(repo, "Package.resolved")
    if not os.path.exists(pr) and ".package(" in t:
        F.add("high", "SWIFT-NO-RESOLVED", "Package.swift", "dependencies without Package.resolved pins")
    elif os.path.exists(pr):
        try:
            d = json.load(open(pr))
            pins = d.get("pins") or d.get("object", {}).get("pins", [])
            for p in pins:
                st = p.get("state", {})
                if st.get("branch"):
                    F.add("high", "SWIFT-RESOLVED-BRANCH", "Package.resolved", f"{p.get('identity') or p.get('package')} pinned to branch {st['branch']}")
                if not st.get("revision"):
                    F.add("medium", "SWIFT-RESOLVED-NO-REVISION", "Package.resolved", f"{p.get('identity') or p.get('package')} without revision")
        except Exception:
            F.add("high", "SWIFT-RESOLVED-MALFORMED", "Package.resolved", "unparseable")
    for dp, dns, fns in os.walk(repo):
        dns[:] = [d for d in dns if d not in (".git", ".build")]
        for fn in fns:
            if fn.endswith(".swift"):
                rel = os.path.relpath(os.path.join(dp, fn), repo)
                try:
                    src = open(os.path.join(dp, fn), errors="replace").read()
                except Exception:
                    continue
                if re.search(r"\b(Unmanaged|unsafeBitCast|UnsafeMutableRawPointer|dlopen|dlsym|NSTask|Process\(\))\b", src):
                    F.add("medium", "SWIFT-UNSAFE-API", rel, "unsafe pointer / dynamic loading / process spawn")
                if re.search(r"NSAllowsArbitraryLoads|allowsArbitraryLoads|setAllowsAnyHTTPSCertificate|serverTrust\s*=\s*nil|URLSessionDelegate.*didReceive challenge", src):
                    F.add("high", "SWIFT-TLS-WEAKENING", rel, "ATS bypass / certificate validation override")
                if re.search(r"UserDefaults.*(password|token|secret)", src, re.I):
                    F.add("high", "SWIFT-INSECURE-STORAGE", rel, "secret-like value in UserDefaults")
    for plist in ("Info.plist",):
        for dp, dns, fns in os.walk(repo):
            if plist in fns:
                t = open(os.path.join(dp, plist), errors="replace").read()
                if "NSAllowsArbitraryLoads" in t and "<true/>" in t:
                    F.add("high", "SWIFT-ATS-DISABLED", os.path.relpath(os.path.join(dp, plist), repo), "NSAllowsArbitraryLoads true")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--base-ref", default="")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    F_ = F()
    roots = set()
    for dp, dns, fns in os.walk(a.repo):
        dns[:] = [d for d in dns if d not in (".git", "node_modules", "target", ".build", ".venv", "venv")]
        if any(m in fns for m in ("package.json", "Cargo.toml", "Package.swift", "setup.py", "pyproject.toml")) or any(re.match(r"requirements.*\.txt$", f) for f in fns):
            roots.add(dp)
    for root in sorted(roots)[:200]:
        rel = os.path.relpath(root, a.repo)
        before = len(F_.items)
        for fn in (node, python, rust, swift):
            try:
                fn(root, a.base_ref if root == a.repo else "", F_)
            except Exception as e:
                F_.add("medium", "SUPPLY-CHAIN-ERROR", fn.__name__, f"{type(e).__name__}: {str(e)[:150]}")
        if rel != ".":
            for it in F_.items[before:]:
                it["path"] = f"{rel}/{it['path']}"
    with open(a.out, "w") as f:
        json.dump({"items": F_.items, "limitations": ["typosquat list is a vendored sample, not the full registry",
                                                     "maintainer/ownership transitions require registry metadata (network); not checked"]}, f, indent=2)
    print(f"[supply-chain] {len(F_.items)} findings")


if __name__ == "__main__":
    main()
