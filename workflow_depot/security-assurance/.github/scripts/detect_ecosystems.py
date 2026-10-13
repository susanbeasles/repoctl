#!/usr/bin/env python3
"""Ecosystem detection from the git-tracked tree (no interpolation of shell booleans into Python)."""
import argparse, json, os, re, subprocess

PATTERNS = {
    "node": [r"(^|/)package\.json$"], "python": [r"(^|/)(pyproject\.toml|setup\.py|requirements[^/]*\.txt|uv\.lock|poetry\.lock)$", r"\.py$"],
    "rust": [r"(^|/)Cargo\.toml$"], "swift": [r"(^|/)Package\.swift$", r"\.swift$"], "shell": [r"\.(sh|bash|zsh|ksh)$"],
    "iac": [r"\.(tf|hcl|tfvars)$", r"(^|/)wrangler\.(toml|jsonc?)$"], "docker": [r"(^|/)[^/]*Dockerfile[^/]*$", r"(^|/)docker-compose[^/]*\.ya?ml$"],
    "workflows": [r"^\.github/workflows/[^/]+\.ya?ml$"], "go": [r"(^|/)go\.mod$"], "java": [r"(^|/)(pom\.xml|build\.gradle(\.kts)?)$"],
    "cpp": [r"\.(c|cc|cpp|cxx|h|hpp)$"], "openapi": [r"(^|/)(openapi|swagger)[^/]*\.(ya?ml|json)$"],
}
LOCKS = {"npm": r"(^|/)package-lock\.json$", "yarn": r"(^|/)yarn\.lock$", "pnpm": r"(^|/)pnpm-lock\.yaml$",
         "python": r"(^|/)(uv\.lock|poetry\.lock|requirements[^/]*\.txt)$", "cargo": r"(^|/)Cargo\.lock$", "swift": r"(^|/)Package\.resolved$"}
CODEQL = [("node", "javascript-typescript"), ("python", "python"), ("rust", "rust"), ("swift", "swift"), ("go", "go"), ("java", "java-kotlin"), ("cpp", "c-cpp"), ("workflows", "actions")]
# Languages CodeQL can analyse without running a project build. Everything else needs an explicit, operator-approved build command.
CODEQL_NO_BUILD = {"javascript-typescript", "python", "actions", "ruby"}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--repo", required=True); ap.add_argument("--out", required=True); a = ap.parse_args()
    files = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "ls-files", "-z"], cwd=a.repo, capture_output=True, check=True).stdout.decode("utf-8", "surrogateescape").split("\0")
    files = [f for f in files if f]
    eco = {k: any(re.search(p, f) for p in pats for f in files) for k, pats in PATTERNS.items()}
    locks = {k: any(re.search(p, f) for f in files) for k, p in LOCKS.items()}
    langs = [l for k, l in CODEQL if eco[k]]
    web = False
    for mf in ("package.json", "requirements.txt", "pyproject.toml", "Cargo.toml", "Package.swift", "go.mod"):
        fp = os.path.join(a.repo, mf)
        if os.path.exists(fp):
            t = open(fp, errors="replace").read().lower()
            if re.search(r"\b(express|fastify|koa|hapi|@nestjs/core|next|nuxt|remix|sveltekit|react-dom|django|flask|fastapi|starlette|aiohttp|tornado|actix-web|axum|rocket|warp|vapor|hummingbird|gin-gonic|net/http|echo)\b", t):
                web = True
    eco["web_app"] = web
    eco["openapi"] = eco.get("openapi", False) or web and any(re.search(r"(^|/)(openapi|swagger)[^/]*\.(ya?ml|json)$", f) for f in files)
    doc = {"schema_version": 2, **eco, "lockfiles": locks, "codeql_languages": langs,
           "codeql_requires_build": [l for l in langs if l not in CODEQL_NO_BUILD], "file_count": len(files),
           "summary": " ".join(f"{k}={str(v).lower()}" for k, v in eco.items())}
    with open(a.out, "w") as f:
        json.dump(doc, f, indent=2)
    gh = os.environ.get("GITHUB_OUTPUT")
    if gh:
        with open(gh, "a") as f:
            f.write(f"matrix={json.dumps(doc)}\ncodeql_languages={json.dumps(langs)}\n")
            for k in ("shell", "node", "python", "rust", "swift"):
                f.write(f"has_{k}={str(eco[k]).lower()}\n")
    print(doc["summary"], "| codeql:", langs)


if __name__ == "__main__":
    main()
