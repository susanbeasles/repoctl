#!/usr/bin/env python3
"""
Install a tool from policy/tool-registry.yml with mandatory SHA-256 verification.

  install_tool.py --registry policy/tool-registry.yml --tool trivy --dest $RUNNER_TEMP/tools

Refuses (exit 3) on any digest mismatch. Writes <dest>/qualification/<tool>.json
with what was installed and the verified digest, so the result records can carry
tool provenance.
"""
import argparse
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import urllib.request

import yaml


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", required=True)
    ap.add_argument("--tool", required=True)
    ap.add_argument("--dest", required=True)
    a = ap.parse_args()

    with open(a.registry) as f:
        reg = yaml.safe_load(f)
    spec = reg["tools"].get(a.tool)
    if not spec:
        print(f"::error::tool {a.tool} is not in the registry (unqualified tools are not installable)")
        sys.exit(2)

    bindir = os.path.join(a.dest, "bin")
    qdir = os.path.join(a.dest, "qualification")
    os.makedirs(bindir, exist_ok=True)
    os.makedirs(qdir, exist_ok=True)

    req = urllib.request.Request(spec["url"], headers={"User-Agent": "security-assurance-installer"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != spec["sha256"]:
        print(f"::error::DIGEST MISMATCH for {a.tool}: expected {spec['sha256']} got {digest}. Refusing to install.")
        sys.exit(3)

    name = os.path.basename(spec["binary"])
    target = os.path.join(bindir, name)
    if spec["archive"] == "binary":
        with open(target, "wb") as f:
            f.write(data)
    elif spec["archive"] == "zip":
        import zipfile
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            info = zf.getinfo(spec["binary"])
            if info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:
                print(f"::error::{spec['binary']} in archive is not a regular file"); sys.exit(3)
            with zf.open(info) as src, open(target, "wb") as dst:
                dst.write(src.read())
    else:
        mode = "r:xz" if spec["archive"] == "tar.xz" else "r:gz"
        with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
            member = tf.getmember(spec["binary"])
            if not member.isfile():
                print(f"::error::{spec['binary']} in archive is not a regular file")
                sys.exit(3)
            with tf.extractfile(member) as src, open(target, "wb") as dst:
                dst.write(src.read())
    os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    rec = {"tool": a.tool, "version": spec["version"], "source": spec["url"], "sha256": digest,
           "verified_against_registry": True, "upstream_checksums": spec.get("upstream_checksums"),
           "cross_checked": spec.get("cross_checked", False), "binary": target,
           "capabilities": spec.get("capabilities", []), "blind_spots": spec.get("blind_spots", [])}
    with open(os.path.join(qdir, f"{a.tool}.json"), "w") as f:
        json.dump(rec, f, indent=2)
    print(f"[install] {a.tool} {spec['version']} sha256:{digest[:16]} -> {target}")
    gh_path = os.environ.get("GITHUB_PATH")
    if gh_path:
        with open(gh_path, "a") as f:
            f.write(bindir + "\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"version={spec['version']}\ndigest=sha256:{digest}\nbin={target}\n")


if __name__ == "__main__":
    main()
