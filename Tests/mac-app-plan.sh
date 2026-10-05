#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
swift build
bin="$(swift build --show-bin-path)/repoctl"
task_dir=$(mktemp -d)
trap 'rm -rf "$task_dir"' EXIT
"$bin" app plan templates/apps/writer.example.json > "$task_dir/plan.json"
node --input-type=module - "$task_dir/plan.json" <<'JS'
import {readFileSync} from 'node:fs';import {createHash} from 'node:crypto';import assert from 'node:assert/strict';
const p=JSON.parse(readFileSync(process.argv[2])),bytes=Buffer.from(p.manifestBytes,'base64');
assert.equal(createHash('sha256').update(bytes).digest('hex'),p.manifestDigest);assert.deepEqual(JSON.parse(bytes),p.manifest);assert.deepEqual(p.manifest.default_permissions,{contents:'write'});assert.equal(p.registrationState,'not_registered');assert.equal(p.installationState,'not_installed');
console.log('PASS: manifest bytes independently verified; plan requests only writer permissions');
JS
python3 - "$task_dir" <<'PY'
import json,pathlib,sys
p=json.loads(pathlib.Path('templates/apps/writer.example.json').read_text());p['callback']='http://untrusted.example/callback'
(pathlib.Path(sys.argv[1])/'bad.json').write_text(json.dumps(p))
PY
if "$bin" app plan "$task_dir/bad.json"; then echo 'Insecure callback accepted' >&2; exit 1; fi
