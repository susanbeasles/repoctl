#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
swift build
bin=$(swift build --show-bin-path)/repoctl
scratch=$(mktemp -d)
# Keep this path: enrolled keys/trust are intentionally not automatically deleted.
policy="$scratch/policy.json"
printf '{"repository":"example/demo","revision":1}\n' > "$policy"
"$bin" policy seal "$policy" --provider keychain --approve
cp "$policy.seal.json" "$scratch/old-seal.json"
"$bin" policy verify "$policy"
printf '{"repository":"unexpected/mirror","revision":1}\n' > "$policy"
if "$bin" policy verify "$policy"; then echo 'Tampering accepted' >&2; exit 1; fi
"$bin" policy seal "$policy" --provider keychain --approve
cp "$scratch/old-seal.json" "$policy.seal.json"
if "$bin" policy verify "$policy"; then echo 'Rollback accepted' >&2; exit 1; fi
printf 'Tampering and rollback rejected. Test enrollment retained at %s\n' "$scratch"
