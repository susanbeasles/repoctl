#!/bin/sh
# agent-guard: unlock one quarantined path for the agent for one hour.
set -eu
[ $# -eq 1 ] || { echo "usage: $0 <repo-relative-path>"; exit 1; }
h=$(printf '%s' "$1" | shasum -a 256 | cut -c1-16)
touch ".agent-guard/UNLOCK-$h"
echo "unlocked $1 for 1 hour (marker UNLOCK-$h)"
