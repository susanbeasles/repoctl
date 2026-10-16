#!/bin/sh
# agent-guard: review and clear a supervisor HALT. Usage: resume.sh <session_id>
set -eu
m="$HOME/.agent-guard/HALT-$1"
[ -f "$m" ] || { echo "no halt marker for session $1"; exit 1; }
echo "== evidence =="; cat "$m"; echo
printf "clear halt for %s? [y/N] " "$1"; read -r a
[ "$a" = "y" ] && rm -f "$m" && echo "resumed"
