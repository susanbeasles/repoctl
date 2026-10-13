#!/usr/bin/env bash
# Isolated executor for repository-controlled code (project tooling, plugins, build scripts).
#
#   sandbox_exec.sh --src <dir> --out <dir> [--ro <dir>:<mount>]... [--timeout N] [--mem-mb N] [--pids N] -- <command...>
#
# Boundary (bubblewrap): fresh user/pid/ipc/uts/cgroup namespaces, NO network namespace
# interfaces except lo, source mounted read-only at /work, toolchain dirs mounted read-only,
# a single writable /out, tmpfs /tmp and /home, no /proc/sys writes, no new privileges,
# seccomp from bwrap defaults, rlimits for CPU/memory/pids/file size. The evidence
# directory, the depot, GITHUB_* env, tokens and the runner's home are NOT visible.
# Exit codes: 0 ok, 124 timeout, 125 sandbox unavailable, else the command's.
set -euo pipefail
SRC=""; OUT=""; TIMEOUT=900; MEM_MB=4096; PIDS=512; ROS=(); ENVS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --src) SRC="$2"; shift 2;; --out) OUT="$2"; shift 2;; --ro) ROS+=("$2"); shift 2;; --env) ENVS+=("$2"); shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;; --mem-mb) MEM_MB="$2"; shift 2;; --pids) PIDS="$2"; shift 2;;
    --) shift; break;; *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
[ -n "$SRC" ] && [ -n "$OUT" ] && [ $# -gt 0 ] || { echo "usage: --src --out -- cmd" >&2; exit 2; }
command -v bwrap >/dev/null || { echo "bwrap not installed" >&2; exit 125; }
mkdir -p "$OUT"
ARGS=(--unshare-all --die-with-parent --new-session --clearenv
      --setenv PATH /usr/local/bin:/usr/bin:/bin --setenv HOME /home/sandbox --setenv TMPDIR /tmp --setenv LANG C.UTF-8
      --setenv CI 1 --setenv SANDBOX 1 --setenv npm_config_ignore_scripts true --setenv npm_config_update_notifier false --setenv NO_COLOR 1
      --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --symlink usr/lib64 /lib64 --ro-bind /etc/ssl /etc/ssl --ro-bind /etc/alternatives /etc/alternatives
      --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache --ro-bind-try /etc/ld.so.conf /etc/ld.so.conf --ro-bind-try /etc/ld.so.conf.d /etc/ld.so.conf.d --ro-bind-try /opt /opt
      --tmpfs /tmp --tmpfs /home --dir /home/sandbox --proc /proc --dev /dev
      --ro-bind "$SRC" /work --bind "$OUT" /out --chdir /work --hostname sandbox)
for ro in "${ROS[@]}"; do ARGS+=(--ro-bind "${ro%%:*}" "${ro##*:}"); done
for kv in "${ENVS[@]}"; do ARGS+=(--setenv "${kv%%=*}" "${kv#*=}"); done
# rlimits inside the sandbox via a wrapper shell; bwrap has no --rlimit, so apply with ulimit in the child.
WRAP="ulimit -v $((MEM_MB*1024)) -u $PIDS -f 2097152 -t $TIMEOUT 2>/dev/null; exec \"\$@\""
set +e
timeout --kill-after=10 "$TIMEOUT" bwrap "${ARGS[@]}" -- /bin/sh -c "$WRAP" sh "$@"
RC=$?
set -e
# Make everything the sandbox wrote non-executable and owned by us; the out dir is DATA.
find "$OUT" -type f -exec chmod a-x {} + 2>/dev/null || true
find "$OUT" -type l -delete 2>/dev/null || true
exit $RC
