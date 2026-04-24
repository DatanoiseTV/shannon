#!/usr/bin/env bash
# push-build.sh — rsync the workspace to the Linux build host and run
# cargo there. Exists because shannon is Linux-only (eBPF) and the dev
# workstation is a mac; this is the tight iteration loop.
#
# Operates at the workspace root, so it doesn't care which crate or
# which module you're working on — the same cargo invocation hits
# whatever you ask for.
#
# Usage:
#   scripts/push-build.sh                     # rsync + cargo build (workspace)
#   scripts/push-build.sh build               # rsync + cargo build
#   scripts/push-build.sh build -p shannon    # rsync + build one package
#   scripts/push-build.sh check               # rsync + cargo check
#   scripts/push-build.sh clippy              # rsync + cargo clippy
#   scripts/push-build.sh test                # rsync + cargo test
#   scripts/push-build.sh test parsers        # rsync + cargo test parsers
#   scripts/push-build.sh test -p shannon foo # rsync + scoped cargo test
#   scripts/push-build.sh run shannon --help  # rsync + cargo run --bin shannon
#   scripts/push-build.sh cargo fmt --check   # rsync + arbitrary cargo subcommand
#   scripts/push-build.sh smoke               # rsync + build + ./scripts/udp-smoke.sh on host
#   scripts/push-build.sh sync                # rsync only
#   scripts/push-build.sh shell               # rsync + interactive ssh
#   scripts/push-build.sh exec <cmd...>       # rsync + run arbitrary remote command
#
# Env overrides:
#   SHANNON_HOST   default syso@10.243.243.8
#   SHANNON_PATH   default ~/shannon
#   SHANNON_CARGO  default `source ~/.cargo/env` (pulls in the remote's nightly)

set -euo pipefail

HOST=${SHANNON_HOST:-syso@10.243.243.8}
# Path relative to the remote user's home. Keeping it tilde-free so
# local bash doesn't expand it to the *local* $HOME when the default
# kicks in.
REMOTE_PATH=${SHANNON_PATH:-shannon}
CARGO_ENV=${SHANNON_CARGO:-'source $HOME/.cargo/env'}

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

sync() {
  # `:$REMOTE_PATH` (no leading slash) is rsync's shorthand for
  # relative-to-remote-home. That's what we want — the remote expands
  # it, not the local shell.
  rsync -a --delete \
    --exclude target \
    --exclude .git \
    "$repo_root/" "$HOST:$REMOTE_PATH/"
}

# Run an arbitrary cargo invocation at the workspace root. Extra args
# pass straight through, so `cargo <sub> <args...>` is literal.
remote_cargo() {
  ssh "$HOST" "$CARGO_ENV; cd \$HOME/$REMOTE_PATH && cargo $*"
}

# Run an arbitrary shell command at the workspace root.
remote_exec() {
  ssh "$HOST" "cd \$HOME/$REMOTE_PATH && $*"
}

action=${1:-build}
shift || true

case "$action" in
  sync)
    sync
    ;;
  build|check|clippy|test|run|doc|bench|fmt)
    sync
    remote_cargo "$action" "$@"
    ;;
  cargo)
    sync
    remote_cargo "$@"
    ;;
  smoke)
    sync
    remote_cargo build
    remote_exec "bash scripts/udp-smoke.sh"
    ;;
  exec)
    sync
    remote_exec "$@"
    ;;
  shell)
    sync
    ssh "$HOST"
    ;;
  -h|--help|help)
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    echo "unknown action: $action" >&2
    echo "run '$0 help' to see available actions" >&2
    exit 2
    ;;
esac
