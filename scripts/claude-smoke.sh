#!/usr/bin/env bash
# claude-smoke.sh — run on the Linux LAB host (NOT the dev laptop).
# Drives the `claude` binary through a couple of unauthenticated calls
# while shannon trace is attached, so we can see what wire traffic
# Claude Code makes on startup.
#
# IMPORTANT: this script ONLY ever kills the background shannon process
# it started itself, by tracked PID. It never `pkill`-s `claude` —
# the dev laptop has many active claude sessions and we mustn't
# touch them. Even though we're on a different host, we keep the same
# discipline so the script is safe to copy elsewhere.

set -u
cd "${SHANNON_PATH:-$HOME/shannon}"

# Background shannon, capture its exact PID. NEVER do a wildcard kill.
sudo ./target/debug/shannon trace > /tmp/claude-shout.log 2>&1 &
SH_PID=$!
sleep 2

echo "=== claude --version (no auth required) ===" >&2
claude --version 2>&1 || true
echo "=== claude --help (first lines) ===" >&2
claude --help 2>&1 | head -5 || true

# Anything that requires an actual prompt would block on auth; we
# don't have a key in this lab box, so calls hit api.anthropic.com
# at the auth check path. That's the wire traffic we want to see.
echo "=== claude doctor (touches the API for self-check) ===" >&2
timeout 10 claude doctor 2>&1 | head -10 || true

sleep 2
sudo kill "$SH_PID" 2>/dev/null || true
# Wait briefly for shannon to flush; do NOT use `wait` without the
# explicit PID argument or it would also wait on any other background
# children the shell happens to remember.
wait "$SH_PID" 2>/dev/null || true

echo "--- captured TLS+HTTP+UDP lines mentioning anthropic ---"
grep -iE "anthropic|claude|claude-code|x-api-key" /tmp/claude-shout.log | head -30

echo "--- raw event lines (first 30) ---"
head -30 /tmp/claude-shout.log
