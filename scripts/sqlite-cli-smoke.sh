#!/usr/bin/env bash
# sqlite-cli-smoke.sh — drive the `sqlite3` CLI binary directly
# (separate from the Python module path). Confirms libsqlite3
# uprobes catch queries from any dynamic-linked sqlite consumer.

set -u

sudo pkill -f "shannon trace" 2>/dev/null || true
sleep 1
cd "${SHANNON_PATH:-$HOME/shannon}"

sudo ./target/debug/shannon trace > /tmp/shout.log 2>&1 &
BG=$!
sleep 2

TMPDB=$(mktemp --suffix=.db)
trap 'rm -f "$TMPDB"' EXIT

echo "=== firing sqlite3-cli queries ===" >&2
sqlite3 "$TMPDB" <<'SQL'
CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE);
INSERT INTO users (email) VALUES ('alice@example.com'), ('bob@example.com');
SELECT email FROM users WHERE id = 1;
SQL

sleep 1
sudo kill "$BG" 2>/dev/null || true
wait 2>/dev/null || true

echo "--- captured (SQL lines) ---"
grep -E "^.{12}  SQL " /tmp/shout.log | head -20
