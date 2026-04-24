#!/usr/bin/env bash
# sqlite-smoke.sh — run on the Linux host. Starts shannon, issues a
# handful of libsqlite3 queries via Python (which dlopens libsqlite3),
# and prints the captured events.

set -u

sudo pkill -f "shannon trace" 2>/dev/null || true
sleep 1
cd "${SHANNON_PATH:-$HOME/shannon}"

sudo ./target/debug/shannon trace > /tmp/shout.log 2>&1 &
BG=$!
sleep 2

echo "=== firing sqlite queries ===" >&2
python3 - <<'PY'
import sqlite3, os, tempfile
p = os.path.join(tempfile.gettempdir(), "shannon-smoke.db")
conn = sqlite3.connect(p)
c = conn.cursor()
c.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, name TEXT)")
c.execute("INSERT INTO t (name) VALUES ('alice'), ('bob')")
conn.commit()
c.execute("SELECT id, name FROM t WHERE name = 'alice'")
_ = c.fetchall()
conn.close()
PY

sleep 2
sudo kill "$BG" 2>/dev/null || true
wait 2>/dev/null || true

echo "--- captured (SQL lines) ---"
grep -E "^.{12}  SQL " /tmp/shout.log | head -20
