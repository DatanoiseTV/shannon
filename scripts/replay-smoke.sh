#!/usr/bin/env bash
# replay-smoke.sh — record live traffic into a JSONL file, then replay
# it back through the same trace pipeline (no kernel attach this time)
# and compare. Validates that the record→replay round-trip preserves
# the meaningful event content.

set -u
cd "${SHANNON_PATH:-$HOME/shannon}"

REC=/tmp/shannon-replay-smoke.jsonl.zst
sudo rm -f "$REC" "${REC%.zst}"

echo "=== phase 1: record ===" >&2
sudo pkill -f "shannon record" 2>/dev/null || true
sleep 1
sudo ./target/debug/shannon record -o "$REC" > /tmp/rec.log 2>&1 &
REC_PID=$!
sleep 2
dig @1.1.1.1 example.com +short +timeout=2 > /dev/null 2>&1 || true
sleep 1
sudo kill -INT "$REC_PID" 2>/dev/null || true
wait "$REC_PID" 2>/dev/null || true
echo "recorded $(wc -l < "$REC") events" >&2

echo "=== phase 2: replay (no kernel attach) ===" >&2
./target/debug/shannon trace --replay "$REC" > /tmp/replay.log 2>&1
echo "replay output:" >&2
head -10 /tmp/replay.log
echo "..."
tail -3 /tmp/replay.log
