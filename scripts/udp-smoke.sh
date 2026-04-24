#!/usr/bin/env bash
# udp-smoke.sh — run on the Linux host. Attaches shannon, generates a
# handful of representative UDP flows (DNS, NTP), and prints captured
# events. Used to smoke-test the UDP kprobe path end-to-end.

set -u

sudo pkill -f "shannon trace" 2>/dev/null || true
sleep 1
cd "${SHANNON_PATH:-$HOME/shannon}"

sudo ./target/debug/shannon trace > /tmp/shout.log 2>&1 &
BG=$!

# Let it attach.
sleep 2

echo "=== firing udp flows ===" >&2
dig @1.1.1.1 example.com +short +timeout=2 > /dev/null 2>&1 || true

python3 - <<'PY' 2>/dev/null || true
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)
try:
    s.sendto(bytes([0x23]) + bytes(47), ('pool.ntp.org', 123))
    s.recvfrom(128)
except Exception:
    pass
PY

# Let the responses arrive.
sleep 2

sudo kill "$BG" 2>/dev/null || true
wait 2>/dev/null || true

echo "--- captured ---"
head -40 /tmp/shout.log
