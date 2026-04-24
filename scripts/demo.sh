#!/usr/bin/env bash
# scripts/demo.sh — exercise shannon end-to-end against real traffic.
#
# Records ~25 s of activity from a battery of small clients (DNS, HTTP/1,
# TLS, sqlite, redis, mqtt, coap), then replays the capture through
# `shannon trace --protocol …` and `shannon analyze` so each feature
# shows up in isolation. Designed to be re-runnable; output is captured
# into /tmp/shannon-demo/ and survives reruns.
#
# Requires:
#   * sudo (for the BPF loader)
#   * a built shannon binary at $SHANNON, default ./target/release/shannon
#   * dig, curl, sqlite3, redis-cli, mosquitto_pub, coap-client-notls
#   * a local redis-server + mosquitto broker on the standard ports

set -euo pipefail

SHANNON="${SHANNON:-$HOME/shannon/target/release/shannon}"
OUT_DIR="${OUT_DIR:-/tmp/shannon-demo}"
CAPTURE="$OUT_DIR/capture.jsonl.zst"
DURATION="${DURATION:-25}"

mkdir -p "$OUT_DIR"
rm -f "$CAPTURE"

if [[ ! -x "$SHANNON" ]]; then
  echo "shannon binary not found at $SHANNON" >&2
  exit 1
fi

banner() {
  printf '\n=========================================================\n'
  printf '== %s\n' "$1"
  printf '=========================================================\n'
}

# ---------------------------------------------------------------------------
banner "1. shannon doctor — environment check"
# ---------------------------------------------------------------------------
sudo "$SHANNON" doctor 2>&1 | tee "$OUT_DIR/01-doctor.txt"

# ---------------------------------------------------------------------------
banner "2. shannon record — capture ${DURATION}s of traffic"
# ---------------------------------------------------------------------------
echo "Recording to $CAPTURE for ${DURATION}s in the background..."
sudo "$SHANNON" record \
  -o "$CAPTURE" \
  --max-duration "${DURATION}s" \
  >"$OUT_DIR/02-record.log" 2>&1 &
RECORD_PID=$!

# Stand up a local CoAP server so the demo's coap-client GETs succeed
# (otherwise libcoap retries with backoff and we lose the response leg).
COAP_LOG="$OUT_DIR/coap-server.log"
coap-server-notls -A 127.0.0.1 -p 5683 >"$COAP_LOG" 2>&1 &
COAP_PID=$!
trap 'kill "$COAP_PID" 2>/dev/null || true' EXIT

# Give the BPF programs and the CoAP server a moment to come up.
sleep 2

# ---------------------------------------------------------------------------
banner "3. Generating traffic — DNS, HTTP, TLS, SQLite, Redis, MQTT, CoAP"
# ---------------------------------------------------------------------------

for i in 1 2 3; do
  echo "[$i] dig example.com..."
  dig +short example.com >/dev/null 2>&1 || true
  dig +short www.iana.org >/dev/null 2>&1 || true

  echo "[$i] curl http://detectportal.firefox.com/success.txt"
  curl -s -o /dev/null -m 5 http://detectportal.firefox.com/success.txt || true

  echo "[$i] curl https://www.cloudflare.com/cdn-cgi/trace"
  curl -s -o /dev/null -m 5 https://www.cloudflare.com/cdn-cgi/trace || true

  echo "[$i] sqlite3 :memory:"
  sqlite3 :memory: \
    "CREATE TABLE users(id INTEGER, name TEXT); \
     INSERT INTO users VALUES(1, 'alice'); \
     INSERT INTO users VALUES(2, 'bob'); \
     SELECT * FROM users WHERE name = 'alice';" >/dev/null

  echo "[$i] redis-cli SET/GET/INCR"
  redis-cli SET demo:greeting "hello-from-shannon" >/dev/null
  redis-cli GET demo:greeting >/dev/null
  redis-cli INCR demo:counter >/dev/null

  echo "[$i] mosquitto_pub demo/topic"
  mosquitto_pub -h 127.0.0.1 -t "demo/topic" -m "tick=$i" -q 0 || true

  echo "[$i] coap-client-notls coap://localhost:5683/.well-known/core"
  coap-client-notls -m get "coap://127.0.0.1:5683/.well-known/core" >/dev/null 2>&1 \
    || true

  sleep 1
done

# ---------------------------------------------------------------------------
banner "4. Waiting for recorder to finish"
# ---------------------------------------------------------------------------
wait "$RECORD_PID" || true
echo "Capture complete: $(ls -lh "$CAPTURE" | awk '{print $5, $9}')"

# ---------------------------------------------------------------------------
banner "5. shannon analyze — top endpoints + protocols"
# ---------------------------------------------------------------------------
sudo "$SHANNON" analyze "$CAPTURE" 2>&1 | tee "$OUT_DIR/05-analyze.txt"

# ---------------------------------------------------------------------------
banner "6. Per-protocol replay slices"
# ---------------------------------------------------------------------------

# Replay once and grep per protocol — the CLI's --protocol filter is a
# live-mode option, so for a recording we slice the full output instead.
echo "Producing the full replay stream..."
sudo "$SHANNON" trace --replay "$CAPTURE" >"$OUT_DIR/06-full.txt" 2>&1 || true
echo "Got $(wc -l <"$OUT_DIR/06-full.txt") lines."

slice() {
  local title="$1"; shift
  local file="$1"; shift
  local pattern="$1"
  echo
  echo "--- $title ---"
  grep -E "$pattern" "$OUT_DIR/06-full.txt" | head -n 12 | tee "$OUT_DIR/$file"
}

slice "DNS"               "06-dns.txt"     ' dns [→←] '
slice "HTTP/1"            "06-http.txt"    ' http [→←] '
slice "TLS handshake"     "06-tls.txt"     ' tls [→←] '
slice "Redis"             "06-redis.txt"   ' redis [→←] '
slice "MQTT"              "06-mqtt.txt"    ' mqtt [→←] '
slice "CoAP"              "06-coap.txt"    ' coap [→←] '
slice "SQLite (uprobes)"  "06-sqlite.txt"  '^[0-9:.]+ +SQL '
slice "Connection start"  "06-conn.txt"    ' CONN +'

banner "Done"
echo "All output saved under: $OUT_DIR"
ls -1 "$OUT_DIR"
