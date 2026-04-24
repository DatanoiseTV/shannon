#!/usr/bin/env bash
# cert-pin-smoke.sh — prove the pin-after-dump workflow end-to-end.
# Phase 1: dump certs seen during an https request.
# Phase 2: re-run with the same dir as --cert-pin — expect zero
#   "not in pinning allowlist" anomalies for the same request.
# Phase 3: re-run with an empty dir as --cert-pin — expect every
#   cert to flag NotPinned.

set -u

cd "${SHANNON_PATH:-$HOME/shannon}"
TMP=${TMP:-/tmp/cert-pin-smoke}
rm -rf "$TMP"
PIN_FULL=$TMP/pin-full
PIN_EMPTY=$TMP/pin-empty
mkdir -p "$PIN_FULL" "$PIN_EMPTY"

run_phase() {
  local label=$1; shift
  sudo pkill -f "shannon trace" 2>/dev/null || true
  sleep 1
  sudo ./target/debug/shannon trace "$@" > "$TMP/out-$label.log" 2>&1 &
  local BG=$!
  sleep 2
  curl -s https://example.com/ -o /dev/null || true
  sleep 2
  sudo kill "$BG" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "--- $label ---"
  grep -E "cert(-anomaly|  subject)" "$TMP/out-$label.log" | head -15
}

run_phase dump       --dump-certs "$PIN_FULL"
run_phase pinned     --cert-pin   "$PIN_FULL"
run_phase empty-pin  --cert-pin   "$PIN_EMPTY"
