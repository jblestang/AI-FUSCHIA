#!/usr/bin/env bash
# Verify obfuscated example output is stable across many build seeds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SEED_COUNT="${SEED_COUNT:-20}"
BIN="/tmp/gooverlay-seed-check"
OBF="/tmp/gooverlay-seed-obf"
WORK="/tmp/gooverlay-seed-work"

rm -rf "$WORK"
mkdir -p "$WORK"

echo "==> build gooverlay"
go build -o "$BIN" ./cmd/gooverlay

pass=0
fail=0
failures=()

verify_output() {
  local seed="$1"
  local output="$2"
  local ec="$3"

  if [[ "$ec" -ne 0 ]]; then
    failures+=("seed=$seed: exit code $ec")
    return 1
  fi
  for expected in "SecureLicense Demo" "session_id=" "license_score= 768" "licensed= true" "tier_len= 10"; do
    if ! grep -Fq "$expected" <<< "$output"; then
      failures+=("seed=$seed: missing output line: $expected")
      return 1
    fi
  done
  for forbidden in "__gooverlay_integrity" "__gooverlay_antidebug" "__gooverlay_antiemulation" "TracerPid:" "QEMU_ENV"; do
    if grep -aFq "$forbidden" "$OBF"; then
      failures+=("seed=$seed: exposes cleartext marker: $forbidden")
      return 1
    fi
  done
  return 0
}

echo "==> verify $SEED_COUNT seeds"
for i in $(seq 0 $((SEED_COUNT - 1))); do
  seed="stability-seed-$(printf '%03d' "$i")"
  mapfile="$WORK/map-$i.json"
  rm -f "$OBF"

  if ! GOOVERLAY_MAPFILE="$mapfile" "$BIN" build -a -max -seed="$seed" -o "$OBF" ./example >/dev/null 2>&1; then
    fail=$((fail + 1))
    failures+=("seed=$seed: build failed")
    continue
  fi

  ec=0
  output="$("$OBF" "host-$i" 2>&1)" || ec=$?
  if verify_output "$seed" "$output" "$ec"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
  fi

  if (( (i + 1) % 10 == 0 )); then
    echo "  ... checked $((i + 1))/$SEED_COUNT seeds ($pass pass, $fail fail)"
  fi
done

echo "==> results: $pass passed, $fail failed (of $SEED_COUNT seeds)"
if (( fail > 0 )); then
  echo "failures:" >&2
  for f in "${failures[@]}"; do
    echo "  - $f" >&2
  done
  exit 1
fi

echo "==> ok: stable across $SEED_COUNT seeds"
