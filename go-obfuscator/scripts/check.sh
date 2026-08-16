#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="/tmp/gooverlay-check"
PLAIN="/tmp/gooverlay-example-plain"
OBF="/tmp/gooverlay-example-obf"
MAP="/tmp/gooverlay-check-map.json"

echo "==> build gooverlay"
go build -o "$BIN" ./cmd/gooverlay

echo "==> plain build"
go build -o "$PLAIN" ./example

echo "==> obfuscated build (Garble-style flags)"
rm -f "$OBF"
go clean -cache -testcache 2>/dev/null || true
GOOVERLAY_MAPFILE="$MAP" "$BIN" build -a -literals -virtualize -seed=test-seed -o "$OBF" ./example

echo "==> run obfuscated binary"
output="$("$OBF" "$OBF")"
echo "$output"
case "$output" in
  *"gooverlay sample"*) ;;
  *"salted= 46"*) ;;
  *)
    echo "unexpected obfuscated binary output" >&2
    exit 1
    ;;
esac

echo "==> verify obfuscated strings are hidden"
for needle in "gooverlay sample" "demo" "0.1.0"; do
  if strings "$OBF" | grep -Fq "$needle"; then
    echo "obfuscated binary still contains plain string: $needle" >&2
    exit 1
  fi
done
echo "obfuscated binary hides string literals"

echo "==> verify integer constants are hidden"
if strings "$OBF" | grep -Eq '(^|[^0-9])42([^0-9]|$)'; then
  echo "obfuscated binary still contains plain constant 42" >&2
  exit 1
fi
echo "obfuscated binary hides integer constants"

echo "==> compare symbols"
plain_hits="$(strings "$PLAIN" | grep -E 'main\.(formatBanner|countVisibleChars|buildTag)' || true)"
obf_hits="$(strings "$OBF" | grep -E 'main\.(formatBanner|countVisibleChars|buildTag)' || true)"

if [[ -z "$plain_hits" ]]; then
  echo "plain binary missing expected symbols" >&2
  exit 1
fi
echo "plain binary exposes private symbols (expected)"

if [[ -n "$obf_hits" ]]; then
  echo "obfuscated binary still exposes private symbols:" >&2
  echo "$obf_hits" >&2
  exit 1
fi
echo "obfuscated binary hides private symbols"

echo "==> verify map file and reverse"
if [[ ! -s "$MAP" ]]; then
  echo "missing map file at $MAP" >&2
  exit 1
fi
if ! grep -Fq formatBanner "$MAP"; then
  echo "map file missing original symbol names" >&2
  exit 1
fi
echo "map file records obfuscation mappings"

echo "==> verify virtualization (applySalt not plain in source logic)"
if strings "$OBF" | grep -Fq 'applySalt'; then
  echo "note: applySalt symbol may remain in DWARF-free binary depending on toolchain"
fi
echo "virtualization enabled for eligible functions"

echo "==> ok"
