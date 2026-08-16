#!/usr/bin/env bash
# Stability across many seeds + plain vs obfuscated overhead (build, size, runtime).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SEED_COUNT="${SEED_COUNT:-20}"
RUN_ITER="${RUN_ITER:-10000}"
REPRESENTATIVE_SEED="${REPRESENTATIVE_SEED:-test-seed}"
BIN="/tmp/gooverlay-overhead-bin"
PLAIN="/tmp/gooverlay-overhead-plain"
OBF="/tmp/gooverlay-overhead-obf"
WORK="/tmp/gooverlay-overhead-work"

now_ms() {
  date +%s%N | awk '{printf "%.3f", $1/1000000}'
}

elapsed_ms() {
  awk -v start="$1" -v end="$2" 'BEGIN {printf "%.3f", end - start}'
}

pct_overhead() {
  awk -v base="$1" -v val="$2" 'BEGIN {
    if (base <= 0) { print "n/a"; exit }
    printf "%+.1f%%", (val - base) / base * 100
  }'
}

human_bytes() {
  awk -v b="$1" 'BEGIN {
    if (b >= 1048576) printf "%.2f MiB (%.0f bytes)", b/1048576, b
    else if (b >= 1024) printf "%.2f KiB (%.0f bytes)", b/1024, b
    else printf "%.0f bytes", b
  }'
}

bench_runtime_ms() {
  local exe="$1"
  local runs="$2"
  local start end
  start="$(now_ms)"
  for ((i = 0; i < runs; i++)); do
    "$exe" "bench-host" >/dev/null
  done
  end="$(now_ms)"
  elapsed_ms "$start" "$end"
}

bench_build_ms() {
  local label="$1"
  shift
  local start end
  start="$(now_ms)"
  "$@" >/dev/null 2>&1
  end="$(now_ms)"
  elapsed_ms "$start" "$end"
}

rm -rf "$WORK"
mkdir -p "$WORK"

echo "==> build gooverlay tool"
go build -o "$BIN" ./cmd/gooverlay

echo "==> plain baseline (build + size + ${RUN_ITER} runs)"
plain_build_ms="$(bench_build_ms plain go build -o "$PLAIN" ./example)"
plain_size="$(stat -c%s "$PLAIN")"
plain_run_ms="$(bench_runtime_ms "$PLAIN" "$RUN_ITER")"
plain_per_run_us="$(awk -v ms="$plain_run_ms" -v n="$RUN_ITER" 'BEGIN {printf "%.2f", ms/n*1000}')"

echo "==> obfuscated baseline (-literals -virtualize, seed=$REPRESENTATIVE_SEED)"
rm -f "$OBF"
obf_build_ms="$(bench_build_ms obf env GOOVERLAY_MAPFILE="$WORK/map-baseline.json" "$BIN" build -a -literals -virtualize -seed="$REPRESENTATIVE_SEED" -o "$OBF" ./example)"
obf_size="$(stat -c%s "$OBF")"
obf_run_ms="$(bench_runtime_ms "$OBF" "$RUN_ITER")"
obf_per_run_us="$(awk -v ms="$obf_run_ms" -v n="$RUN_ITER" 'BEGIN {printf "%.2f", ms/n*1000}')"

echo ""
echo "==> overhead summary (representative seed: $REPRESENTATIVE_SEED)"
printf "%-22s %14s %14s %12s\n" "metric" "plain" "obfuscated" "overhead"
printf "%-22s %14s %14s %12s\n" "--------------------" "--------------" "--------------" "------------"
printf "%-22s %11.0f ms %11.0f ms %12s\n" "build time" "$plain_build_ms" "$obf_build_ms" "$(pct_overhead "$plain_build_ms" "$obf_build_ms")"
printf "%-22s %14s %14s %12s\n" "binary size" "$(human_bytes "$plain_size")" "$(human_bytes "$obf_size")" "$(pct_overhead "$plain_size" "$obf_size")"
printf "%-22s %11.0f ms %11.0f ms %12s\n" "runtime ($RUN_ITER runs)" "$plain_run_ms" "$obf_run_ms" "$(pct_overhead "$plain_run_ms" "$obf_run_ms")"
printf "%-22s %11s us %11s us\n" "per execution" "$plain_per_run_us" "$obf_per_run_us"

echo ""
echo "==> stability + per-seed build/size across $SEED_COUNT seeds"
pass=0
fail=0
failures=()
sum_build=0
sum_size=0
min_build=""
max_build=""
min_size=""
max_size=""

verify_output() {
  local seed="$1"
  local output="$2"
  local ec="$3"

  if [[ "$ec" -ne 0 ]]; then
    failures+=("seed=$seed: exit code $ec")
    return 1
  fi
  for expected in "SecureLicense Demo" "license_score= 768" "licensed= true" "tier_len= 10"; do
    if ! grep -Fq "$expected" <<< "$output"; then
      failures+=("seed=$seed: missing output line: $expected")
      return 1
    fi
  done
  for needle in "__gooverlay_integrity" "__gooverlay_antidebug" "__gooverlay_antiemulation"; do
    if ! grep -aFq "$needle" "$OBF"; then
      failures+=("seed=$seed: missing security symbol: $needle")
      return 1
    fi
  done
  return 0
}

for i in $(seq 0 $((SEED_COUNT - 1))); do
  seed="stability-seed-$(printf '%03d' "$i")"
  mapfile="$WORK/map-$i.json"
  rm -f "$OBF"

  build_start="$(now_ms)"
  if ! GOOVERLAY_MAPFILE="$mapfile" "$BIN" build -a -literals -virtualize -seed="$seed" -o "$OBF" ./example >/dev/null 2>&1; then
    fail=$((fail + 1))
    failures+=("seed=$seed: build failed")
    continue
  fi
  build_end="$(now_ms)"
  build_ms="$(elapsed_ms "$build_start" "$build_end")"
  size_bytes="$(stat -c%s "$OBF")"

  sum_build="$(awk -v s="$sum_build" -v v="$build_ms" 'BEGIN {print s + v}')"
  sum_size=$((sum_size + size_bytes))
  if [[ -z "$min_build" ]] || awk -v a="$build_ms" -v b="$min_build" 'BEGIN {exit !(a < b)}'; then min_build="$build_ms"; fi
  if [[ -z "$max_build" ]] || awk -v a="$build_ms" -v b="$max_build" 'BEGIN {exit !(a > b)}'; then max_build="$build_ms"; fi
  if [[ -z "$min_size" ]] || (( size_bytes < min_size )); then min_size="$size_bytes"; fi
  if [[ -z "$max_size" ]] || (( size_bytes > max_size )); then max_size="$size_bytes"; fi

  ec=0
  output="$("$OBF" "host-$i" 2>&1)" || ec=$?
  if verify_output "$seed" "$output" "$ec"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
  fi

  if (( (i + 1) % 20 == 0 )); then
    echo "  ... checked $((i + 1))/$SEED_COUNT seeds ($pass pass, $fail fail)"
  fi
done

avg_build="$(awk -v s="$sum_build" -v n="$pass" 'BEGIN { if (n==0) print 0; else printf "%.3f", s/n }')"
avg_size=$((sum_size / (pass > 0 ? pass : 1)))

echo ""
echo "==> stability: $pass passed, $fail failed (of $SEED_COUNT seeds)"
if (( fail > 0 )); then
  echo "failures:" >&2
  for f in "${failures[@]}"; do
    echo "  - $f" >&2
  done
  exit 1
fi

echo ""
echo "==> per-seed obfuscated build stats ($SEED_COUNT seeds)"
printf "  avg build time:   %.0f ms (plain baseline: %.0f ms, %+0.f%% vs plain)\n" \
  "$avg_build" "$plain_build_ms" "$(awk -v a="$avg_build" -v p="$plain_build_ms" 'BEGIN {print (a-p)/p*100}')"
printf "  build range:      %.0f ms .. %.0f ms\n" "$min_build" "$max_build"
printf "  avg binary size:  %s\n" "$(human_bytes "$avg_size")"
printf "  size range:       %s .. %s\n" "$(human_bytes "$min_size")" "$(human_bytes "$max_size")"
printf "  plain binary:     %s\n" "$(human_bytes "$plain_size")"
printf "  avg size overhead vs plain: %s\n" "$(pct_overhead "$plain_size" "$avg_size")"

echo ""
echo "==> ok: stable across $SEED_COUNT seeds; overhead measured"
