#!/usr/bin/env bash
# Throughput benchmarks on loopback + tmpfs: botjim vs `tar | nc` (with
# extraction on the receiving side, matching botjim's work).
# usage: test/bench.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/botjim"
WORK="/tmp/botjim-bench.$$"
PORT=14780
mkdir -p "$WORK"

cleanup() {
  pkill -f "nc -l .* $PORT" 2>/dev/null
  P=$(ss -tlnp 2>/dev/null | grep ":$PORT" | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -n "$P" ] && kill "$P" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

G=$((1024*1024*1024))

echo "== building workloads (tmpfs) =="
mkdir -p "$WORK/single" "$WORK/small" "$WORK/rand" "$WORK/zero"
head -c $((5*G)) /dev/urandom > "$WORK/single/big5g.bin" &
P1=$!
python3 - "$WORK/small" <<'PY' &
import os, sys, random
d = sys.argv[1]
random.seed(7)
for i in range(20000):
    with open(f"{d}/f{i:05d}.bin", "wb") as f:
        f.write(random.randbytes(64 * 1024))
PY
P2=$!
head -c $G /dev/urandom > "$WORK/rand/r.bin"
head -c $G /dev/zero > "$WORK/zero/z.bin"
wait $P1 $P2

# botjim server on the bench port
pkill -f "botjim -s .* -p $PORT" 2>/dev/null; sleep 0.3
mkdir -p "$WORK/dst"
( cd "$WORK" && setsid "$BIN" -s --root "$WORK/dst" -p $PORT --no-tui > server.log 2>&1 & )
sleep 0.7

run_botjim() { # run_botjim <label> <path...> [flags...]
  local label="$1"; shift
  local paths="$1"; shift
  local t0=$(date +%s.%N)
  ( cd "$(dirname "$paths")" && "$BIN" -c 127.0.0.1:$PORT --no-tui -q "$@" "$(basename "$paths")" >/dev/null 2>&1 )
  local rc=$?
  local t1=$(date +%s.%N)
  if [ $rc -ne 0 ]; then echo "$label: FAILED rc=$rc"; return; fi
  python3 -c "print(f'$label: {$t1-$t0:.2f}s  $((5*G))B-scale rate see below')"
}
rate() { # rate <label> <bytes> <t0> <t1>
  python3 -c "print(f'  $1: {$4-$t0_mark:.2f}s')" 2>/dev/null || true
}

bench() { # bench <label> <dir> <size> <args...>
  local label="$1" dir="$2" size="$3"; shift 3
  rm -rf "$WORK/dst"; mkdir -p "$WORK/dst"
  local t0=$(date +%s.%N)
  ( cd "$dir" && "$BIN" -c 127.0.0.1:$PORT --no-tui -q "$@" . ) >/dev/null 2>&1
  local rc=$?
  local t1=$(date +%s.%N)
  if [ $rc -ne 0 ]; then echo "$label: FAILED"; return; fi
  python3 -c "print(f'$label: {$t1-$t0:.2f}s  {$size/($t1-$t0)/1024/1024:.0f} MiB/s')"
}

tarbench() { # tarbench <label> <dir> <size>
  local label="$1" dir="$2" size="$3"
  rm -rf "$WORK/tardst"; mkdir -p "$WORK/tardst"
  pkill -f "nc -l .* $PORT" 2>/dev/null; sleep 0.2
  ( cd "$WORK/tardst" && setsid nc -l -p $PORT | tar x >/dev/null 2>&1 & )
  sleep 0.3
  local t0=$(date +%s.%N)
  ( cd "$dir" && tar cf - . | nc -q 2 127.0.0.1 $PORT ) >/dev/null 2>&1
  local t1=$(date +%s.%N)
  pkill -f "nc -l .* $PORT" 2>/dev/null
  python3 -c "print(f'$label: {$t1-$t0:.2f}s  {$size/($t1-$t0)/1024/1024:.0f} MiB/s')"
}

echo; echo "== 5 GiB single file =="
tarbench "tar|nc (extract) " "$WORK/single" $((5*G))
bench "botjim none  p=8  " "$WORK/single" $((5*G)) --compress none
bench "botjim zstd3 p=8  " "$WORK/single" $((5*G)) --compress zstd --zstd-level 3
bench "botjim lz4   p=8  " "$WORK/single" $((5*G)) --compress lz4
bench "botjim none  p=1  " "$WORK/single" $((5*G)) --compress none --parallel 1

echo; echo "== 20000 × 64 KiB small files (1.22 GiB) =="
SM=$(python3 -c "print(20000*64*1024)")
tarbench "tar|nc (extract) " "$WORK/small" $SM
bench "botjim none  p=8  " "$WORK/small" $SM --compress none
bench "botjim zstd3 p=8  " "$WORK/small" $SM --compress zstd --zstd-level 3

echo; echo "== 1 GiB incompressible (random) =="
tarbench "tar|nc (extract) " "$WORK/rand" $G
bench "botjim zstd3 p=8  " "$WORK/rand" $G --compress zstd --zstd-level 3

echo; echo "== 1 GiB sparse (zeros) — wire bytes matter =="
rm -rf "$WORK/dst"; mkdir -p "$WORK/dst"
t0=$(date +%s.%N)
( cd "$WORK/zero" && "$BIN" -c 127.0.0.1:$PORT --no-tui -q --compress none . ) >/dev/null 2>&1
t1=$(date +%s.%N)
python3 -c "print(f'botjim sparse: {$t1-$t0:.2f}s')"
echo "  (wire check: sender counts payload; holes are not transmitted)"

echo; echo "done"
