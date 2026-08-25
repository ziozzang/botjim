#!/usr/bin/env bash
# kill -9 resume suite: pushes a tree while killing the client at N random
# points, then resumes to completion and verifies every file's hash.
# usage: test/kill9.sh [iterations] [port]
set -u
ITER="${1:-10}"
PORT="${2:-14771}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/botjim"
WORK="$(mktemp -d /tmp/botjim-kill9.XXXXXX)"
SRC="$WORK/src"
DST="$WORK/dst"
mkdir -p "$SRC" "$DST"

cleanup() { pkill -f "botjim -s .* -p $PORT" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# source tree: one 96MiB file (12 chunks), 60 small files, a sparse file
head -c $((96*1024*1024)) /dev/urandom > "$SRC/big.bin"
for i in $(seq -w 0 59); do head -c $((RANDOM % 200000 + 1000)) /dev/urandom > "$SRC/s$i.bin"; done
head -c $((20*1024*1024)) /dev/zero > "$SRC/sparse.bin"
dd if=/dev/urandom of="$SRC/sparse.bin" bs=1M seek=10 count=1 conv=notrunc status=none
( cd "$SRC" && find . -type f -print0 | sort -z | xargs -0 sha256sum ) > "$WORK/manifest.sha"

pkill -f "botjim -s .* -p $PORT" 2>/dev/null
sleep 0.3
( cd "$WORK" && setsid "$BIN" -s --root "$DST" -p "$PORT" --no-tui > "$WORK/server.log" 2>&1 & )
sleep 0.6

fail=0
for iter in $(seq 1 "$ITER"); do
  delay=$(python3 -c "import random; print(round(random.uniform(0.05, 0.5), 3))")
  ( cd "$SRC" && "$BIN" -c 127.0.0.1:$PORT --no-tui -q . 2>/dev/null ) &
  client=$!
  sleep "$delay"
  if kill -0 $client 2>/dev/null; then
    kill -9 $client
    killed=yes
  else
    killed=no
  fi
  wait $client 2>/dev/null
  # wait for the server to release part locks (session unwind)
  for _ in $(seq 1 100); do
    locked=$(fuser "$DST"/*".fs-part-"* 2>/dev/null | wc -w)
    [ "$locked" -eq 0 ] && break
    sleep 0.05
  done
  # resume
  ( cd "$SRC" && "$BIN" -c 127.0.0.1:$PORT --no-tui -q . 2>"$WORK/resume.err" )
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "iter $iter (kill=$killed delay=$delay): resume FAILED rc=$rc"
    cat "$WORK/resume.err" | tail -3
    fail=1
    break
  fi
  # verify
  ( cd "$DST" && find . -type f -print0 | sort -z | xargs -0 sha256sum ) > "$WORK/got.sha"
  # manifest paths are identical (same tree layout, '.' root)
  if ! diff -q <(sed "s|$SRC/||" "$WORK/manifest.sha" 2>/dev/null || sed 's|\./||' "$WORK/manifest.sha") \
               <(sed 's|\./||' "$WORK/got.sha") >/dev/null; then
    echo "iter $iter: HASH MISMATCH"
    diff <(sed 's|\./||' "$WORK/manifest.sha") <(sed 's|\./||' "$WORK/got.sha") | head -5
    fail=1
    break
  fi
  leftovers=$(ls "$DST" | grep -c 'fs-part-\|fs-meta-')
  if [ "$leftovers" -ne 0 ]; then
    echo "iter $iter: $leftovers leftover files"
    fail=1
    break
  fi
  echo "iter $iter (kill=$killed delay=${delay}s): ok"
  rm -rf "$DST"; mkdir -p "$DST"
done
if [ $fail -eq 0 ]; then
  echo "kill9 suite: ALL $ITER PASSED"
  exit 0
fi
echo "kill9 suite: FAILED (state kept at $WORK)"
trap - EXIT
exit 1
