#!/usr/bin/env bash
# Attribute-preservation harness: builds a torture tree, transfers it with
# botjim (push then pull), and compares a tar snapshot (with xattrs) plus a
# stat dump of every entry against the source.
# usage: test/attrs.sh [port]
set -u
PORT="${1:-14772}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/botjim"
WORK="$(mktemp -d /tmp/botjim-attrs.XXXXXX)"
SRC="$WORK/src"
DST="$WORK/dst"
PULL="$WORK/pull"
mkdir -p "$SRC" "$DST" "$PULL"

cleanup() { pkill -f "botjim -s .* -p $PORT" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# ---- torture tree ----
cd "$SRC"
mkdir -p dir_plain dir_750 nested/a/b/c
echo "plain" > file_plain.txt
printf 'setuid\0' > file_setuid
printf 'setgid' > file_setgid
printf 'sticky' > file_sticky
printf 'comb\0\0' > file_4770
head -c $((12*1024*1024)) /dev/urandom > big.bin
head -c $((9*1024*1024)) /dev/zero > holey.bin
dd if=/dev/urandom of=holey.bin bs=1M seek=4 count=1 conv=notrunc status=none
: > empty.txt
ln file_plain.txt hard_link_a
ln file_plain.txt hard_link_b
ln -s file_plain.txt link_rel
ln -s /etc/hostname link_abs
ln -s nested/a/b/c link_dir
chmod 750 dir_750
chmod 700 nested
chmod 640 file_plain.txt
chmod 4755 file_setuid
chmod 2755 file_setgid
chmod 1755 file_sticky
chmod 4770 file_4770
chmod 600 big.bin
chmod 604 holey.bin
touch -d "2020-01-02 03:04:05.123456789" file_plain.txt big.bin
touch -d "2021-11-12 13:14:15.987654321" dir_plain nested
touch -a -d "2019-05-06 07:08:09" file_plain.txt 2>/dev/null || true
python3 - <<'PY'
import os
os.setxattr('file_plain.txt', 'user.botjim', b'xattr-value-1')
os.setxattr('file_plain.txt', 'user.other', b'\x00\x01\x02\xff')
os.setxattr('dir_plain', 'user.d', b'dirattr')
os.setxattr('big.bin', 'user.big', b'v'*200)
PY
if [ "$(id -u)" -eq 0 ]; then
  mkfifo my_fifo
  mknod my_null c 1 3
  chown 65534:65534 file_plain.txt
  chown 1:1 dir_750
fi

# ---- snapshot helpers ----
snap() { # snap <dir> <outfile>
  local dir="$1" out="$2"
  ( cd "$dir" && find . -mindepth 1 -printf '%y %m %p\n' | sort > "$out.types"
    tar cpf - --xattrs --format=pax . 2>/dev/null | sha256sum | awk '{print $1}' > "$out.tarmd5" )
  ( cd "$dir" && find . -mindepth 1 -not -type l -printf '%p %s %T@\n' | sort > "$out.stat" )
  ( cd "$dir" && find . -type l -printf '%p -> %l\n' | sort > "$out.links" )
  # xattr digest per file
  ( cd "$dir" && find . -type f -print0 | sort -z | while IFS= read -r -d '' f; do
      vals=$(python3 -c "import os,sys; print(sorted((n, os.getxattr(sys.argv[1], n)) for n in os.listxattr(sys.argv[1])))" "$f" 2>/dev/null)
      echo "$f $vals"
    done > "$out.xattrs" )
}

snap "$SRC" "$WORK/src"

# ---- transfer ----
pkill -f "botjim -s .* -p $PORT" 2>/dev/null
sleep 0.3
( cd "$WORK" && setsid "$BIN" -s --root "$DST" -p "$PORT" --no-tui > "$WORK/server.log" 2>&1 & )
sleep 0.6
( cd "$SRC" && "$BIN" -c 127.0.0.1:$PORT --no-tui -q . ) || { echo PUSH-FAILED; exit 1; }
"$BIN" -c 127.0.0.1:$PORT --pull --dest "$PULL" --no-tui -q . || { echo PULL-FAILED; exit 1; }

fail=0
for side in "$DST" "$PULL"; do
  name=$(basename "$side")
  snap "$side" "$WORK/$name"
  for part in types links stat xattrs; do
    if ! diff -u "$WORK/src.$part" "$WORK/$name.$part" > "$WORK/diff.$name.$part"; then
      echo "== $name: $part DIFFERS =="
      head -20 "$WORK/diff.$name.$part"
      fail=1
    fi
  done
  # hardlink check: inode identity within the copy
  a=$(stat -c %i "$side/hard_link_a" 2>/dev/null); b=$(stat -c %i "$side/hard_link_b" 2>/dev/null)
  [ "$a" = "$b" ] && [ -n "$a" ] || { echo "$name: hardlink identity broken ($a vs $b)"; fail=1; }
done

if [ $fail -eq 0 ]; then
  echo "attrs harness: PUSH and PULL both preserve everything checked"
else
  echo "attrs harness: FAILURES (state at $WORK)"
  trap - EXIT
  exit 1
fi
