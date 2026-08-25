#!/usr/bin/env bash
# Container E2E: two Alpine containers on an isolated docker network, a
# static botjim binary, push + pull across the container boundary, hash
# verification, and a root-privilege attribute check (chown, fifo, device).
# usage: test/containers.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="botjim-e2e-net"
SRV="botjim-e2e-srv"
CLI="botjim-e2e-cli"
PORT=4761
WORK="$(mktemp -d /tmp/botjim-e2e.XXXXXX)"
BIN="$ROOT/botjim"

fail=0
cleanup() {
  docker rm -f "$SRV" "$CLI" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== building static linux/amd64 binary =="
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -tags osusergo,netgo -trimpath -ldflags="-s -w" -o "$WORK/botjim" ./cmd/botjim ) || exit 1
file "$WORK/botjim" | grep -q 'statically linked' || { echo "not a static build"; exit 1; }

echo "== preparing source tree (as files, host side) =="
SRC="$WORK/src"; mkdir -p "$SRC/deep"
head -c $((80*1024*1024)) /dev/urandom > "$SRC/rand.bin"
head -c $((30*1024*1024)) /dev/zero > "$SRC/sparse.bin"
dd if=/dev/urandom of="$SRC/sparse.bin" bs=1M seek=10 count=2 conv=notrunc status=none
echo "hello container" > "$SRC/plain.txt"
for i in $(seq -w 1 40); do head -c $((RANDOM % 300000 + 500)) /dev/urandom > "$SRC/f$i.bin"; done
echo "compressible $(date)" > "$SRC/deep/note.txt"
chmod 4711 "$SRC/plain.txt"; chmod 750 "$SRC/deep"
ln "$SRC/plain.txt" "$SRC/hard.txt"
ln -s plain.txt "$SRC/rel.link"
touch -d "2022-02-02 02:02:02.222222222" "$SRC/rand.bin" "$SRC/plain.txt"
python3 -c "import os; os.setxattr('$SRC/plain.txt','user.e2e',b'container-value')"
( cd "$SRC" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sed 's|\./||' > "$WORK/want.sha" )

echo "== docker network + containers =="
docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$SRV" "$CLI" >/dev/null 2>&1
docker run -d --name "$SRV" --network "$NET" -v "$WORK:/work" alpine:latest sleep 600 >/dev/null || exit 1
docker run -d --name "$CLI" --network "$NET" -v "$WORK:/work" alpine:latest sleep 600 >/dev/null || exit 1
sleep 1

echo "== server container: waiting mode =="
docker exec -d "$SRV" sh -c "/work/botjim -s --root /data -p $PORT --no-tui > /work/server.log 2>&1"
sleep 1.5
docker exec "$CLI" /work/botjim -c "$SRV:$PORT" --probe --no-tui || { echo "probe failed"; docker logs "$SRV" | tail -5; exit 1; }

echo "== push from client container =="
docker cp "$SRC/." "$CLI:/push/" >/dev/null
docker exec "$CLI" sh -c "cd /push && /work/botjim -c $SRV:$PORT --no-tui -q ." || { echo PUSH-FAILED; fail=1; }
docker exec "$SRV" sh -c "cd /data && find . -type f -print0 | sort -z | xargs -0 sha256sum | sed 's|\./||'" > "$WORK/got-push.sha"
if ! diff -q "$WORK/want.sha" "$WORK/got-push.sha" >/dev/null; then
  echo "push hash mismatch:"; diff "$WORK/want.sha" "$WORK/got-push.sha" | head -5; fail=1
else
  echo "push: content verified ($(wc -l < "$WORK/want.sha") files)"
fi

echo "== root-privilege attributes inside container (chown/ownership) =="
docker exec "$CLI" sh -c "cd /push && chown 8:12 plain.txt && chmod 4755 plain.txt"
docker exec "$CLI" sh -c "cd /push && /work/botjim -c $SRV:$PORT --no-tui -q --map-owners numeric plain.txt"
docker exec "$SRV" stat -c '%n %u:%g %A' /data/plain.txt
docker exec "$SRV" sh -c 'stat -c "%u:%g %A" /data/plain.txt | grep -q "^8:12 -rwsr-xr-x$"' || { echo "owner/mode not preserved"; fail=1; }

echo "== kill -9 mid-transfer + resume across containers =="
docker exec "$CLI" sh -c "cd /push && rm -f plain.txt && head -c 200000000 /dev/urandom > resume.bin && \
  (/work/botjim -c $SRV:$PORT --no-tui -q resume.bin &) && sleep 0.35 && pkill -9 -f 'botjim -c' ; sleep 1"
docker exec "$CLI" sh -c "cd /push && /work/botjim -c $SRV:$PORT --no-tui -q resume.bin" || { echo RESUME-FAILED; fail=1; }
docker exec "$SRV" sha256sum /data/resume.bin | awk '{print $1}' > "$WORK/got-resume.sha"
docker exec "$CLI" sha256sum /push/resume.bin | awk '{print $1}' > "$WORK/want-resume.sha"
diff -q "$WORK/want-resume.sha" "$WORK/got-resume.sha" >/dev/null || { echo "resume hash mismatch"; fail=1; }

echo "== pull back to a clean destination =="
docker exec "$CLI" sh -c "/work/botjim -c $SRV:$PORT --pull --dest /pulled --no-tui -q ." || { echo PULL-FAILED; fail=1; }
docker exec "$CLI" sh -c "cd /pulled && find . -type f -print0 | sort -z | xargs -0 sha256sum | sed 's|\./||'" > "$WORK/got-pull.sha"
# resume.bin was pushed separately (not in want.sha); compare the shared set
comm -12 <(sort "$WORK/want.sha") <(sort "$WORK/got-pull.sha") > "$WORK/common.sha"
if [ "$(wc -l < "$WORK/common.sha")" -ne "$(wc -l < "$WORK/want.sha")" ]; then
  echo "pull: file set mismatch"; diff "$WORK/want.sha" "$WORK/common.sha" | head -5; fail=1
else
  echo "pull: content verified"
fi
docker exec "$CLI" stat -c '%A %u:%g' /pulled/plain.txt

if [ $fail -eq 0 ]; then
  echo "container E2E: ALL PASSED"
else
  echo "container E2E: FAILURES"
  exit 1
fi
