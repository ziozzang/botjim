#!/bin/bash
# 네트워크 지연+손실 주입 하에서 암호화 전송 + resume. 컨테이너에
# iproute2 설치, eth0에 netem(지연 40ms, 손실 1%). NET_ADMIN 필요.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="botjim-netem-net"; SRV="botjim-netem-srv"; CLI="botjim-netem-cli"
WORK="$(mktemp -d /tmp/botjim-netem.XXXXXX)"
fail=0
cleanup(){ docker rm -f "$SRV" "$CLI" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags osusergo,netgo -trimpath -ldflags="-s -w" -o "$WORK/botjim" ./cmd/botjim ) || exit 1
mkdir -p "$WORK/src"; head -c 60000000 /dev/urandom > "$WORK/src/big.bin"
SHA=$(sha256sum "$WORK/src/big.bin" | awk '{print $1}')

docker network create "$NET" >/dev/null 2>&1 || true
docker run -d --name "$SRV" --cap-add NET_ADMIN --network "$NET" -v "$WORK:/work" alpine:latest sleep 600 >/dev/null || exit 1
docker run -d --name "$CLI" --cap-add NET_ADMIN --network "$NET" -v "$WORK:/work" alpine:latest sleep 600 >/dev/null || exit 1
sleep 1
# netem: 양쪽 eth0에 40ms 지연 + 1% 손실
for c in "$SRV" "$CLI"; do
  docker exec "$c" sh -c "apk add -q iproute2 2>/dev/null; tc qdisc add dev eth0 root netem delay 40ms 1% loss 1% 2>/dev/null"
done
docker exec "$CLI" sh -c "mkdir -p /push && cp /work/src/big.bin /push/"

echo "== 암호화(--pass) 전송, 지연+손실 하 =="
docker exec "$SRV" sh -c "rm -rf /data && mkdir -p /data"
docker exec -d "$SRV" sh -c "/work/botjim -s --root /data -p 4761 --no-tui --pass benchpass12 > /work/s.log 2>&1"
sleep 1.5
t0=$(date +%s)
docker exec "$CLI" sh -c "cd /push && /work/botjim -c $SRV:4761 --no-tui -q --pass benchpass12 --parallel 8 big.bin" || { echo "PASS-XFER-FAIL"; fail=1; }
t1=$(date +%s)
got=$(docker exec "$SRV" sh -c "sha256sum /data/big.bin 2>/dev/null | awk '{print \$1}'")
[ "$got" = "$SHA" ] && echo "encrypted xfer over lossy link OK (${SHA:0:12}, $((t1-t0))s)" || { echo "encrypted xfer HASH FAIL"; fail=1; }
docker exec "$SRV" pkill -f 'botjim -s' 2>/dev/null; sleep 0.3

echo "== kill9 resume, 지연+손실 하 =="
docker exec "$SRV" sh -c "rm -rf /data && mkdir -p /data"
docker exec -d "$SRV" sh -c "/work/botjim -s --root /data -p 4762 --no-tui > /work/s2.log 2>&1"
sleep 1.5
docker exec "$CLI" sh -c "cd /push && (/work/botjim -c $SRV:4762 --no-tui -q big.bin &) && sleep 1.5 && pkill -9 -f 'botjim -c'; sleep 1"
docker exec "$CLI" sh -c "cd /push && /work/botjim -c $SRV:4762 --no-tui -q big.bin" || { echo "RESUME-FAIL"; fail=1; }
got=$(docker exec "$SRV" sh -c "sha256sum /data/big.bin 2>/dev/null | awk '{print \$1}'")
[ "$got" = "$SHA" ] && echo "resume over lossy link OK" || { echo "resume HASH FAIL"; fail=1; }

[ $fail -eq 0 ] && echo "CONTAINER NETEM E2E: ALL PASSED" || echo "CONTAINER NETEM E2E: FAILURES"
exit $fail
