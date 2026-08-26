#!/bin/bash
# relay(브로커) 모드 컨테이너 검증: 두 피어가 브로커 컨테이너를 경유해
# e2ee 페어링. 브로커는 암호문만 봄. NAT 뒤 피어 흉내(피어들은 서로의
# 주소를 모르고 브로커로 아웃바운드 연결).
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="botjim-relay-net"
WORK="$(mktemp -d /tmp/botjim-relay.XXXXXX)"
NAMES="relay-broker relay-send relay-recv"
fail=0
cleanup(){ for n in $NAMES; do docker rm -f "$n" >/dev/null 2>&1; done; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags osusergo,netgo -trimpath -ldflags="-s -w" -o "$WORK/botjim" ./cmd/botjim ) || exit 1
mkdir -p "$WORK/src"; head -c 30000000 /dev/urandom > "$WORK/src/file.bin"
SHA=$(sha256sum "$WORK/src/file.bin" | awk '{print $1}')

docker network create "$NET" >/dev/null 2>&1 || true
for n in $NAMES; do docker run -d --name "$n" --network "$NET" -v "$WORK:/work" alpine:latest sleep 600 >/dev/null || exit 1; done
sleep 1

echo "== broker =="
docker exec -d relay-broker sh -c "/work/botjim relay -p 4762 > /work/broker.log 2>&1"
sleep 1
docker exec relay-send sh -c "mkdir -p /push && cp /work/src/file.bin /push/"

echo "== send가 코드 생성, 브로커로 offer =="
docker exec -d relay-send sh -c "cd /push && /work/botjim send --via relay-broker:4762 file.bin > /work/send.log 2>&1"
sleep 2
CODE=$(docker exec relay-send sh -c "grep -oE 'code:[[:space:]]+[A-Z0-9-]+' /work/send.log | awk '{print \$2}'")
echo "code=$CODE"
[ -z "$CODE" ] && { echo "no code generated"; docker exec relay-send cat /work/send.log; fail=1; }

echo "== recv가 코드로 브로커 경유 수신 =="
docker exec relay-recv sh -c "/work/botjim recv --via relay-broker:4762 --code $CODE --dest /pulled --no-tui -q" || { echo "RECV-FAIL"; fail=1; }
got=$(docker exec relay-recv sh -c "sha256sum /pulled/file.bin 2>/dev/null | awk '{print \$1}'")
[ "$got" = "$SHA" ] && echo "relay e2ee transfer OK (broker saw only ciphertext)" || { echo "relay HASH FAIL"; fail=1; docker exec relay-recv sh -c "ls -la /pulled"; }

echo "== 브로커 로그: 암호문 바이트만 (내용 안 봄) =="
docker exec relay-broker sh -c "grep -c 'piped' /work/broker.log" | sed 's/^/  piped events: /'

[ $fail -eq 0 ] && echo "CONTAINER RELAY E2E: ALL PASSED" || echo "CONTAINER RELAY E2E: FAILURES"
exit $fail
