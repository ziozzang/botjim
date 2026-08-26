#!/bin/bash
# 컨테이너 간 인증 v2 검증: token 단독 암호화, pass, cloak, 그리고
# 잘못된 자격증명 거부. 두 컨테이너, 격리 네트워크.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="botjim-auth-net"; SRV="botjim-auth-srv"; CLI="botjim-auth-cli"
WORK="$(mktemp -d /tmp/botjim-auth.XXXXXX)"
fail=0
cleanup(){ docker rm -f "$SRV" "$CLI" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags osusergo,netgo -trimpath -ldflags="-s -w" -o "$WORK/botjim" ./cmd/botjim ) || exit 1
mkdir -p "$WORK/src"; head -c 20000000 /dev/urandom > "$WORK/src/data.bin"
SHA=$(sha256sum "$WORK/src/data.bin" | awk '{print $1}')

docker network create "$NET" >/dev/null 2>&1 || true
docker run -d --name "$SRV" --network "$NET" -v "$WORK:/work" alpine:latest sleep 600 >/dev/null || exit 1
docker run -d --name "$CLI" --network "$NET" -v "$WORK:/work" alpine:latest sleep 600 >/dev/null || exit 1
sleep 1
docker exec "$CLI" cp -r /work/src /push 2>/dev/null; docker exec "$CLI" sh -c "mkdir -p /push && cp /work/src/data.bin /push/"

check(){ # $1 label, $2 server-args, $3 client-args, $4 expect(ok|reject)
  docker exec "$SRV" sh -c "rm -rf /data && mkdir -p /data"
  docker exec -d "$SRV" sh -c "/work/botjim -s --root /data -p 4761 --no-tui $2 > /work/s.log 2>&1"
  sleep 1.2
  if docker exec "$CLI" sh -c "cd /push && /work/botjim -c $SRV:4761 --no-tui -q $3 data.bin" >/dev/null 2>&1; then
    got=$(docker exec "$SRV" sh -c "sha256sum /data/data.bin 2>/dev/null | awk '{print \$1}'")
    if [ "$4" = "ok" ] && [ "$got" = "$SHA" ]; then echo "$1: OK"; else echo "$1: FAIL (expected $4, transfer succeeded)"; fail=1; fi
  else
    if [ "$4" = "reject" ]; then echo "$1: correctly rejected"; else echo "$1: FAIL (expected ok, transfer failed)"; fail=1; fi
  fi
  docker exec "$SRV" pkill -f 'botjim -s' 2>/dev/null; sleep 0.3
}

check "token-only(encrypted)"  "--token secret123"                    "--token secret123"                    ok
check "token-mismatch"         "--token secret123"                    "--token wrongtoken"                   reject
check "token-missing"          "--token secret123"                    ""                                     reject
check "pass-encryption"        "--pass passphrase12"                  "--pass passphrase12"                  ok
check "pass-mismatch"          "--pass passphrase12"                  "--pass wrongpass1234"                 reject
check "token+pass"             "--token T --pass passphrase12"        "--token T --pass passphrase12"        ok
check "token+pass partial"     "--token T --pass passphrase12"        "--token T"                            reject
check "cloak+token"            "--cloak /cdn --token T"               "--cloak /cdn --token T"               ok
check "cloak-path-mismatch"    "--cloak /cdn --token T"               "--cloak /wrong --token T"             reject
check "plain"                  ""                                     ""                                     ok

[ $fail -eq 0 ] && echo "CONTAINER AUTH E2E: ALL PASSED" || echo "CONTAINER AUTH E2E: FAILURES"
exit $fail
