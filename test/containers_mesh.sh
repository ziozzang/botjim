#!/bin/bash
# 6개 컨테이너 토렌트 메시: tracker, seed, joiner x4.
# 각 노드가 별도 컨테이너 + 격리 네트워크. seed를 죽여도 joiner들이
# 서로에게서 조각을 받아 완성해야 함(진짜 mesh 검증).
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="botjim-mesh-net"
WORK="$(mktemp -d /tmp/botjim-mesh.XXXXXX)"
NAMES="mesh-track mesh-seed mesh-j1 mesh-j2 mesh-j3 mesh-j4"
fail=0
cleanup(){ for n in $NAMES; do docker rm -f "$n" >/dev/null 2>&1; done; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags osusergo,netgo -trimpath -ldflags="-s -w" -o "$WORK/botjim" ./cmd/botjim ) || exit 1
mkdir -p "$WORK/data"; head -c 50000000 /dev/urandom > "$WORK/data/model.bin"
SHA=$(sha256sum "$WORK/data/model.bin" | awk '{print $1}')

docker network create "$NET" >/dev/null 2>&1 || true
for n in $NAMES; do
  docker run -d --name "$n" --network "$NET" -v "$WORK:/work" alpine:latest sleep 900 >/dev/null || exit 1
done
sleep 1

echo "== tracker =="
docker exec -d mesh-track sh -c "/work/botjim swarm track -p 4763 > /work/track.log 2>&1"
sleep 1
echo "== seed =="
docker exec mesh-seed sh -c "mkdir -p /d && cp /work/data/model.bin /d/"
docker exec -d mesh-seed sh -c "/work/botjim swarm seed --tracker mesh-track:4763 -p 4764 /d/model.bin > /work/seed.log 2>&1"
sleep 3
CODE=$(docker exec mesh-seed sh -c "awk '/^code:/{print \$2}' /work/seed.log")
echo "code=$CODE"
# seed가 만든 spec을 공유 볼륨으로
docker exec mesh-seed sh -c "cp /d/model.bin.swarm.json /work/model.bin.swarm.json"

echo "== joiner1: 다운로드 + 시딩 유지 =="
docker exec -d mesh-j1 sh -c "mkdir -p /out && cp /work/model.bin.swarm.json /out/ && /work/botjim swarm join --tracker mesh-track:4763 --code $CODE --spec /out/model.bin.swarm.json --dest /out --serve :4765 --seed > /work/j1.log 2>&1"
# j1 완성 대기
for i in $(seq 1 40); do
  g=$(docker exec mesh-j1 sh -c "sha256sum /out/model.bin 2>/dev/null | awk '{print \$1}'")
  [ "$g" = "$SHA" ] && break; sleep 0.5
done
g=$(docker exec mesh-j1 sh -c "sha256sum /out/model.bin 2>/dev/null | awk '{print \$1}'")
[ "$g" = "$SHA" ] && echo "j1 downloaded+seeding" || { echo "j1 FAIL"; fail=1; }

echo "== SEED KILL — 이제 j1만 소스 =="
docker rm -f mesh-seed >/dev/null 2>&1
sleep 1

echo "== joiner2,3,4 동시 시작 (seed 없이 j1에서) =="
for n in 2 3 4; do
  port=$((4765+n))
  docker exec -d mesh-j$n sh -c "mkdir -p /out && cp /work/model.bin.swarm.json /out/ && /work/botjim swarm join --tracker mesh-track:4763 --code $CODE --spec /out/model.bin.swarm.json --dest /out --serve :$port --seed > /work/j$n.log 2>&1"
done
# 모두 완성 대기
for i in $(seq 1 80); do
  c=0
  for n in 2 3 4; do
    g=$(docker exec mesh-j$n sh -c "sha256sum /out/model.bin 2>/dev/null | awk '{print \$1}'")
    [ "$g" = "$SHA" ] && c=$((c+1))
  done
  [ $c = 3 ] && break; sleep 0.5
done
for n in 2 3 4; do
  g=$(docker exec mesh-j$n sh -c "sha256sum /out/model.bin 2>/dev/null | awk '{print \$1}'")
  [ "$g" = "$SHA" ] && echo "j$n OK (from mesh, no seed)" || { echo "j$n FAIL"; fail=1; docker exec mesh-j$n sh -c "tail -3 /work/j$n.log"; }
done

[ $fail -eq 0 ] && echo "CONTAINER MESH E2E: ALL PASSED" || echo "CONTAINER MESH E2E: FAILURES"
exit $fail
