#!/bin/bash
# mesh 램프업 실증: seed 업링크를 rate 제한하고, 4 joiner를 동시에.
# A) mesh OFF (joiner가 serve 안 함, seed만 소스)
# B) mesh ON  (joiner끼리 serve)
# 총 완료 시간 비교 — mesh가 seed 병목을 우회하면 훨씬 빨라야.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="botjim-ramp-net"
WORK="$(mktemp -d /tmp/botjim-ramp.XXXXXX)"
NAMES="ramp-track ramp-seed ramp-j1 ramp-j2 ramp-j3 ramp-j4"
RATE="${RATE:-25mbit}"
SIZE="${SIZE:-50000000}"
cleanup(){ for n in $NAMES; do docker rm -f "$n" >/dev/null 2>&1; done; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags osusergo,netgo -trimpath -ldflags="-s -w" -o "$WORK/botjim" ./cmd/botjim ) || exit 1
mkdir -p "$WORK/data"; head -c "$SIZE" /dev/urandom > "$WORK/data/model.bin"
SHA=$(sha256sum "$WORK/data/model.bin" | awk '{print $1}')

docker network create "$NET" >/dev/null 2>&1 || true
docker run -d --name ramp-track --network "$NET" -v "$WORK:/work" alpine:latest sleep 900 >/dev/null || exit 1
docker run -d --name ramp-seed --cap-add NET_ADMIN --network "$NET" -v "$WORK:/work" alpine:latest sleep 900 >/dev/null || exit 1
for n in 1 2 3 4; do docker run -d --name ramp-j$n --network "$NET" -v "$WORK:/work" alpine:latest sleep 900 >/dev/null || exit 1; done
sleep 1
# seed 업링크 제한
docker exec ramp-seed sh -c "apk add -q iproute2 2>/dev/null; tc qdisc add dev eth0 root tbf rate $RATE burst 32kbit latency 400ms 2>/dev/null"

run_scenario(){ # $1 label, $2 extra-join-args
  docker exec -d ramp-track sh -c "/work/botjim swarm track -p 4763 > /work/track.log 2>&1"
  sleep 1
  docker exec ramp-seed sh -c "rm -rf /d && mkdir -p /d && cp /work/data/model.bin /d/"
  docker exec -d ramp-seed sh -c "/work/botjim swarm seed --tracker ramp-track:4763 -p 4764 /d/model.bin > /work/seed.log 2>&1"
  sleep 3
  local CODE=$(docker exec ramp-seed sh -c "awk '/^code:/{print \$2}' /work/seed.log")
  docker exec ramp-seed sh -c "cp /d/model.bin.swarm.json /work/model.bin.swarm.json"
  local t0=$(date +%s%N)
  for n in 1 2 3 4; do
    docker exec -d ramp-j$n sh -c "rm -rf /out && mkdir -p /out && cp /work/model.bin.swarm.json /out/ && /work/botjim swarm join --tracker ramp-track:4763 --code $CODE --spec /out/model.bin.swarm.json --dest /out $2 > /work/j$n.log 2>&1"
  done
  for i in $(seq 1 200); do
    local c=0
    for n in 1 2 3 4; do
      g=$(docker exec ramp-j$n sh -c "sha256sum /out/model.bin 2>/dev/null | awk '{print \$1}'")
      [ "$g" = "$SHA" ] && c=$((c+1))
    done
    [ $c = 4 ] && break; sleep 0.25
  done
  local t1=$(date +%s%N)
  local ok=0; for n in 1 2 3 4; do g=$(docker exec ramp-j$n sh -c "sha256sum /out/model.bin 2>/dev/null | awk '{print \$1}'"); [ "$g" = "$SHA" ] && ok=$((ok+1)); done
  python3 -c "print(f'$1: {($t1-$t0)/1e9:.1f}s  ($ok/4 completed)')"
  docker exec ramp-seed pkill -f 'botjim swarm seed' 2>/dev/null
  docker exec ramp-track pkill -f 'botjim swarm track' 2>/dev/null
  for n in 1 2 3 4; do docker exec ramp-j$n pkill -f 'botjim swarm join' 2>/dev/null; done
  sleep 1
}

echo "seed uplink limited to $RATE, file $((SIZE/1000000))MB, 4 joiners concurrent"
echo "== A) mesh OFF (joiners do not serve each other) =="
run_scenario "mesh-OFF" "--serve ''"
echo "== B) mesh ON (joiners serve + seed) =="
run_scenario "mesh-ON " "--serve :0 --seed"
