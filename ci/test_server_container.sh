#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
image=debian:13-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
network=$(docker network create vpn-lab-server-test-$$)
server=
peer=
cleanup() {
  result=$?
  if [ "$result" -ne 0 ] && [ "${VPN_LAB_KEEP_FAILED_TEST:-0}" = 1 ]; then
    printf 'Disposable debug containers retained: server=%s peer=%s network=%s\n' "$server" "$peer" "$network"
    return
  fi
  if [ -n "$server" ]; then docker rm -f "$server" >/dev/null; fi
  if [ -n "$peer" ]; then docker rm -f "$peer" >/dev/null; fi
  docker network rm "$network" >/dev/null
}
trap cleanup EXIT HUP INT TERM
peer=$(docker create --network "$network" --cap-add NET_ADMIN "$image" sleep infinity)
server=$(docker create --network "$network" --cap-add NET_ADMIN \
  --device-cgroup-rule 'c 10:200 rwm' --sysctl net.ipv4.ip_forward=1 "$image" sleep infinity)
docker start "$peer" "$server" >/dev/null
docker exec "$peer" sh -c 'apt-get update -qq >/tmp/packages.log 2>&1 && apt-get install -y -qq --no-install-recommends python3 iproute2 >>/tmp/packages.log 2>&1 || { tail -30 /tmp/packages.log; exit 1; }'
docker exec "$peer" ip addr add 9.9.9.9/32 dev lo
docker cp ci/dns_fixture.py "$peer:/dns_fixture.py"
docker exec -d "$peer" python3 /dns_fixture.py
peer_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer")
docker exec "$server" sh -c 'apt-get update -qq >/tmp/packages.log 2>&1 && apt-get install -y -qq --no-install-recommends python3 >>/tmp/packages.log 2>&1 || { tail -30 /tmp/packages.log; exit 1; }'
docker exec "$server" mkdir -p /test/ops /test/ci
docker cp ops/server_foundation.py "$server:/test/ops/server_foundation.py"
docker cp ops/server_selftest.py "$server:/test/ops/server_selftest.py"
docker cp ci/server_container_smoke.py "$server:/test/ci/server_container_smoke.py"
docker exec "$server" chown -R 0:0 /test
docker exec -e VPN_LAB_DISPOSABLE_SERVER_TEST=1 "$server" \
  /usr/bin/python3 -I -B /test/ci/server_container_smoke.py "$peer_ip"
