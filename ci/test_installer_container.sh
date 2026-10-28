#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
image=debian:13-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
container=$(docker create "$image" sleep infinity)
cleanup() {
  docker rm -f "$container" >/dev/null
}
trap cleanup EXIT HUP INT TERM
docker start "$container" >/dev/null
docker exec "$container" sh -c 'apt-get update -qq >/tmp/packages.log 2>&1 && apt-get install -y -qq --no-install-recommends python3 python3-tk sudo openvpn iproute2 nftables passwd xterm >>/tmp/packages.log 2>&1 || { tail -30 /tmp/packages.log; exit 1; }'
docker exec "$container" useradd --create-home --user-group --uid 1000 vpn-install-test
docker exec "$container" mkdir /test
docker cp vpn-dashboard "$container:/test/vpn-dashboard"
docker cp ci/installer_smoke.py "$container:/test/installer_smoke.py"
docker exec "$container" chown -R 0:0 /test
if [ "$#" -ge 1 ]; then
  docker cp "$1" "$container:/test/legacy.zip"
  shift
  docker exec -e VPN_LAB_DISPOSABLE_INSTALLER_TEST=1 "$container" /usr/bin/python3 -I -B /test/installer_smoke.py /test/legacy.zip "$@"
else
  docker exec -e VPN_LAB_DISPOSABLE_INSTALLER_TEST=1 "$container" /usr/bin/python3 -I -B /test/installer_smoke.py
fi
