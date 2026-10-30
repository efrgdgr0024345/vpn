#!/bin/sh
# Real OpenSSH tests in an unexposed, disposable container; no host mounts/caps.
set -eu
cd "$(dirname "$0")/.."
container=$(docker create debian:13-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad sleep infinity)
cleanup() {
  result=$?
  if [ "$result" -ne 0 ] && [ "${VPN_LAB_KEEP_FAILED_TEST:-0}" = 1 ]; then
    printf 'Disposable SSH debug container retained: %s\n' "$container"
    return
  fi
  docker rm -f "$container" >/dev/null
}
trap cleanup EXIT HUP INT TERM
docker start "$container" >/dev/null
docker exec "$container" mkdir -p /test/ci /test/ops /test/vpn-dashboard
docker cp ci/lab_admin.py "$container:/test/ci/lab_admin.py"
docker cp ci/ssh_container_smoke.py "$container:/test/ci/ssh_container_smoke.py"
docker cp ops/bootstrap_runner_key.py "$container:/test/ops/bootstrap_runner_key.py"
docker cp ops/server_diagnostics.py "$container:/test/ops/server_diagnostics.py"
docker cp ops/prepare_test_access.py "$container:/test/ops/prepare_test_access.py"
docker cp ops/inspect_test_peer.py "$container:/test/ops/inspect_test_peer.py"
docker cp ops/external_vpn_test.py "$container:/test/ops/external_vpn_test.py"
docker cp ops/peer_vpn_client.py "$container:/test/ops/peer_vpn_client.py"
docker cp ops/server_foundation.py "$container:/test/ops/server_foundation.py"
docker cp ops/configure_download.py "$container:/test/ops/configure_download.py"
docker cp vpn-dashboard/safe_io.py "$container:/test/vpn-dashboard/safe_io.py"
docker exec "$container" chown -R 0:0 /test
docker exec -e DEBIAN_FRONTEND=noninteractive "$container" sh -c \
  'apt-get update -qq >/tmp/test-packages.log 2>&1 && apt-get install -y -qq --no-install-recommends python3 openssh-server openssh-client iproute2 passwd >>/tmp/test-packages.log 2>&1 || { tail -40 /tmp/test-packages.log; exit 1; }'
docker exec -e VPN_LAB_DISPOSABLE_SSH_TEST=1 "$container" \
  /usr/bin/python3 -I -B /test/ci/ssh_container_smoke.py
