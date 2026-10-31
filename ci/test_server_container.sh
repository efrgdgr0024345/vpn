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
peer=$(docker create --network "$network" --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined --device-cgroup-rule 'c 10:200 rwm' "$image" sleep infinity)
server=$(docker create --network "$network" --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  --device-cgroup-rule 'c 10:200 rwm' --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  --sysctl net.ipv6.conf.default.disable_ipv6=1 "$image" sleep infinity)
docker start "$peer" "$server" >/dev/null
docker exec "$peer" sh -c 'apt-get update -qq >/tmp/packages.log 2>&1 && apt-get install -y -qq --no-install-recommends python3 iproute2 openssh-server openssl ca-certificates >>/tmp/packages.log 2>&1 || { tail -30 /tmp/packages.log; exit 1; }'
docker exec "$peer" ip addr add 198.41.0.4/32 dev lo
docker exec "$peer" ip addr add 93.184.216.34/32 dev lo
docker cp ci/dns_fixture.py "$peer:/dns_fixture.py"
docker cp ci/peer_fixture.py "$peer:/peer_fixture.py"
docker exec "$peer" mkdir -p /test/ops
docker cp ops/bootstrap_runner_key.py "$peer:/test/ops/bootstrap_runner_key.py"
docker cp ops/prepare_test_access.py "$peer:/test/ops/prepare_test_access.py"
docker exec "$peer" python3 -I -B /peer_fixture.py prepare
docker exec -d "$peer" python3 /dns_fixture.py
docker exec -d "$peer" python3 -I -B /peer_fixture.py https
peer_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer")
docker exec "$server" sh -c 'apt-get update -qq >/tmp/packages.log 2>&1 && apt-get install -y -qq --no-install-recommends python3 openssh-client curl ca-certificates >>/tmp/packages.log 2>&1 || { tail -30 /tmp/packages.log; exit 1; }'
# Public synthetic trust anchor only; no peer TLS private key is copied.
docker exec "$peer" cat /usr/local/share/ca-certificates/vpn-peer-fixture.crt | \
  docker exec -i "$server" sh -c 'cat > /usr/local/share/ca-certificates/vpn-peer-fixture.crt && chmod 644 /usr/local/share/ca-certificates/vpn-peer-fixture.crt && update-ca-certificates >/dev/null 2>&1'
docker exec "$server" mkdir -p /test/ops /test/ci /test/vpn-dashboard /test/vpn-admin
docker cp ops/server_foundation.py "$server:/test/ops/server_foundation.py"
docker cp ops/server_selftest.py "$server:/test/ops/server_selftest.py"
docker cp ops/enable_ipv4_only.py "$server:/test/ops/enable_ipv4_only.py"
docker cp ops/install_admin_panel.py "$server:/test/ops/install_admin_panel.py"
docker cp ops/server_diagnostics.py "$server:/test/ops/server_diagnostics.py"
docker cp ops/prepare_test_access.py "$server:/test/ops/prepare_test_access.py"
docker cp ops/inspect_test_peer.py "$server:/test/ops/inspect_test_peer.py"
docker cp ops/peer_vpn_client.py "$server:/test/ops/peer_vpn_client.py"
docker cp ops/external_vpn_test.py "$server:/test/ops/external_vpn_test.py"
docker cp ops/session_broker.py "$server:/test/ops/session_broker.py"
docker cp ops/device_admin.py "$server:/test/ops/device_admin.py"
docker cp ops/client_diagnostics.py "$server:/test/ops/client_diagnostics.py"
docker cp ci/server_container_smoke.py "$server:/test/ci/server_container_smoke.py"
docker cp ci/admin_panel_smoke.py "$server:/test/ci/admin_panel_smoke.py"
docker cp vpn-admin/. "$server:/test/vpn-admin/"
docker cp ci/ipv4_migration_smoke.py "$server:/test/ci/ipv4_migration_smoke.py"
docker cp ci/client_control_smoke.py "$server:/test/ci/client_control_smoke.py"
docker cp ci/diagnostics_client_smoke.py "$server:/test/ci/diagnostics_client_smoke.py"
docker cp vpn-dashboard/. "$server:/test/vpn-dashboard/"
docker exec "$server" chown -R 0:0 /test
docker exec "$server" chmod -R go+rX /test/vpn-dashboard
test_identity=$(docker exec "$server" /usr/bin/python3 -I -B /test/ops/prepare_test_access.py)
peer_pin=$(printf '%s' "$test_identity" | docker exec -i "$peer" python3 -I -B /peer_fixture.py authorize)
docker exec -e VPN_LAB_DISPOSABLE_SERVER_TEST=1 "$server" \
  /usr/bin/python3 -I -B /test/ci/client_control_smoke.py
docker exec -e VPN_LAB_DISPOSABLE_SERVER_TEST=1 -e VPN_TEST_PEER_HOST="$peer_ip" \
  -e VPN_TEST_PEER_HOST_FINGERPRINT="$peer_pin" "$server" \
  /usr/bin/python3 -I -B /test/ci/server_container_smoke.py "$peer_ip"
