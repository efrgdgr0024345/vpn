"""Exercise real nft JSON in a fresh network namespace, never the host ruleset."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vpn-dashboard'))
import firewall_policy
import portal_helper
import network_setup
import vpn_session_helper
from security import Refused


def command(argv, data=None):
    return subprocess.run(argv, input=data, text=True, capture_output=True,
                          check=True, timeout=10).stdout


DNS_PEER = r'''
import select, socket, struct, sys
print('namespace ready', flush=True)
if sys.stdin.readline().strip() != 'start':
    raise SystemExit(1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(('172.27.240.1', 53))
    mode, count = 'ok', 0
    print('resolver ready', flush=True)
    while True:
        readable, _, _ = select.select([sys.stdin, sock], [], [], 1)
        if sys.stdin in readable:
            value = sys.stdin.readline().strip()
            if value == 'count':
                print(count, flush=True)
            elif value in ('ok', 'servfail', 'silence'):
                mode = value
                print('mode ready', flush=True)
            else:
                break
        if sock in readable:
            query, address = sock.recvfrom(4096)
            count += 1
            if mode == 'silence' or len(query) < 12:
                continue
            flags, answers = (0x8180, 1) if mode == 'ok' else (0x8182, 0)
            response = query[:2] + struct.pack('!5H', flags, 1, answers, 0, 0) + query[12:]
            if answers:
                response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4)
                response += socket.inet_aton('203.0.113.7')
            sock.sendto(response, address)
'''


def private_dns_roundtrip(policy, uid):
    """Actual bound UDP through the real guard, confined to two fresh namespaces."""
    peer = subprocess.Popen(['/usr/bin/unshare', '--net', '--', '/usr/bin/python3',
                             '-I', '-B', '-c', DNS_PEER], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    def receive(expected=None):
        import select
        if not select.select([peer.stdout], [], [], 5)[0]:
            raise RuntimeError('The isolated DNS fixture did not respond in time.')
        value = peer.stdout.readline().strip()
        if expected is not None and value != expected:
            raise RuntimeError('The isolated DNS fixture returned an unexpected status.')
        return value
    def control(value, expected=None):
        peer.stdin.write(value+'\n')
        peer.stdin.flush()
        return receive(expected)
    guard = False
    try:
        receive('namespace ready')
        command(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
        command(['/usr/sbin/ip', 'link', 'add', 'tun0', 'type', 'veth', 'peer', 'name', 'dns-peer'])
        command(['/usr/sbin/ip', 'link', 'set', 'dns-peer', 'netns', str(peer.pid)])
        command(['/usr/sbin/ip', 'address', 'add', '172.27.240.10/24', 'dev', 'tun0'])
        command(['/usr/sbin/ip', 'link', 'set', 'tun0', 'up'])
        enter = ['/usr/bin/nsenter', '-t', str(peer.pid), '-n', '--', '/usr/sbin/ip']
        command(enter+['address', 'add', '172.27.240.1/24', 'dev', 'dns-peer'])
        command(enter+['link', 'set', 'dns-peer', 'up'])
        control('start', 'resolver ready')
        command(['/usr/sbin/nft', '-j', '-f', '-'], json.dumps(firewall_policy.render_batch(policy, uid)))
        guard = True
        before = command(['/usr/sbin/nft', '-j', 'list', 'ruleset'])
        for mode, expected in (('ok', 'ok'), ('servfail', 'servfail'), ('silence', 'timeout')):
            control(mode, 'mode ready')
            status, elapsed = vpn_session_helper.private_dns_probe()
            if status != expected or type(elapsed) is not int or not 0 <= elapsed <= 5000:
                raise RuntimeError('The bound private DNS probe misclassified a real resolver response.')
        count = int(control('count'))
        # A misleading route must not send the query or fall back to a resolver.
        command(['/usr/sbin/ip', 'route', 'add', '172.27.240.1/32', 'dev', 'lo'])
        status, _ = vpn_session_helper.private_dns_probe()
        if status != 'route_unavailable' or int(control('count')) != count:
            raise RuntimeError('The DNS probe did not refuse a route outside the tunnel.')
        command(['/usr/sbin/ip', 'route', 'delete', '172.27.240.1/32', 'dev', 'lo'])
        command(['/usr/sbin/ip', 'link', 'set', 'tun0', 'down'])
        status, _ = vpn_session_helper.private_dns_probe()
        if status != 'route_unavailable' or int(control('count')) != count:
            raise RuntimeError('The DNS probe did not refuse an unavailable tunnel.')
        if command(['/usr/sbin/nft', '-j', 'list', 'ruleset']) != before:
            raise RuntimeError('The DNS health check changed the firewall guard.')
    finally:
        if guard:
            command(['/usr/sbin/nft', 'delete', 'table', 'inet', 'vpn_guard'])
        if peer.poll() is None:
            peer.terminate()
        peer.wait(timeout=5)
        peer.stdin.close()
        peer.stdout.close()
        peer.stderr.close()
    print('Real tun0-bound DNS answer, SERVFAIL, bounded timeout and route refusal passed under the guard.')


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run this CI check with sudo on a disposable Linux runner.')
    current = os.stat('/proc/self/ns/net').st_ino
    if len(sys.argv) == 1:
        # The child loses access to the host's network and all its firewall rules.
        result = subprocess.run([
            '/usr/bin/unshare', '--net', '--', '/usr/bin/python3', '-I', '-B',
            str(Path(__file__).resolve()), str(current)], check=False, timeout=45)
        return result.returncode
    if (len(sys.argv) != 2 or not sys.argv[1].isdigit()
            or current == int(sys.argv[1])
            or current == os.stat('/proc/1/ns/net').st_ino):
        raise SystemExit('Refusing to test in the original network namespace.')
    links = json.loads(command(['/usr/sbin/ip', '-j', 'link', 'show']))
    if {link['ifname'] for link in links} != {'lo'}:
        raise SystemExit('Expected a fresh namespace containing only loopback.')
    policy = json.loads((ROOT / 'vpn-dashboard/policy.example.json').read_text())
    uid = 65534  # Only fixture identity metadata; no system account is created.
    batch = firewall_policy.render_batch(policy, uid)
    command(['/usr/sbin/nft', '-j', '-f', '-'], json.dumps(batch))
    document = json.loads(command(['/usr/sbin/nft', '-j', 'list', 'ruleset']))
    # Config/account lookup alone is substituted. Parsing, kernel installation,
    # nft readback and policy comparison are exercised without a mocked nft tool.
    with patch.object(portal_helper, 'load_policy', return_value=policy), patch.object(
            portal_helper, 'service_account', return_value=SimpleNamespace(pw_uid=uid)):
        try:
            state = portal_helper.inspect_guard(document)
        except Refused:
            # The namespace contains only this public test fixture, no host rules.
            print('Unrecognized kernel fixture readback: ' + json.dumps(document), flush=True)
            raise
        if state != (False, False):
            raise SystemExit('Expected a recognized, closed guard.')
        command(['/usr/sbin/nft', 'add', 'rule', 'inet', 'vpn_guard', 'output', 'accept'])
        tampered = json.loads(command(['/usr/sbin/nft', '-j', 'list', 'ruleset']))
        try:
            portal_helper.inspect_guard(tampered)
        except Refused:
            pass
        else:
            raise SystemExit('An unexpected output bypass was accepted.')
    print('Real nftables roundtrip and bypass refusal passed in an isolated namespace.')
    command(['/usr/sbin/nft','delete','table','inet','vpn_guard'])
    policy['server_name']='VPNLabServer'
    with tempfile.TemporaryDirectory(prefix='vpn-desk-network-',dir='/run') as directory:
        directory=Path(directory)
        resolver=directory/'resolv.conf'
        resolver.write_text('nameserver 192.0.2.53\n')
        resolver.chmod(0o644)
        (directory/'policy.json').write_text(json.dumps(policy))
        (directory/'policy.json').chmod(0o600)
        with patch.object(network_setup,'CONFIG_DIR',directory), \
                patch.object(network_setup,'STATE',directory/'network-state.json'), \
                patch.object(network_setup,'RESOLVER',resolver), \
                patch.object(network_setup,'load_policy',return_value=policy), \
                patch.object(network_setup,'service_account',return_value=SimpleNamespace(pw_uid=uid)), \
                patch.object(portal_helper,'load_policy',return_value=policy), \
                patch.object(portal_helper,'service_account',return_value=SimpleNamespace(pw_uid=uid)), \
                patch.object(portal_helper,'active_openvpn',return_value=False):
            network_setup.prepare()
            if resolver.read_text()!=network_setup.MANAGED_DNS:
                raise SystemExit('Private VPN DNS was not installed after the real guard.')
            resolver.write_text('nameserver 192.0.2.53\n')
            if network_setup.verify_during_session() is not False or resolver.read_text()!=network_setup.MANAGED_DNS:
                raise SystemExit('Resolver repair under the guard failed.')
            network_setup.restore()
            if resolver.read_text()!='nameserver 192.0.2.53\n' or (directory/'network-state.json').exists():
                raise SystemExit('Explicit owned-network restore failed.')
            if any('table' in row for row in json.loads(command(['/usr/sbin/nft','-j','list','ruleset']))['nftables']):
                raise SystemExit('The owned firewall was not released on explicit restore.')
    print('Real guard/private-DNS sequencing, repair and explicit restore passed with a private resolver fixture.')
    private_dns_roundtrip(policy, uid)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
