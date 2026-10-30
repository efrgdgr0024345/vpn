"""Exercise real nft JSON in a fresh network namespace, never the host ruleset."""
from contextlib import nullcontext
import fcntl
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vpn-dashboard'))
sys.path.insert(0, str(ROOT / 'ops'))
import firewall_policy
import portal_helper
import network_setup
import vpn_session_helper
import security
import safe_io
import upgrade_client_transport as upgrade
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


def private_dhcp_refresh(policy, uid):
    """Real protected writes and kernel checks; only the lease/account are fixtures."""
    sys.path.insert(0, str(ROOT/'vpn-dashboard/tests'))
    from test_security import PROFILE
    policy = {**policy, 'dhcp_server_ipv4': '10.131.33.103'}
    requested = '192.0.2.1'
    # The DHCP identifier deliberately differs from the gateway. A guessed
    # gateway value must not satisfy the explicit NetworkManager lease check.
    command(['/usr/sbin/ip', 'link', 'add', 'wlan0', 'type', 'veth', 'peer', 'name', 'wifi-peer'])
    command(['/usr/sbin/ip', 'link', 'set', 'wifi-peer', 'up'])
    command(['/usr/sbin/ip', 'address', 'add', '192.0.2.48/24', 'dev', 'wlan0'])
    command(['/usr/sbin/ip', 'link', 'set', 'wlan0', 'up'])
    command(['/usr/sbin/ip', 'route', 'add', 'default', 'via', '192.0.2.254', 'dev', 'wlan0'])
    lease = requested
    def observed(argv, **kwargs):
        if argv == ['/usr/bin/nmcli', '-g', 'DHCP4.OPTION', 'device', 'show', 'wlan0']:
            return subprocess.CompletedProcess(argv, 0,
                'dhcp_server_identifier = '+lease+' | routers = 192.0.2.254\n', '')
        return safe_io.bounded_run(argv, **kwargs)
    modules = SimpleNamespace(
        security=SimpleNamespace(validate_policy=security.validate_policy,
            validate_profile=security.validate_profile, service_account=lambda:SimpleNamespace(pw_uid=uid)),
        firewall_policy=firewall_policy, portal_helper=portal_helper,
        safe_io=SimpleNamespace(bounded_run=observed))
    names = ('policy.json', 'client.ovpn', 'vpn-guard.candidate.json')
    resolver = Path('/etc/resolv.conf').read_bytes()
    routes = command(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'])
    firewall = command(['/usr/sbin/nft', '-j', 'list', 'ruleset'])
    with tempfile.TemporaryDirectory(prefix='vpn-dhcp-refresh-', dir='/run') as temporary:
        directory = Path(temporary)
        original = {'policy.json': (json.dumps(policy, indent=2)+'\n').encode(),
                    'client.ovpn': PROFILE.replace('vpn.example.invalid', policy['server_name']).encode(),
                    'vpn-guard.candidate.json': (json.dumps(firewall_policy.render_batch(policy, uid), indent=2)+'\n').encode()}
        def reset():
            for name, value in original.items():
                (directory/name).write_bytes(value)
                (directory/name).chmod(0o600)
        def snapshot():
            return {name:(directory/name).read_bytes() for name in names}
        def metadata():
            for name in names:
                info = (directory/name).lstat()
                if info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                    raise RuntimeError('DHCP refresh broadened private configuration access.')
        def unchanged_network():
            if (Path('/etc/resolv.conf').read_bytes() != resolver
                    or command(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all']) != routes
                    or command(['/usr/sbin/nft', '-j', 'list', 'ruleset']) != firewall):
                raise RuntimeError('The DHCP refresh changed live networking.')
        reset()
        with (directory/'action.lock').open('w') as lock, \
                patch.object(upgrade, 'CONFIG', directory), \
                patch.object(upgrade, 'installed_helpers', side_effect=lambda files:nullcontext(modules)):
            os.fchmod(lock.fileno(), 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # A gateway guess is rejected without touching the protected pair.
            try:
                upgrade.prepare_dhcp_refresh('192.0.2.254', {})
            except upgrade.UpgradeError:
                pass
            else:
                raise RuntimeError('A gateway guess replaced the explicit DHCP identifier.')
            if snapshot() != original:
                raise RuntimeError('A mismatched DHCP lease changed private settings.')
            state = directory/'network-state.json'
            state.write_text('{}\n')
            state.chmod(0o600)
            try:
                try:
                    upgrade.prepare_dhcp_refresh(requested, {})
                except upgrade.UpgradeError:
                    pass
                else:
                    raise RuntimeError('Saved active-network state did not block DHCP refresh.')
            finally:
                state.unlink()
            if snapshot() != original:
                raise RuntimeError('Saved network-state refusal changed private settings.')
            command(['/usr/sbin/nft', '-j', '-f', '-'], json.dumps(firewall_policy.render_batch(policy, uid)))
            active = command(['/usr/sbin/nft', '-j', 'list', 'ruleset'])
            try:
                try:
                    upgrade.prepare_dhcp_refresh(requested, {})
                except upgrade.UpgradeError:
                    pass
                else:
                    raise RuntimeError('A live firewall guard did not block DHCP refresh.')
                if snapshot() != original or command(['/usr/sbin/nft', '-j', 'list', 'ruleset']) != active:
                    raise RuntimeError('A guard refusal changed protected files or firewall rules.')
            finally:
                command(['/usr/sbin/nft', 'delete', 'table', 'inet', 'vpn_guard'])
            # Interrupt only the policy publication after the inert candidate
            # was durably replaced. A fresh plan must recognize and resume it.
            plan = upgrade.prepare_dhcp_refresh(requested, {})
            publish = upgrade.publish_private
            def interrupt(path, value):
                if path.name == 'policy.json':
                    raise OSError('fixture interrupted policy publication')
                publish(path, value)
            with patch.object(upgrade, 'publish_private', side_effect=interrupt):
                try:
                    upgrade.commit_dhcp_refresh(plan)
                except OSError:
                    pass
                else:
                    raise RuntimeError('The interruption fixture did not stop policy publication.')
            if (directory/'policy.json').read_bytes() != original['policy.json'] or (directory/'vpn-guard.candidate.json').read_bytes() != plan['candidate']:
                raise RuntimeError('DHCP refresh did not publish the candidate before committing policy.')
            metadata()
            unchanged_network()
            upgrade.commit_dhcp_refresh(upgrade.prepare_dhcp_refresh(requested, {}))
            target = {**policy, 'dhcp_server_ipv4': requested}
            if (json.loads((directory/'policy.json').read_text()) != target
                    or json.loads((directory/'vpn-guard.candidate.json').read_text()) != firewall_policy.render_batch(target, uid)
                    or (directory/'client.ovpn').read_bytes() != original['client.ovpn']):
                raise RuntimeError('The resumed DHCP-only refresh changed unrelated private settings.')
            metadata()
            unchanged_network()
            before = snapshot()
            upgrade.commit_dhcp_refresh(upgrade.prepare_dhcp_refresh(requested, {}))
            if snapshot() != before:
                raise RuntimeError('A same-lease DHCP refresh was not idempotent.')
    command(['/usr/sbin/ip', 'link', 'delete', 'wlan0'])
    print('Real private 0600 DHCP refresh, explicit lease checks, guard/state refusal and interrupted-pair recovery passed without networking changes.')


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
    private_dhcp_refresh(policy, uid)
    private_dns_roundtrip(policy, uid)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
