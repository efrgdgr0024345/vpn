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
from security import Refused


def command(argv, data=None):
    return subprocess.run(argv, input=data, text=True, capture_output=True,
                          check=True, timeout=10).stdout


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
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
