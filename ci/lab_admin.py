"""Fixed read-only lab operations over pinned SSH, for manual main-branch runs."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vpn-dashboard'))
from safe_io import bounded_run

ENVIRONMENT = {'PATH': '/usr/bin:/bin:/usr/sbin', 'LC_ALL': 'C'}

# No environment dumps, account databases, configuration contents, private keys,
# process arguments, VPN profiles or journals are collected from the server.
INVENTORY = r'''
import ipaddress, json, os, platform, shutil, subprocess
if os.geteuid() != 0:
    raise SystemExit('Expected the independently authorized root account.')
def read(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=8,
                           env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        return p.stdout[:65536] if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None
release = {}
with open('/etc/os-release') as f:
    for line in f:
        key, sep, value = line.strip().partition('=')
        if sep and key in ('ID','VERSION_ID','PRETTY_NAME'):
            release[key] = value.strip('"')
services = read(['/usr/bin/systemctl','list-units','--type=service','--state=running',
                 '--no-pager','--no-legend'])
ports = read(['/usr/bin/ss','-H','-lntu'])
listeners = set()
for line in (ports or '').splitlines():
    fields = line.split()
    if len(fields) >= 6:
        port = fields[4].rsplit(':',1)[-1]
        if port.isdigit():
            listeners.add((fields[0], int(port)))
routes = read(['/usr/sbin/ip','-j','-4','route','show','table','all'])
overlap = None
if routes is not None:
    try:
        candidates = [ipaddress.ip_network(r['dst'],strict=False) for r in json.loads(routes)
                      if r.get('dst') and r['dst'] != 'default']
        overlap = any(n.overlaps(ipaddress.ip_network('172.27.240.0/24')) for n in candidates)
    except (ValueError, KeyError, TypeError):
        pass
firewall = read(['/usr/sbin/nft','-j','list','ruleset'])
firewall_summary = None
if firewall is not None:
    try:
        objects = json.loads(firewall)['nftables']
        firewall_summary = {'tables':sum('table' in o for o in objects),
                            'rules':sum('rule' in o for o in objects),
                            'base_chain_policies':[o['chain']['policy'] for o in objects
                                if 'chain' in o and 'policy' in o['chain']]}
    except (ValueError, KeyError, TypeError):
        pass
disk = shutil.disk_usage('/')
report = {'os':release, 'kernel':platform.release(), 'root_free_bytes':disk.free,
          'running_service_units':None if services is None else sorted(
              line.split()[0] for line in services.splitlines() if line.split()),
          'listening_ports':sorted(listeners),
          'candidate_vpn_subnet_overlaps_existing_route':overlap,
          'firewall_summary':firewall_summary,
          'tools':{tool:shutil.which(tool) is not None for tool in
                   ('openvpn','openssl','nft','iptables','ufw','docker','systemctl')}}
print(json.dumps(report, sort_keys=True))
'''


class LabError(RuntimeError):
    pass


def settings(environment):
    host = environment.get('VPN_LAB_HOST', '')
    try:
        address = ipaddress.IPv4Address(host)
    except ValueError:
        raise LabError('Supply a literal IPv4 lab address.') from None
    if address.is_loopback or address.is_unspecified or address.is_multicast or host == '255.255.255.255':
        raise LabError('Invalid lab address.')
    port = environment.get('VPN_LAB_PORT', '22')
    if not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
        raise LabError('Invalid SSH port.')
    fingerprint = environment.get('VPN_LAB_HOST_FINGERPRINT', '')
    if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint):
        raise LabError('Supply the complete provider-console ED25519 SHA256 fingerprint.')
    return host, str(int(port)), fingerprint


def verified_host(host, port, fingerprint, run):
    scan = run(['/usr/bin/ssh-keyscan', '-T', '8', '-p', port, '-t', 'ed25519', host],
               timeout=15, limit=16384, env=ENVIRONMENT)
    if scan.returncode:
        raise LabError('SSH host-key scan failed. No authentication attempted.')
    found = []
    identity = host if port == '22' else '[' + host + ']:' + port
    for line in scan.stdout.splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) != 3 or fields[:2] != [identity, 'ssh-ed25519']:
            raise LabError('Unexpected SSH host-key response. No authentication attempted.')
        try:
            wire = base64.b64decode(fields[2], validate=True)
        except ValueError:
            raise LabError('Malformed SSH host key. No authentication attempted.') from None
        if len(wire) != 51 or wire[:19] != b'\0\0\0\x0bssh-ed25519\0\0\0\x20':
            raise LabError('Malformed ED25519 host key. No authentication attempted.')
        actual = 'SHA256:' + base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip('=')
        if actual != fingerprint:
            raise LabError('HOST KEY MISMATCH. No authentication attempted.')
        found.append(' '.join(fields))
    if not found:
        raise LabError('SSH returned no host key. No authentication attempted.')
    return '\n'.join(sorted(set(found))) + '\n'


def private_file(path, contents):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(contents)


def execute(operation, environment, run=bounded_run):
    if operation not in ('connectivity', 'inventory'):
        raise LabError('Unsupported lab operation.')
    host, port, fingerprint = settings(environment)
    known = verified_host(host, port, fingerprint, run)
    print('SSH host identity verified against the provider-console fingerprint.')
    if operation == 'connectivity':
        return
    secret = environment.get('VPN_LAB_SSH_PRIVATE_KEY', '').strip().replace('\r\n', '\n')
    if (len(secret) > 16384 or not secret.startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n')
            or not secret.endswith('\n-----END OPENSSH PRIVATE KEY-----')):
        raise LabError('The vpn-lab environment needs VPN_LAB_SSH_PRIVATE_KEY (multiline private key).')
    with tempfile.TemporaryDirectory(prefix='vpn-lab-ssh-') as directory:
        key, hosts = Path(directory) / 'identity', Path(directory) / 'known_hosts'
        private_file(key, secret + '\n')
        private_file(hosts, known)
        result = run([
            '/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', port, '-i', str(key),
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(hosts),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=10',
            '-o', 'ConnectionAttempts=1', '-o', 'ForwardAgent=no',
            '-o', 'ClearAllForwardings=yes', '-o', 'LogLevel=ERROR',
            'root@' + host, '/usr/bin/python3 -I -B -'],
            input=INVENTORY, timeout=65, limit=131072, env=ENVIRONMENT)
        if result.returncode:
            raise LabError('SSH inventory failed. Check key authorization/expiry and environment-secret setup; raw stderr withheld.')
        try:
            report = json.loads(result.stdout)
        except ValueError:
            raise LabError('Inventory returned unsupported output; raw output withheld.') from None
        expected = {'os', 'kernel', 'root_free_bytes', 'running_service_units', 'listening_ports',
                    'candidate_vpn_subnet_overlaps_existing_route', 'firewall_summary', 'tools'}
        if not isinstance(report, dict) or set(report) != expected:
            raise LabError('Inventory returned unexpected fields; raw output withheld.')
        print(json.dumps(report, indent=2, sort_keys=True))
    print('Read-only inventory completed. No server settings changed; runner key file removed.')


def main():
    if (os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or os.environ.get('GITHUB_REF') != 'refs/heads/main'
            or os.environ.get('GITHUB_REPOSITORY') != 'efrgdgr0024345/vpn'):
        raise LabError('Lab administration requires a manual run from this repository main branch.')
    if len(sys.argv) != 2:
        raise LabError('Select a fixed lab operation.')
    execute(sys.argv[1], os.environ)


if __name__ == '__main__':
    try:
        main()
    except (LabError, OSError, UnicodeError, subprocess.SubprocessError) as exc:
        print(str(exc) if isinstance(exc, LabError) else 'Lab command failed or exceeded its time/output limit.', file=sys.stderr)
        raise SystemExit(1)
