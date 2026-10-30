"""Fixed read-only lab operations over pinned SSH, for manual main-branch runs."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import socket
import threading
import secrets

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vpn-dashboard'))
sys.path.insert(0, str(ROOT / 'ops'))
from safe_io import bounded_run
from server_diagnostics import validate_report as validate_connection_report
from prepare_test_access import validate_report as validate_test_access_report
from inspect_test_peer import validate_report as validate_test_peer_report
from external_vpn_test import validate_report as validate_external_test_report

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
with open('/proc/uptime') as stream:
    uptime_seconds=int(float(stream.read().split()[0]))
report = {'os':release, 'kernel':platform.release(), 'root_free_bytes':disk.free,
          'uptime_seconds':uptime_seconds,
          'running_service_units':None if services is None else sorted(
              line.split()[0] for line in services.splitlines() if line.split()),
          'listening_ports':sorted(listeners),
          'candidate_vpn_subnet_overlaps_existing_route':overlap,
          'firewall_summary':firewall_summary,
          'tools':{tool:shutil.which(tool) is not None for tool in
                   ('openvpn','openssl','nft','iptables','ufw','docker','systemctl')}}
print(json.dumps(report, sort_keys=True))
'''

UDP_PROBE = r'''
import json, socket, subprocess, time
routes=json.loads(subprocess.check_output(['/usr/sbin/ip','-j','-4','route','show','default'],text=True))
if len(routes)!=1:
    raise SystemExit('Expected one external interface.')
found=False
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)) as channel:
    channel.bind((routes[0]['dev'],0))
    channel.settimeout(.5)
    end=time.monotonic()+10
    while time.monotonic()<end:
        try:
            packet,address=channel.recvfrom(4096)
        except socket.timeout:
            continue
        if address[2]==socket.PACKET_OUTGOING or len(packet)<42 or packet[12:14]!=b'\x08\x00' or packet[23]!=17:
            continue
        offset=14+(packet[14]&15)*4
        if len(packet)>=offset+8 and packet[offset+2:offset+4]==b'\x04\xaa' and packet[offset+8:]==PROBE:
            found=True
            break
if not found:
    print(json.dumps({'error':'selftest_failed','detail':'Public UDP 1194 did not reach the server.'}))
    raise SystemExit(1)
print(json.dumps({'public_udp_1194_received':True}))
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
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if operation not in ('connectivity', 'inventory', 'diagnose-connection', 'prepare-test-access', 'inspect-test-peer', 'test-from-peer', 'install-foundation', 'test-foundation','probe-udp','prepare-download','close-download',
                         'device-status','revoke-device','enable-device','reset-sessions','reboot-lab','rotate-password'):
        raise LabError('Unsupported lab operation.')
    host, port, fingerprint = settings(environment)
    peer = None
    if operation in ('inspect-test-peer', 'test-from-peer'):
        peer = settings({'VPN_LAB_HOST': environment.get('VPN_TEST_PEER_HOST', ''),
                         'VPN_LAB_PORT': environment.get('VPN_TEST_PEER_PORT', '22'),
                         'VPN_LAB_HOST_FINGERPRINT': environment.get('VPN_TEST_PEER_HOST_FINGERPRINT', '')})
    known = verified_host(host, port, fingerprint, run)
    print('SSH host identity verified against the provider-console fingerprint.')
    if operation == 'connectivity':
        return
    program=INVENTORY
    remote_command='/usr/bin/python3 -I -B -'
    timeout=65
    probe=None
    device=environment.get('VPN_LAB_DEVICE','kali')
    if device not in ('kali','iphone','android'):
        raise LabError('Select a fixed registered device name.')
    if operation == 'diagnose-connection':
        program = (ROOT/'ops/server_diagnostics.py').read_text()
    if operation == 'prepare-test-access':
        program = (ROOT/'ops/prepare_test_access.py').read_text()
    if operation == 'inspect-test-peer':
        peer_host, peer_port, peer_fingerprint = peer
        program = ('TEST_PEER_HOST = '+repr(peer_host)+'\nTEST_PEER_HOST_FINGERPRINT = '
                   +repr(peer_fingerprint)+'\nTEST_PEER_PORT = '+repr(peer_port)+'\n'
                   +(ROOT/'ops/inspect_test_peer.py').read_text())
    if operation == 'test-from-peer':
        peer_host, peer_port, peer_fingerprint = peer
        program = ('TEST_PEER_HOST = '+repr(peer_host)+'\nTEST_PEER_HOST_FINGERPRINT = '
                   +repr(peer_fingerprint)+'\nTEST_PEER_PORT = '+repr(peer_port)+'\n'
                   +'TEST_SERVER_HOST = '+repr(host)+'\nPEER_LIBRARY_SOURCE = '
                   +repr((ROOT/'ops/inspect_test_peer.py').read_text())+'\nPEER_CLIENT_SOURCE = '
                   +repr((ROOT/'ops/peer_vpn_client.py').read_text())+'\n'
                   +(ROOT/'ops/external_vpn_test.py').read_text())
        timeout = 900
    if operation in ('device-status','revoke-device','enable-device','reset-sessions','reboot-lab','rotate-password'):
        program=('DEVICE_OPERATION = '+repr(operation)+'\nDEVICE_NAME = '+repr(device)+'\n'
                 +(ROOT/'ops/device_admin.py').read_text())
    if operation=='probe-udp':
        probe=b'VPN-LAB-PROBE-v1:'+secrets.token_hex(16).encode()
        program='PROBE = '+repr(probe)+'\n'+UDP_PROBE
    if operation=='install-foundation':
        selftest=(ROOT/'ops/server_selftest.py').read_text()
        notices=(ROOT/'THIRD_PARTY_NOTICES.md').read_text()
        revision=environment.get('GITHUB_SHA','local-test')
        if revision!='local-test' and not re.fullmatch(r'[0-9a-f]{40}',revision):
            raise LabError('Invalid deployment revision.')
        foundation=(ROOT/'ops/server_foundation.py').read_text()
        broker=(ROOT/'ops/session_broker.py').read_text()
        program=('SELFTEST_SOURCE = '+repr(selftest)+'\nNOTICES_SOURCE = '+repr(notices)
                 +'\nBROKER_SOURCE = '+repr(broker)
                 +'\nDEPLOYED_REVISION = '+repr(revision)+'\n'
                 +'FOUNDATION_SOURCE = '+repr(foundation)+'\n'+foundation)
        # Both values are validated numeric/literal-IP strings, never shell input.
        remote_command+=' --endpoint '+host+' --ssh-port '+port
        timeout=1500
    elif operation=='test-foundation':
        program=(ROOT/'ops/server_selftest.py').read_text()
        timeout=240
    elif operation=='prepare-download':
        value=environment.get('VPN_LAB_DOWNLOAD_PUBLIC_KEY','').strip()
        fields=value.split()
        if '\n' in value or '\r' in value or len(fields)<2 or fields[0]!='ssh-ed25519':
            raise LabError('Supply an ED25519 public key for download enrollment.')
        try:
            wire=base64.b64decode(fields[1],validate=True)
        except ValueError:
            raise LabError('Invalid download public key.') from None
        if len(wire)!=51 or wire[:19]!=b'\0\0\0\x0bssh-ed25519\0\0\0\x20':
            raise LabError('Invalid ED25519 public key.')
        value='ssh-ed25519 '+fields[1]+' vpn-lab-download'
        program=('DOWNLOAD_PUBLIC_KEY = '+repr(value)+'\nDOWNLOAD_DEVICE = '+repr(device)+'\n'
                 +(ROOT/'ops/configure_download.py').read_text())
    elif operation=='close-download':
        program='REVOKE_DOWNLOAD = True\n'+(ROOT/'ops/configure_download.py').read_text()
    secret = environment.get('VPN_LAB_SSH_PRIVATE_KEY', '').strip().replace('\r\n', '\n')
    if (len(secret) > 16384 or not secret.startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n')
            or not secret.endswith('\n-----END OPENSSH PRIVATE KEY-----')):
        raise LabError('The vpn-lab environment needs VPN_LAB_SSH_PRIVATE_KEY (multiline private key).')
    with tempfile.TemporaryDirectory(prefix='vpn-lab-ssh-') as directory:
        key, hosts = Path(directory) / 'identity', Path(directory) / 'known_hosts'
        private_file(key, secret + '\n')
        private_file(hosts, known)
        sender_done=threading.Event()
        def send_probe():
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as channel:
                for _ in range(20):
                    if sender_done.wait(.5):
                        return
                    try:
                        channel.sendto(probe,(host,1194))
                    except OSError:
                        return
        sender=threading.Thread(target=send_probe,daemon=True) if probe else None
        if sender:
            sender.start()
        try:
            result = run([
            '/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', port, '-i', str(key),
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(hosts),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=10',
            '-o', 'ConnectionAttempts=1', '-o', 'ForwardAgent=no',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=8',
            '-o', 'ClearAllForwardings=yes', '-o', 'LogLevel=ERROR',
            'root@' + host, remote_command],
                input=program, timeout=timeout, limit=131072, env=ENVIRONMENT)
        finally:
            sender_done.set()
            if sender:
                sender.join(timeout=1)
        if result.returncode:
            if result.returncode == 255 and re.search(r'Permission denied \([^\r\n]*\)', result.stderr):
                raise LabError('SSH authentication rejected. The dedicated key grant may have expired; renew it in the provider console. Raw stderr withheld.')
            if operation == 'diagnose-connection':
                raise LabError('SSH connection diagnosis failed; raw diagnostic output and stderr withheld.')
            if operation == 'prepare-test-access':
                raise LabError('SSH test access preparation failed; raw output and stderr withheld.')
            if operation == 'inspect-test-peer':
                raise LabError('SSH test peer inspection failed; raw output and stderr withheld.')
            if operation == 'test-from-peer':
                raise LabError('SSH external VPN test failed; raw output and stderr withheld.')
            try:
                failure=json.loads(result.stdout)
            except ValueError:
                failure={}
            if (isinstance(failure,dict) and set(failure)=={'error','detail'}
                    and failure['error'] in ('setup_failed','selftest_failed')
                    and isinstance(failure['detail'],str)
                    and re.fullmatch(r'[A-Za-z0-9 ,/_.()-]{1,180}',failure['detail'])):
                raise LabError('Lab operation failed: '+failure['detail'])
            raise LabError('SSH '+operation+' failed. Check key authorization/expiry and environment-secret setup; raw stderr withheld.')
        try:
            report = json.loads(result.stdout)
        except ValueError:
            raise LabError('Inventory returned unsupported output; raw output withheld.') from None
        expected = {'os', 'kernel', 'root_free_bytes','uptime_seconds', 'running_service_units', 'listening_ports',
                    'candidate_vpn_subnet_overlaps_existing_route', 'firewall_summary', 'tools'}
        if operation=='install-foundation':
            expected={'version','server_service_active','vpn_udp_port','recovery_ssh_port','max_clients',
                      'required_factors','retired_runner_services','client_profile','credential_file',
                      'staged_login_implemented','source_commit'}
        elif operation=='diagnose-connection':
            expected={'version','server_utc','ntp_synchronized','services','tunnel',
                      'dns_listeners','authorization','input_counters','dns_probe'}
        elif operation=='prepare-test-access':
            expected={'ssh_public_key','ssh_public_key_fingerprint','private_key_retained_on_server'}
        elif operation=='inspect-test-peer':
            expected={'version','root_confirmed','os','kernel','access_server_active','openvpn_client','tools'}
        elif operation=='test-from-peer':
            expected={'version','peer_prepared','test','registry_restored',
                      'ephemeral_certificate_revoked','credential_contents_returned','stage','failure'}
        elif operation=='test-foundation':
            expected={'correct_credentials_connect','wrong_password_rejected',
                      'ipv4_dns_roundtrip_through_vpn_and_nat','metadata_private_network_packet_dropped',
                      'client_ipv6_block_response_observed','second_connection_rejected_without_displacing_first',
                      'unapproved_device_rejected','session_token_reauthentication',
                      'kernel_lease_expires_when_broker_frozen','ownership_transfers_between_devices',
                      'device_revocation_denies_forwarding',
                      'replayed_session_token_denied',
                      'disconnected_replay_preserves_broker',
                      'normal_disconnect_releases_slot',
                      'private_vpn_resolver_answers',
                      'host_routes_and_resolver_modified','credentials_exported'}
        elif operation=='probe-udp':
            expected={'public_udp_1194_received'}
        elif operation=='prepare-download':
            expected={'download_user','public_key_fingerprint','expires_utc','chrooted',
                      'read_only','shell_access','credential_contents_returned'}
        elif operation=='close-download':
            expected={'new_download_access_closed','private_export_copies_removed'}
        elif operation in ('device-status','revoke-device','enable-device','reset-sessions','reboot-lab'):
            expected={'devices','session_reset','reboot_scheduled','credential_contents_returned'}
        elif operation=='rotate-password':
            expected={'password_rotated','sessions_invalidated','old_download_closed','credential_contents_returned'}
        if not isinstance(report, dict) or set(report) != expected:
            raise LabError('Inventory returned unexpected fields; raw output withheld.')
        if operation == 'diagnose-connection':
            try:
                validate_connection_report(report)
            except ValueError:
                raise LabError('Connection diagnosis returned unsupported data; raw output withheld.') from None
        if operation == 'prepare-test-access':
            try:
                validate_test_access_report(report)
            except ValueError:
                raise LabError('Test access preparation returned unsupported public-key data; raw output withheld.') from None
        if operation == 'inspect-test-peer':
            try:
                validate_test_peer_report(report)
            except ValueError:
                raise LabError('Test peer inspection returned unsupported data; raw output withheld.') from None
        if operation == 'test-from-peer':
            try:
                validate_external_test_report(report)
            except ValueError:
                raise LabError('External VPN test returned unsupported data; raw output withheld.') from None
        if environment.get('GITHUB_ACTIONS') == 'true':
            # Checks annotations are available through api.github.com even when
            # signed log-download hosts cannot be reached by the controller.
            # This contains only the same approved inventory already in logs.
            message = json.dumps(report, sort_keys=True, separators=(',', ':'))
            if len(message.encode('utf-8')) > 60000:
                raise LabError('Inventory exceeds the check-report size limit; raw output withheld.')
            message = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            title='VPN lab inventory' if operation=='inventory' else 'VPN lab '+operation
            print('::notice title='+title+'::' + message)
        print(json.dumps(report, indent=2, sort_keys=True))
        if operation == 'test-from-peer' and (report['failure'] is not None or report['test'] is None
                or report['test']['passed'] is not True or report['registry_restored'] is not True
                or report['ephemeral_certificate_revoked'] is not True):
            # Stage is a fixed enum verified above. Keep the approved report
            # visible while ensuring failed packet tests/cleanup fail the job.
            raise LabError('External VPN test failed at '+report['stage']+'; see the validated report.')
    print('Lab '+operation+' completed; runner key file removed.')


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
        message=str(exc) if isinstance(exc, LabError) else 'Lab command failed or exceeded its time/output limit.'
        if os.environ.get('GITHUB_ACTIONS')=='true':
            escaped=message.replace('%','%25').replace('\r','%0D').replace('\n','%0A')
            print('::error title=VPN lab operation failed::'+escaped,flush=True)
        print(message,file=sys.stderr)
        raise SystemExit(1)
