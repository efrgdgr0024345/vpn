#!/usr/bin/python3
"""Run one ephemeral VPN client on an explicitly pinned, owner-controlled peer."""
import base64
import fcntl
import importlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shlex
import stat
import subprocess
import tempfile
import time
from types import SimpleNamespace

FOUNDATION = Path('/usr/local/libexec/vpn-lab/server_foundation.py')
CRL = Path('/etc/openvpn/server/vpn-lab-crl.pem')
STAGES = {'preflight', 'peer_prepare', 'certificate', 'registry', 'peer_test', 'cleanup', 'complete'}
FAILURES = {'busy', 'host_pin_failed', 'peer_prepare_failed', 'test_failed', 'registry_changed',
            'certificate_cleanup_failed', 'local_verification_failed', 'ssh_failed', 'invalid_peer_report'}
REPORT_KEYS = {'version', 'peer_prepared', 'test', 'registry_restored',
               'ephemeral_certificate_revoked', 'credential_contents_returned', 'stage', 'failure'}


class TestError(RuntimeError):
    pass


def protected(path, *, private=False, directory=False):
    info = path.lstat()
    if (info.st_uid != 0 or info.st_mode & (0o077 if private else 0o022)
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or not directory and info.st_nlink != 1):
        raise TestError('local_verification_failed')


def load_server():
    for path in reversed(FOUNDATION.parents):
        protected(path, directory=True)
    protected(FOUNDATION)
    fd = os.open(FOUNDATION, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        source = stream.read(262145)
    if len(source) > 262144:
        raise TestError('local_verification_failed')
    namespace = {'__name__': 'verified_test_foundation'}
    exec(compile(source, '<verified-test-foundation>', 'exec'), namespace)
    return SimpleNamespace(**namespace)


def public_library(source, name):
    if source is None:
        return vars(importlib.import_module(name))
    if not isinstance(source, str) or not 1 <= len(source.encode()) <= 65536:
        raise TestError('local_verification_failed')
    namespace = {'__name__': 'verified_'+name}
    exec(compile(source, '<verified-'+name+'>', 'exec'), namespace)
    return namespace


def client_library(source=None):
    return public_library(source if source is not None else globals().get('PEER_CLIENT_SOURCE'), 'peer_vpn_client')


def validate_report(value):
    try:
        if not isinstance(value, dict) or set(value) != REPORT_KEYS or type(value['version']) is not int or value['version'] != 1:
            raise ValueError()
        for key in ('peer_prepared', 'registry_restored', 'ephemeral_certificate_revoked'):
            if type(value[key]) is not bool:
                raise ValueError()
        if value['credential_contents_returned'] is not False:
            raise ValueError()
        if not isinstance(value['stage'], str) or value['stage'] not in STAGES:
            raise ValueError()
        if value['failure'] is not None and (not isinstance(value['failure'], str) or value['failure'] not in FAILURES):
            raise ValueError()
        if value['test'] is not None:
            client_library()['validate_report'](value['test'])
            if value['test']['mode'] != 'test':
                raise ValueError()
        if value['failure'] is None and (value['stage'] != 'complete' or value['test'] is None
                or not value['test']['passed'] or not all(value[key] for key in
                    ('peer_prepared', 'registry_restored', 'ephemeral_certificate_revoked'))):
            raise ValueError()
        return value
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError('Unsupported external VPN test report.') from None


def empty_authorization(server):
    document = json.loads(server.run(['/usr/sbin/nft', '-j', 'list', 'set', 'inet', 'vpn_lab', 'authorized']))
    if not isinstance(document, dict) or not isinstance(document.get('nftables'), list):
        raise TestError('local_verification_failed')
    sets = [item['set'] for item in document['nftables'] if isinstance(item, dict) and isinstance(item.get('set'), dict)
            and item['set'].get('family') == 'inet' and item['set'].get('table') == 'vpn_lab'
            and item['set'].get('name') == 'authorized']
    if len(sets) != 1 or sets[0].get('type') != 'ipv4_addr' or not isinstance(sets[0].get('elem', []), list):
        raise TestError('local_verification_failed')
    if sets[0].get('elem', []):
        raise TestError('busy')


def registry(value):
    devices = json.loads(value)
    if not isinstance(devices, dict) or set(devices) != {'kali', 'iphone', 'android'}:
        raise TestError('local_verification_failed')
    addresses, fingerprints, names = set(), set(), set()
    for device in devices.values():
        if not isinstance(device, dict) or set(device) != {'cn', 'sha256', 'address', 'enabled'}:
            raise TestError('local_verification_failed')
        if (not isinstance(device['cn'], str) or re.fullmatch(r'[A-Za-z0-9-]{1,64}', device['cn']) is None
                or not isinstance(device['sha256'], str) or re.fullmatch(r'[0-9a-f]{64}', device['sha256']) is None
                or type(device['enabled']) is not bool):
            raise TestError('local_verification_failed')
        address = ipaddress.IPv4Address(device['address'])
        if str(address) != device['address'] or address not in ipaddress.ip_network('172.27.240.0/24'):
            raise TestError('local_verification_failed')
        if device['address'] in addresses or device['sha256'] in fingerprints or device['cn'] in names:
            raise TestError('local_verification_failed')
        addresses.add(device['address'])
        fingerprints.add(device['sha256'])
        names.add(device['cn'])
    return devices


def remote(peer, known_hosts, source, host, port, request, client):
    if not isinstance(source, str) or not 1 <= len(source.encode()) <= 65536:
        raise TestError('local_verification_failed')
    encoded = base64.b64encode(source.encode()).decode()
    bootstrap = 'import base64;exec(compile(base64.b64decode('+repr(encoded)+'),"<verified-peer-client>","exec"),{"__name__":"__main__"})'
    command = '/usr/bin/python3 -I -B -c '+shlex.quote(bootstrap)
    argv = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', port, '-i', str(peer['KEY']),
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile='+str(known_hosts), '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-o', 'IdentityAgent=none',
            '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
            '-o', 'KbdInteractiveAuthentication=no', '-o', 'HostKeyAlgorithms=ssh-ed25519',
            '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3', '-o', 'LogLevel=ERROR',
            'root@'+host, command]
    try:
        result = peer['run'](argv, input=json.dumps(request), timeout=600 if request['mode'] == 'prepare' else 180, limit=32768)
    except Exception:
        raise TestError('ssh_failed') from None
    if result.returncode:
        raise TestError('ssh_failed')
    try:
        value = client['validate_report'](json.loads(result.stdout))
        if value['mode'] != request['mode']:
            raise ValueError()
        return value
    except (ValueError, TypeError, KeyError):
        raise TestError('invalid_peer_report') from None


def restore_registry(server, path, original, candidate, replacement):
    current = server.read_owned(path)
    if current == original:
        return
    if current == candidate:
        server.write(path, original)
        if server.read_owned(path) != original:
            raise TestError('registry_changed')
        return
    # An independent root administrator may have edited another device. Undo
    # only our own substitution, preserving that administrator's other records.
    devices = registry(current)
    if devices['android'] == replacement:
        devices['android'] = registry(original)['android']
        server.write(path, json.dumps(devices, sort_keys=True)+'\n')
    raise TestError('registry_changed')


def revoke_and_remove(server, cn):
    certificate = server.PKI/'issued'/(cn+'.crt')
    revoked = False
    try:
        if certificate.exists() or certificate.is_symlink():
            protected(certificate)
            server.easyrsa('revoke', cn)
            server.easyrsa('gen-crl')
            server.write(CRL, server.read_owned(server.PKI/'crl.pem'), 0o644)
            revoked = True
    finally:
        # Keep issued certificates, serial files and the CA index as revocation
        # audit evidence; discard only this temporary identity's private key/CSR.
        for path in (server.PKI/'private'/(cn+'.key'), server.PKI/'reqs'/(cn+'.req')):
            if path.exists() or path.is_symlink():
                protected(path, private=path.suffix == '.key')
                path.unlink()
    return revoked


def orchestrate(*, server=None, peer=None, client=None, client_source=None,
                host=None, port='22', fingerprint=None, server_host=None):
    result = {'version': 1, 'peer_prepared': False, 'test': None, 'registry_restored': True,
              'ephemeral_certificate_revoked': False, 'credential_contents_returned': False,
              'stage': 'preflight', 'failure': None}
    try:
        if os.geteuid() != 0:
            raise TestError('local_verification_failed')
        server = server or load_server()
        peer = peer or public_library(globals().get('PEER_LIBRARY_SOURCE'), 'inspect_test_peer')
        client = client or client_library(client_source)
        client_source = client_source if client_source is not None else globals().get('PEER_CLIENT_SOURCE')
        host, port, fingerprint = peer['settings'](host, port, fingerprint)
        address = ipaddress.IPv4Address(server_host)
        if str(address) != server_host or address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
            raise TestError('local_verification_failed')
        peer['check_key']()
        try:
            known = peer['pin_host'](host, port, fingerprint, peer['run'])
        except Exception:
            raise TestError('host_pin_failed') from None
        for path in (*reversed(server.CONFIG.parents), server.CONFIG):
            protected(path, directory=True)
        lock_path = server.CONFIG/'install.lock'
        if lock_path.exists() or lock_path.is_symlink():
            protected(lock_path, private=True)
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock_fd, 'r+b') as lock:
            info = os.fstat(lock.fileno())
            if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
                raise TestError('local_verification_failed')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise TestError('busy') from None
            empty_authorization(server)
            with tempfile.TemporaryDirectory(prefix='vpn-external-test-', dir=peer['RUNTIME']) as temporary:
                known_hosts = Path(temporary)/'known_hosts'
                with os.fdopen(os.open(known_hosts, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
                    stream.write(known)
                result['stage'] = 'peer_prepare'
                prepared = remote(peer, known_hosts, client_source, host, port, {'mode': 'prepare'}, client)
                if not prepared['passed'] or not prepared['tools_ready'] or not prepared['cleanup_confirmed']:
                    raise TestError('peer_prepare_failed')
                result['peer_prepared'] = True
                path = server.CONFIG/'devices.json'
                protected(path, private=True)
                original = server.read_owned(path)
                devices = registry(original)
                cn = 'vpn-test-'+secrets.token_hex(12)
                targets = [server.PKI/folder/(cn+suffix) for folder, suffix in
                           (('issued', '.crt'), ('private', '.key'), ('reqs', '.req'))]
                if any(target.exists() or target.is_symlink() for target in targets):
                    raise TestError('local_verification_failed')
                candidate, replacement, substituted = None, None, False
                try:
                    result['stage'] = 'certificate'
                    server.easyrsa('build-client-full', cn, 'nopass')
                    fingerprint_text = server.run(['/usr/bin/openssl', 'x509', '-in', str(server.PKI/'issued'/(cn+'.crt')),
                                                   '-noout', '-fingerprint', '-sha256'])
                    digest = fingerprint_text.strip().split('=', 1)[-1].replace(':', '').lower()
                    if re.fullmatch(r'[0-9a-f]{64}', digest) is None:
                        raise TestError('local_verification_failed')
                    profile = server.client_configuration(server_host, cn, portable=True)
                    login_path = server.EXPORT/'login.txt'
                    protected(login_path, private=True)
                    login = server.read_owned(login_path)
                    parts = login.splitlines()
                    if len(parts) != 2 or parts[0] != 'vpn-lab-client' or not 40 <= len(parts[1]) <= 256:
                        raise TestError('local_verification_failed')
                    result['stage'] = 'registry'
                    empty_authorization(server)
                    if server.read_owned(path) != original:
                        raise TestError('registry_changed')
                    replacement = {'cn': cn, 'sha256': digest, 'address': '172.27.240.249', 'enabled': True}
                    devices['android'] = replacement
                    registry(json.dumps(devices))
                    candidate = json.dumps(devices, sort_keys=True)+'\n'
                    substituted = True
                    result['registry_restored'] = False
                    server.write(path, candidate)
                    # The installed broker reloads its protected registry once
                    # per second. Starting a local/fast peer immediately can
                    # otherwise present the fresh certificate to stale pins.
                    # This is scheduling room, not proof of authorization.
                    time.sleep(1.25)
                    empty_authorization(server)
                    result['stage'] = 'peer_test'
                    result['test'] = remote(peer, known_hosts, client_source, host, port,
                        {'mode': 'test', 'profile': profile, 'login': login, 'server_ipv4': server_host,
                         'expected_ipv4': '172.27.240.249'}, client)
                    if not result['test']['passed']:
                        raise TestError('test_failed')
                finally:
                    cleanup_error = None
                    if substituted:
                        try:
                            restore_registry(server, path, original, candidate, replacement)
                            result['registry_restored'] = True
                        except Exception:
                            cleanup_error = 'registry_changed'
                    try:
                        result['ephemeral_certificate_revoked'] = revoke_and_remove(server, cn)
                    except Exception:
                        cleanup_error = 'certificate_cleanup_failed'
                    if cleanup_error:
                        result['stage'] = 'cleanup'
                        raise TestError(cleanup_error)
        result['stage'] = 'complete'
    except Exception as error:
        result['failure'] = str(error) if isinstance(error, TestError) and str(error) in FAILURES else 'local_verification_failed'
    return result


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    value = orchestrate(host=globals().get('TEST_PEER_HOST'), port=globals().get('TEST_PEER_PORT', '22'),
                        fingerprint=globals().get('TEST_PEER_HOST_FINGERPRINT'), server_host=globals().get('TEST_SERVER_HOST'))
    try:
        print(json.dumps(validate_report(value), sort_keys=True))
    except (ValueError, ImportError, TestError):
        raise SystemExit('External VPN test report validation failed; private contents withheld.') from None


if __name__ == '__main__':
    main()
