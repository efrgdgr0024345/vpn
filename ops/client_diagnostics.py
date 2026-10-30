#!/usr/bin/python3
"""One explicit VPN test with private credentials and authenticated recovery."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib
import inspect
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import resource
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT_UID = 0
APP = Path('/opt/vpn-desk')
HELPERS = Path('/usr/local/libexec/vpn-desk')
ROOTS = (APP, HELPERS)
MANIFEST = APP/'install-manifest.json'
EXACT = {'/usr/local/bin/vpn-desk', '/usr/local/share/applications/vpn-desk.desktop'}
CONFIG = Path('/etc/vpn-desk')
TEST_LOGIN = CONFIG/'testing-login.txt'
ACTION_LOCK = Path('/run/vpn-dashboard-portal.lock')
TEST_LOCK = Path('/run/vpn-desk-test.lock')
SOCKET = Path('/run/vpn-desk/session.sock')
NAMES = ('security', 'safe_io', 'session_channel', 'portal_helper', 'firewall_policy',
         'network_setup', 'vpn_session_helper')
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}
OUTCOMES = {'success', 'installation_unverified', 'credential_error', 'restore_not_authorized',
    'owner_invalid', 'preflight_failed', 'lock_busy', 'auth_failed', 'tls_failed',
    'configuration_failed', 'route_failed', 'server_timeout', 'handshake_timeout',
    'startup_timeout', 'reconnecting', 'attempt_timeout', 'session_failed', 'dns_failed',
    'system_dns_failed', 'https_failed', 'interrupted', 'cleanup_failed', 'restore_failed', 'internal_error'}
WITHHELD = {'none', 'preflight_unchanged', 'ownership_unproven', 'child_running',
            'lock_busy', 'active_openvpn', 'state_missing', 'restore_refused', 'network_changed'}
DNS_STATUS = {'unchecked', 'checking', 'ok', 'timeout', 'servfail', 'refused', 'truncated',
              'invalid', 'no_answer', 'rcode_error', 'route_unavailable', 'transport_failed', 'not_run'}
TOP_KEYS = {'version', 'started_utc', 'finished_utc', 'kernel', 'outcome', 'credentials',
            'before', 'checks', 'session', 'after', 'recovery', 'child_exit_status'}
_INTERRUPTED = False
_REPORT_CHANNEL = None


class DiagnosticError(RuntimeError):
    def __init__(self, code):
        self.code = code if code in OUTCOMES else 'internal_error'
        super().__init__(self.code)


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def trusted_parents(path):
    for parent in reversed(Path(path).parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise DiagnosticError('installation_unverified')


def read_public(path, *, private=False):
    path = Path(path)
    trusted_parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1
                or info.st_mode & 0o022 or private and stat.S_IMODE(info.st_mode) != 0o600):
            raise DiagnosticError('installation_unverified')
        value = stream.read(2_000_001)
    if len(value) > 2_000_000:
        raise DiagnosticError('installation_unverified')
    return value


def verify_installation():
    try:
        document = json.loads(read_public(MANIFEST))
        if (not isinstance(document, dict) or set(document) != {'version', 'files'}
                or type(document['version']) is not int or document['version'] != 1
                or not isinstance(document['files'], dict) or not 10 <= len(document['files']) <= 80):
            raise ValueError()
        files = document['files']
        required = {str(HELPERS/(name+'.py')) for name in NAMES} | EXACT
        if not required <= set(files):
            raise ValueError()
        for name, digest in files.items():
            path = Path(name)
            if (not path.is_absolute() or str(path) != name or '..' in path.parts
                    or not (path.parent in ROOTS or name in EXACT)
                    or re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', path.name) is None
                    or not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None
                    or hashlib.sha256(read_public(path)).hexdigest() != digest):
                raise ValueError()
        for root in ROOTS:
            trusted_parents(root/'member')
            if any(str(path) not in files and path != MANIFEST for path in root.iterdir()):
                raise ValueError()
    except (OSError, ValueError, TypeError, KeyError, DiagnosticError):
        raise DiagnosticError('installation_unverified') from None


def load_modules():
    verify_installation()
    # A hash-checked script must never reuse a checkout module or another
    # caller's cached module with the same short import name.
    for name in NAMES:
        sys.modules.pop(name, None)
    sys.path.insert(0, str(HELPERS))
    importlib.invalidate_caches()
    modules = {name: importlib.import_module(name) for name in NAMES}
    if any(Path(module.__file__) != HELPERS/(name+'.py') for name, module in modules.items()):
        raise DiagnosticError('installation_unverified')
    helper = modules['vpn_session_helper']
    if ('test_credentials' not in inspect.signature(helper.main).parameters
            or not callable(getattr(helper, 'dns_reply_status', None))
            or not callable(getattr(helper, 'private_dns_probe', None))):
        raise DiagnosticError('installation_unverified')
    return modules


def credentials(path, owner):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (ROOT_UID, owner)
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError()
            value = stream.read(513)
        if (len(value) > 512 or not value.endswith(b'\n') or value.count(b'\n') != 2
                or b'\r' in value):
            raise ValueError()
        user, password, _ = value.split(b'\n')
        if user != b'vpn-lab-client' or not 20 <= len(password) <= 256 or any(byte < 33 or byte > 126 for byte in password):
            raise ValueError()
        return value
    except (OSError, ValueError, TypeError):
        raise DiagnosticError('credential_error') from None


def save_credentials(value):
    trusted_parents(TEST_LOGIN)
    if stat.S_IMODE(CONFIG.lstat().st_mode) != 0o700:
        raise DiagnosticError('credential_error')
    if os.path.lexists(TEST_LOGIN):
        credentials(TEST_LOGIN, ROOT_UID)
    fd, temporary = tempfile.mkstemp(prefix='.testing-login-', dir=CONFIG)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, TEST_LOGIN)
        directory = os.open(CONFIG, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def locked(path):
    trusted_parents(path)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+b') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise DiagnosticError('lock_busy')
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DiagnosticError('lock_busy') from None
        yield


def command(argv, *, timeout=3, limit=32768):
    process = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=ENV)
        output, deadline = bytearray(), time.monotonic()+timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline-time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return 'timeout', b''
                part = os.read(process.stdout.fileno(), min(4096, limit+1-len(output)))
                if not part:
                    break
                output.extend(part)
                if len(output) > limit:
                    return 'failed', b''
        code = process.wait(timeout=max(.001, deadline-time.monotonic()))
        return ('ok', bytes(output)) if code == 0 else ('failed', b'')
    except (OSError, ValueError, subprocess.SubprocessError):
        return 'failed', b''
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            process.stdout.close()


def ip_json(arguments):
    status, output = command(['/usr/sbin/ip', '-j', '-4', *arguments])
    if status != 'ok':
        raise DiagnosticError('preflight_failed')
    try:
        return json.loads(output)
    except ValueError:
        raise DiagnosticError('preflight_failed') from None


def ipv4(value):
    if not isinstance(value, str) or str(ipaddress.IPv4Address(value)) != value:
        raise ValueError()
    return value


def interface(value):
    if not isinstance(value, str) or re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}', value) is None:
        raise ValueError()
    return value


def guard_present(modules):
    document = modules['portal_helper'].js(['/usr/sbin/nft', '-j', 'list', 'ruleset'])
    if not isinstance(document, dict) or not isinstance(document.get('nftables'), list):
        raise DiagnosticError('preflight_failed')
    return any(isinstance(item, dict) and isinstance(item.get('table'), dict)
               and item['table'].get('name') == 'vpn_guard' for item in document['nftables'])


def network_snapshot(modules, policy):
    routes = ip_json(['route', 'show'])
    if not isinstance(routes, list) or len(routes) > 64:
        raise DiagnosticError('preflight_failed')
    rows = []
    for route in routes:
        if not isinstance(route, dict) or not isinstance(route.get('dst'), str):
            raise DiagnosticError('preflight_failed')
        destination = route['dst']
        if destination != 'default':
            destination = str(ipaddress.IPv4Network(destination, strict=False))
        rows.append({'destination': destination, 'interface': interface(route.get('dev')),
                     'gateway': ipv4(route['gateway']) if 'gateway' in route else None,
                     'source': ipv4(route['prefsrc']) if 'prefsrc' in route else None})
    rows.sort(key=lambda row: json.dumps(row, sort_keys=True))
    physical = ip_json(['route', 'get', policy['vpn_server_ipv4']])
    if not isinstance(physical, list) or len(physical) != 1 or not isinstance(physical[0], dict):
        raise DiagnosticError('preflight_failed')
    physical = physical[0]
    resolver = modules['network_setup'].resolver_read()
    addresses, has_ipv6 = [], False
    for line in resolver.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == 'nameserver':
            address = ipaddress.ip_address(fields[1])
            if address.version == 4:
                addresses.append(str(address))
            else:
                has_ipv6 = True
    if len(addresses) > 8:
        raise DiagnosticError('preflight_failed')
    links = ip_json(['address', 'show'])
    return {'wifi_interface': interface(policy['wifi_interface']),
            'endpoint': {'ipv4': ipv4(policy['vpn_server_ipv4']), 'port': policy['vpn_port'], 'protocol': policy['vpn_protocol']},
            'dhcp_server_ipv4': ipv4(policy['dhcp_server_ipv4']),
            'physical_route': {'interface': interface(physical.get('dev')),
                'source': ipv4(physical.get('prefsrc', physical.get('src'))),
                'gateway': ipv4(physical['gateway']) if 'gateway' in physical else None},
            'resolver_ipv4': addresses, 'ipv6_resolver_present': has_ipv6, 'routes': rows,
            'guard_present': guard_present(modules), 'state_present': os.path.lexists(CONFIG/'network-state.json'),
            'tun_present': any(isinstance(link, dict) and link.get('ifname') == 'tun0' for link in links)}


def socket_stamp():
    try:
        info = SOCKET.lstat()
        return info.st_dev, info.st_ino, info.st_ctime_ns
    except FileNotFoundError:
        return None


def child_status(pid, owner, previous, modules, action='status'):
    try:
        trusted_parents(SOCKET)
        info = SOCKET.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != owner
                or (info.st_dev, info.st_ino, info.st_ctime_ns) == previous):
            return None
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            deadline = time.monotonic()+.5
            def timeout():
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise socket.timeout()
                channel.settimeout(remaining)
            timeout()
            channel.connect(str(SOCKET))
            peer_pid, peer_uid, _ = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer_pid != pid or peer_uid != ROOT_UID:
                return None
            timeout()
            channel.sendall(action.encode()+b'\n')
            data = bytearray()
            while b'\n' not in data and len(data) <= 131072:
                timeout()
                part = channel.recv(min(8192, 131073-len(data)))
                if not part:
                    break
                data.extend(part)
            if len(data) > 131072 or data.count(b'\n') != 1 or not data.endswith(b'\n'):
                return None
            value = json.loads(data)
            if action == 'stop':
                return value if value == {'stop_requested': True} else None
            return modules['session_channel'].validate_snapshot(value)
    except (OSError, ValueError, RuntimeError):
        return None


def launch(owner):
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    process = None
    try:
        code = ('import os,sys;permit=os.read('+str(read_fd)+',1);os.close('+str(read_fd)+');'
                'sys.exit(1) if permit!=b"1" else None;sys.path.insert(0,'+repr(str(HELPERS))+');'
                'import vpn_session_helper as s;raise SystemExit(s.main('+str(owner)+',test_credentials=True))')
        process = subprocess.Popen(['/usr/bin/python3', '-I', '-B', '-c', code],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=ENV, pass_fds=(read_fd,), start_new_session=True)
        os.close(read_fd)
        read_fd = None
        pidfd = os.pidfd_open(process.pid)
        os.write(write_fd, b'1')
        return process, pidfd
    except (OSError, ValueError):
        # Without the permit the child exits before importing/starting OpenVPN.
        if process is not None:
            os.close(write_fd)
            write_fd = None
            process.wait(timeout=3)
        raise DiagnosticError('session_failed') from None
    finally:
        if read_fd is not None:
            os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


def stop_owned(process, pidfd, owner, previous, modules):
    if process.poll() is not None:
        return True
    child_status(process.pid, owner, previous, modules, 'stop')
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=15)
        return True
    except subprocess.TimeoutExpired:
        # Killing a supervisor could orphan OpenVPN. Leave protection enabled.
        return False


def restore_owned(modules, proof, stopped, recovery):
    if not stopped:
        recovery['restore_withheld'] = 'child_running'
        return
    if not proof:
        recovery['restore_withheld'] = 'ownership_unproven'
        return
    try:
        with locked(ACTION_LOCK):
            if modules['portal_helper'].active_openvpn():
                recovery['restore_withheld'] = 'active_openvpn'
                return
            if not os.path.lexists(CONFIG/'network-state.json'):
                recovery['restore_withheld'] = 'state_missing'
                return
            recovery['restore_attempted'] = True
            modules['network_setup'].restore()
            recovery['restored'] = True
            recovery['restore_withheld'] = 'none'
    except DiagnosticError:
        recovery['restore_withheld'] = 'lock_busy'
    except (OSError, ValueError, RuntimeError):
        recovery['restore_withheld'] = 'restore_refused'


def public_tunnel():
    try:
        route = ip_json(['route', 'get', '9.9.9.9'])
        routes = ip_json(['route', 'show'])
        return (isinstance(route, list) and len(route) == 1 and route[0].get('dev') == 'tun0'
                and {'0.0.0.0/1', '128.0.0.0/1'} <= {row.get('dst') for row in routes if row.get('dev') == 'tun0'})
    except (DiagnosticError, ValueError, TypeError, AttributeError):
        return False


def tcp_dns(helper):
    source = helper.dns_tunnel_source()
    if source is None:
        return 'route_unavailable'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
            deadline = time.monotonic()+3
            def timeout():
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise socket.timeout()
                channel.settimeout(remaining)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'tun0\0')
            channel.bind((source, 0))
            timeout()
            channel.connect(('172.27.240.1', 53))
            identifier = int.from_bytes(os.urandom(2), 'big')
            query = struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0)+helper.DNS_QUESTION
            timeout()
            channel.sendall(struct.pack('!H', len(query))+query)
            def receive(size):
                value = bytearray()
                while len(value) < size:
                    timeout()
                    part = channel.recv(size-len(value))
                    if not part:
                        raise ValueError()
                    value.extend(part)
                return bytes(value)
            size = struct.unpack('!H', receive(2))[0]
            if not 12 <= size <= 4096:
                return 'invalid'
            return helper.dns_reply_status(receive(size), identifier)
    except socket.timeout:
        return 'timeout'
    except (OSError, ValueError, struct.error):
        return 'transport_failed'


def connection_checks(modules, started, deadline):
    row = {'utc': utc(), 'elapsed_ms': int((time.monotonic()-started)*1000),
           'tunnel_route_verified': public_tunnel(), 'private_dns': 'not_run',
           'private_dns_tcp': 'not_run', 'system_dns': 'not_run', 'https': 'not_run', 'http_status': None}
    if not row['tunnel_route_verified']:
        return row
    helper = modules['vpn_session_helper']
    if time.monotonic()+7 < deadline:
        row['private_dns'] = helper.private_dns_probe()[0]
    if time.monotonic()+4 < deadline:
        row['private_dns_tcp'] = tcp_dns(helper)
    if time.monotonic()+3 < deadline:
        row['system_dns'] = command(['/usr/bin/getent', 'ahostsv4', 'example.com'], timeout=3, limit=8192)[0]
    remaining = deadline-time.monotonic()
    if remaining >= 1:
        status, output = command(['/usr/bin/curl', '-q', '-4', '--interface', 'tun0', '--noproxy', '*',
            '--proto', '=https', '--connect-timeout', '3', '--max-time', str(min(8, int(remaining))),
            '--silent', '--show-error', '--output', '/dev/null', '--write-out', '%{http_code}',
            'https://example.com/'], timeout=min(8, remaining)+.2, limit=16)
        code = int(output) if re.fullmatch(rb'[0-9]{3}', output) else None
        row['http_status'] = code
        row['https'] = 'ok' if status == 'ok' and code is not None and 200 <= code < 400 else status if status != 'ok' else 'failed'
    return row


def new_report():
    stamp = utc()
    kernel = platform.release()
    return {'version': 1, 'started_utc': stamp, 'finished_utc': stamp,
        'kernel': kernel if re.fullmatch(r'[A-Za-z0-9_.+\-]{1,160}', kernel) else 'unknown',
        'outcome': 'internal_error', 'credentials': 'not_checked', 'before': None, 'checks': [],
        'session': None, 'after': None, 'child_exit_status': None,
        'recovery': {'child_stopped': True, 'ownership_proven': False, 'restore_attempted': False,
            'restored': False, 'guard_absent': None, 'state_absent': None, 'routes_match': None,
            'dns_match': None, 'confirmed': False, 'restore_withheld': 'preflight_unchanged'}}


def session_failure(snapshot):
    for row in snapshot['events']:
        code = row['code']
        if code in {'auth_failed','tls_failed','configuration_failed','route_failed',
                    'server_timeout','handshake_timeout','startup_timeout','reconnecting'}:
            return code
    return 'session_failed' if snapshot['state'] == 'error' else None


def run_test(owner, credential_path=None, *, restore_after_test=False):
    global _REPORT_CHANNEL
    _REPORT_CHANNEL = None
    report, modules, process, pidfd = new_report(), None, None, None
    test_mutex, mutex_held, policy, baseline_dns = None, False, None, None
    started, deadline, proof, previous = time.monotonic(), time.monotonic()+60, False, None
    if not restore_after_test:
        report['outcome'] = 'restore_not_authorized'
        return report
    if type(owner) is not int or not 1 <= owner < 2**32-1:
        report['outcome'] = 'owner_invalid'
        return report
    try:
        modules = load_modules()
        _REPORT_CHANNEL = modules['session_channel']
        test_mutex = locked(TEST_LOCK)
        test_mutex.__enter__()
        mutex_held = True
        policy = modules['security'].load_policy()
        with locked(ACTION_LOCK):
            modules['portal_helper'].check_network()
            report['before'] = network_snapshot(modules, policy)
            baseline_dns = modules['network_setup'].resolver_read()
            if (report['before']['guard_present'] or report['before']['state_present']
                    or report['before']['tun_present']):
                raise DiagnosticError('preflight_failed')
            defaults = [row for row in report['before']['routes'] if row['destination'] == 'default']
            if (len(defaults) != 1 or defaults[0]['interface'] != policy['wifi_interface']
                    or defaults[0]['gateway'] is None
                    or report['before']['physical_route']['interface'] != policy['wifi_interface']):
                raise DiagnosticError('preflight_failed')
            nft = modules['portal_helper'].js(['/usr/sbin/nft', '-j', 'list', 'ruleset'])
            if any('table' in row for row in nft['nftables']):
                raise DiagnosticError('preflight_failed')
            if credential_path is not None:
                save_credentials(credentials(credential_path, owner))
                report['credentials'] = 'imported'
            else:
                credentials(TEST_LOGIN, ROOT_UID)
                report['credentials'] = 'reused'
            previous = socket_stamp()
        process, pidfd = launch(owner)
        report['recovery']['child_stopped'] = False
        ready_at = None
        while time.monotonic() < deadline:
            if _INTERRUPTED:
                raise DiagnosticError('interrupted')
            snapshot = child_status(process.pid, owner, previous, modules)
            if snapshot is not None:
                report['session'] = snapshot
                codes = [row['code'] for row in snapshot['events']]
                proof = proof or {'guard_checked', 'dns_configured', 'credentials'} <= set(codes)
                failure = session_failure(snapshot)
                if failure is not None:
                    raise DiagnosticError(failure)
                if 'tunnel_ready' in codes and ready_at is None:
                    ready_at = time.monotonic()
            if process.poll() is not None:
                raise DiagnosticError('session_failed')
            if ready_at is not None:
                due = 1 if not report['checks'] else 10
                if time.monotonic()-ready_at >= due:
                    report['checks'].append(connection_checks(modules, started, deadline))
                    if len(report['checks']) == 2:
                        check = report['checks'][-1]
                        report['outcome'] = ('dns_failed' if check['private_dns'] != 'ok'
                            else 'system_dns_failed' if check['system_dns'] != 'ok'
                            else 'https_failed' if check['https'] != 'ok' else 'success')
                        break
            time.sleep(.1)
        else:
            report['outcome'] = 'attempt_timeout'
        # Keep the test mutex through stop/restore so a second runner cannot
        # replace credentials or misattribute this attempt's network state.
        finish_test(report, modules, process, pidfd, owner, previous, proof, policy, baseline_dns)
        process = None
    except DiagnosticError as error:
        report['outcome'] = error.code
    except KeyboardInterrupt:
        report['outcome'] = 'interrupted'
    except Exception:
        report['outcome'] = 'preflight_failed' if process is None else 'session_failed'
    finally:
        if process is not None and modules is not None:
            finish_test(report, modules, process, pidfd, owner, previous, proof, policy, baseline_dns)
        if pidfd is not None:
            os.close(pidfd)
        if mutex_held:
            test_mutex.__exit__(None, None, None)
        report['finished_utc'] = utc()
    return report


def finish_test(report, modules, process, pidfd, owner, previous, proof, policy, baseline_dns=None):
    recovery = report['recovery']
    try:
        # A transport failure may arrive while bounded DNS/HTTPS checks run.
        # Sample the same authenticated child once more before stopping it.
        snapshot = child_status(process.pid, owner, previous, modules)
        if snapshot is not None:
            report['session'] = snapshot
            proof = proof or {'guard_checked','dns_configured','credentials'} <= {row['code'] for row in snapshot['events']}
            failure = session_failure(snapshot)
            if failure is not None and report['outcome'] == 'success':
                report['outcome'] = failure
        recovery['ownership_proven'] = proof
        stopped = stop_owned(process, pidfd, owner, previous, modules)
        recovery['child_stopped'] = stopped
        report['child_exit_status'] = process.returncode
        if stopped and process.returncode != 0 and report['outcome'] == 'success':
            report['outcome'] = 'session_failed'
        restore_owned(modules, proof, stopped, recovery)
        if not stopped:
            report['outcome'] = 'cleanup_failed'
            return
        report['after'] = network_snapshot(modules, policy)
        after, before = report['after'], report['before']
        recovery['guard_absent'] = not after['guard_present']
        recovery['state_absent'] = not after['state_present']
        recovery['routes_match'] = before is not None and after['routes'] == before['routes']
        recovery['dns_match'] = (baseline_dns is not None
            and modules['network_setup'].resolver_read() == baseline_dns)
        recovery['confirmed'] = (recovery['restored'] and all(recovery[key] for key in
            ('child_stopped','guard_absent','state_absent','routes_match','dns_match'))
            and not modules['portal_helper'].active_openvpn())
        if not recovery['confirmed']:
            if recovery['restored']:
                recovery['restore_withheld'] = 'network_changed'
            report['outcome'] = 'restore_failed'
    except Exception:
        recovery['restore_withheld'] = 'restore_refused'
        report['outcome'] = 'restore_failed'


def validate_report(value, channel=None):
    """No arbitrary child output, credentials, exception strings or paths."""
    try:
        if not isinstance(value, dict) or set(value) != TOP_KEYS or type(value['version']) is not int or value['version'] != 1:
            raise ValueError()
        for name in ('started_utc', 'finished_utc'):
            if not isinstance(value[name], str) or re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00', value[name]) is None:
                raise ValueError()
            datetime.fromisoformat(value[name])
        if (value['outcome'] not in OUTCOMES or value['credentials'] not in ('not_checked','imported','reused')
                or not isinstance(value['kernel'], str) or re.fullmatch(r'[A-Za-z0-9_.+\-]{1,160}', value['kernel']) is None):
            raise ValueError()
        for name in ('before', 'after'):
            item = value[name]
            if item is not None:
                if set(item) != {'wifi_interface','endpoint','dhcp_server_ipv4','physical_route',
                        'resolver_ipv4','ipv6_resolver_present','routes','guard_present','state_present','tun_present'}:
                    raise ValueError()
                interface(item['wifi_interface']); ipv4(item['dhcp_server_ipv4'])
                endpoint = item['endpoint']
                if set(endpoint) != {'ipv4','port','protocol'} or endpoint['protocol'] not in ('udp','tcp-client') or type(endpoint['port']) is not int or not 1 <= endpoint['port'] <= 65535:
                    raise ValueError()
                ipv4(endpoint['ipv4'])
                if not isinstance(item['resolver_ipv4'], list) or len(item['resolver_ipv4']) > 8:
                    raise ValueError()
                for address in item['resolver_ipv4']:
                    ipv4(address)
                for flag in ('ipv6_resolver_present','guard_present','state_present','tun_present'):
                    if type(item[flag]) is not bool:
                        raise ValueError()
                physical = item['physical_route']
                if set(physical) != {'interface','source','gateway'}:
                    raise ValueError()
                interface(physical['interface']); ipv4(physical['source'])
                if physical['gateway'] is not None:
                    ipv4(physical['gateway'])
                if not isinstance(item['routes'], list) or len(item['routes']) > 64:
                    raise ValueError()
                for row in item['routes']:
                    if set(row) != {'destination','interface','gateway','source'}:
                        raise ValueError()
                    if row['destination'] != 'default' and str(ipaddress.IPv4Network(row['destination'])) != row['destination']:
                        raise ValueError()
                    interface(row['interface'])
                    for field in ('gateway','source'):
                        if row[field] is not None:
                            ipv4(row[field])
        if not isinstance(value['checks'], list) or len(value['checks']) > 2:
            raise ValueError()
        for row in value['checks']:
            if set(row) != {'utc','elapsed_ms','tunnel_route_verified','private_dns','private_dns_tcp','system_dns','https','http_status'}:
                raise ValueError()
            if (not isinstance(row['utc'], str) or re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00', row['utc']) is None
                    or type(row['elapsed_ms']) is not int or not 0 <= row['elapsed_ms'] <= 120000
                    or type(row['tunnel_route_verified']) is not bool
                    or row['private_dns'] not in DNS_STATUS or row['private_dns_tcp'] not in DNS_STATUS
                    or row['system_dns'] not in ('ok','failed','timeout','not_run')
                    or row['https'] not in ('ok','failed','timeout','not_run')
                    or row['http_status'] is not None and (type(row['http_status']) is not int or not 0 <= row['http_status'] <= 599)):
                raise ValueError()
        recovery = value['recovery']
        if set(recovery) != {'child_stopped','ownership_proven','restore_attempted','restored','guard_absent','state_absent','routes_match','dns_match','confirmed','restore_withheld'}:
            raise ValueError()
        for key in ('child_stopped','ownership_proven','restore_attempted','restored','confirmed'):
            if type(recovery[key]) is not bool:
                raise ValueError()
        for key in ('guard_absent','state_absent','routes_match','dns_match'):
            if recovery[key] is not None and type(recovery[key]) is not bool:
                raise ValueError()
        if recovery['restore_withheld'] not in WITHHELD:
            raise ValueError()
        if value['child_exit_status'] is not None and (type(value['child_exit_status']) is not int or not -128 <= value['child_exit_status'] <= 255):
            raise ValueError()
        if value['session'] is not None:
            channel = channel if channel is not None else _REPORT_CHANNEL
            if channel is None:
                raise ValueError()
            channel.validate_snapshot(value['session'])
        if len(json.dumps(value).encode()) > 180000:
            raise ValueError()
        return value
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError):
        raise DiagnosticError('internal_error') from None


def main():
    global _INTERRUPTED
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path)
    parser.add_argument('--restore-after-test', action='store_true', required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    report = new_report()
    try:
        if os.geteuid() != ROOT_UID or not sys.flags.isolated:
            raise DiagnosticError('owner_invalid')
        owner = int(os.environ.get('SUDO_UID', '0'))
        def interrupted(number, frame):
            global _INTERRUPTED
            _INTERRUPTED = True
        for number in (signal.SIGINT, signal.SIGTERM):
            signal.signal(number, interrupted)
        report = run_test(owner, args.credentials, restore_after_test=args.restore_after_test)
        validate_report(report)
    except DiagnosticError as error:
        report = new_report()
        report['outcome'] = error.code
    except Exception:
        report = new_report()
        report['outcome'] = 'internal_error'
    print(json.dumps(report, sort_keys=True))
    return 0 if report['outcome'] == 'success' and report['recovery']['confirmed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
