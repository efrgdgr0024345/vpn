"""Local session events and a credential-free Unix control channel.

The protected helper owns the socket's parent. The desktop owner can read
status. Only root can request a stop, after explicit terminal sudo. Neither
party supplies commands, profile paths, PIDs or credentials through this API.
"""
from collections import deque
from datetime import datetime, timezone
import json
import ipaddress
import os
import re
from pathlib import Path
import socket
import stat
import struct
import tempfile
import threading
import time

DIRECTORY = Path('/run/vpn-desk')
SOCKET = DIRECTORY/'session.sock'
LIMIT = 131072
HISTORY = Path('/var/lib/vpn-desk-history')
IPV6_FLAG = Path('/sys/module/ipv6/parameters/disable')
MESSAGES = {
    'starting': 'Starting the protected VPN session.',
    'preflight': 'Checking the protected profile, local interfaces and existing network controls.',
    'guard_checked': 'The configured firewall baseline passed its startup check.',
    'dns_configured': 'DNS is configured to use the private VPN resolver.',
    'dns_repaired': 'The resolver file changed; the private VPN DNS policy was restored under the guard.',
    'dns_checking': 'Checking the private VPN resolver through tun0; the firewall remains enabled.',
    'dns_ok': 'The private VPN resolver answered the fixed DNS test through tun0. This is not a full internet or leak test.',
    'dns_timeout': 'The private VPN DNS test timed out. No alternative resolver was used; the kill switch remains enabled.',
    'dns_servfail': 'The private VPN resolver returned SERVFAIL; check its upstream resolution, DNSSEC validation and server clock.',
    'dns_refused': 'The private VPN resolver refused the test query; check resolver access rules and VPN authorization.',
    'dns_truncated': 'The private VPN DNS reply was truncated; this UDP test could not verify resolution.',
    'dns_invalid': 'The private VPN DNS reply failed the fixed-query validation; no reply contents were retained.',
    'dns_no_answer': 'The private VPN DNS reply contained no usable A answer for the fixed test query.',
    'dns_rcode_error': 'The private VPN resolver returned a DNS error for the fixed test query.',
    'dns_route_unavailable': 'The private VPN DNS test was not sent: a tun0 route and matching tunnel source could not be verified.',
    'dns_transport_failed': 'The private VPN DNS socket could not complete the test through tun0.',
    'credentials': 'Enter VPN credentials in the authentication terminal.',
    'transport_start': 'Contacting the VPN server over IPv4; waiting for a reply.',
    'server_replied': 'The VPN server replied; TLS negotiation is in progress.',
    'route_setup': 'OpenVPN is configuring the tunnel interface or IPv4 routes.',
    'peer_verified': 'The configured TLS peer verification succeeded.',
    'tls_ready': 'An encrypted TLS control channel was negotiated.',
    'tunnel_ready': 'OpenVPN initialized the tunnel; DNS and leak behavior still require validation.',
    'rekey': 'OpenVPN is renegotiating its encrypted session.',
    'auth_failed': 'VPN authentication was rejected.',
    'tls_failed': 'TLS verification or negotiation failed.',
    'network_failed': 'The VPN transport reported a network error.',
    'configuration_failed': 'OpenVPN rejected a configuration option; check the approved profile and client version.',
    'route_failed': 'VPN interface or route configuration failed.',
    'dco_failed': 'Kernel VPN offload setup failed; tunnel readiness is unconfirmed.',
    'server_timeout': 'No VPN server reply was recognized within 60 seconds. Check server availability, UDP reachability and the matching TLS profile.',
    'handshake_timeout': 'The server replied but the VPN did not initialize within 60 seconds. Check TLS, authentication and tunnel setup.',
    'startup_timeout': 'VPN startup did not finish within three minutes, including credential entry.',
    'preflight_failed': 'Startup stopped during the protected network or installation checks. Read the terminal refusal message.',
    'reconnecting': 'OpenVPN is reconnecting; tunnel readiness is unconfirmed.',
    'stopping': 'A stop was requested for this app-owned VPN session.',
    'stopped': 'The app-owned OpenVPN process exited. Firewall rules remain in place.',
    'process_failed': 'The VPN process exited with an error.',
    'attempt_failed': 'The VPN attempt failed. The kill switch remains enabled; review the preceding stages before retrying.',
    'unavailable': 'No live session information is available.',
}
STATES = {'starting', 'authenticating', 'connecting', 'tls_negotiating', 'configuring_tunnel',
          'tunnel_ready', 'reconnecting', 'stopping', 'stopped', 'error'}
FAILURES = {'auth_failed', 'tls_failed', 'network_failed', 'configuration_failed',
            'route_failed', 'dco_failed', 'server_timeout', 'handshake_timeout',
            'startup_timeout', 'preflight_failed', 'process_failed', 'attempt_failed'}
DETAIL_LABELS = {
    'server_ipv4': 'VPN server IP', 'server_port': 'VPN server port', 'protocol': 'Transport',
    'wifi_interface': 'Physical interface', 'local_ipv4': 'Local IPv4', 'local_port': 'Local socket port',
    'gateway_ipv4': 'Physical gateway', 'expected_tls_name': 'Expected TLS certificate name',
    'dhcp_server_ipv4': 'Configured Wi-Fi DHCP server',
    'openvpn_version': 'OpenVPN version', 'openssl_version': 'OpenSSL version',
    'tls_version': 'Negotiated TLS', 'control_cipher': 'Control-channel cipher', 'data_cipher': 'Data-channel cipher',
    'tunnel_ipv4': 'Tunnel IPv4', 'tunnel_interface': 'Tunnel interface',
    'tunnel_mtu': 'Tunnel MTU', 'mssfix': 'Configured mssfix',
    'dns_ipv4': 'Configured VPN DNS', 'dns_file_verified': 'DNS file matches managed configuration',
    'dns_health': 'Private VPN DNS test status', 'dns_latency_ms': 'Private VPN DNS test elapsed milliseconds',
    'route_interface': 'IPv4 route lookup interface', 'split_routes_verified': 'Both IPv4 full-tunnel /1 routes observed',
    'ipv6_kernel_disabled': 'IPv6 disabled at kernel boot',
    'preflight_reason': 'Startup refusal reason',
}
REFUSALS = {
    'already_running': 'OpenVPN is already running.',
    'wifi_down': 'Configured Wi-Fi interface is not up.',
    'default_route': 'Exactly one IPv4 default via the configured Wi-Fi interface is required.',
    'unmanaged_tunnel': 'An unmanaged tunnel exists.',
    'unmanaged_route': 'Unmanaged tunnel route exists.',
    'foreign_firewall': 'A pre-existing firewall requires a reviewed migration; no rules were changed.',
    'busy': 'Another VPN action or session is active; stop it before connecting.',
    'profile_policy': 'Profile must pin the local policy endpoint, tun0 and expected TLS server identity.',
    'local_check': 'Protected local files, network ownership or action-lock checks could not complete.',
}
CONTROL_CIPHERS = {'TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256',
                   'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES128-GCM-SHA256',
                   'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256'}
DATA_CIPHERS = {'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'}
DNS_HEALTH = {'unchecked', 'checking', 'ok', 'timeout', 'servfail', 'refused',
              'truncated', 'invalid', 'no_answer', 'rcode_error', 'route_unavailable', 'transport_failed'}
DNS_RECOVERY = ('DNS is not verified. The tunnel may remain open and the kill switch stays enabled. '
                'To return to normal networking, press Ctrl+C in the VPN terminal, wait for it to stop, '
                'then use Restore normal networking.')


class ChannelError(RuntimeError):
    pass


def public_message(line):
    if len(line) > 8192:
        return None
    # Ignore secret-bearing messages as a whole, including misleading status
    # substrings inside a password, token, certificate or pushed option.
    lowered = line.lower()
    if any(word in lowered for word in ('auth-token', 'sess_id_', 'password=', 'password:',
                                        'private key', 'begin certificate', 'push_reply')):
        return None
    return re.sub(r'^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)? ', '', line, count=1)


def classify(line):
    """Return only a fixed event code. Never retain or display raw logs."""
    message = public_message(line)
    if message is None:
        return None
    for marker, event in (
        ('AUTH: Received control message: AUTH_FAILED', 'auth_failed'), ('VERIFY ERROR', 'tls_failed'),
        ('TLS Error:', 'tls_failed'), ('TLS handshake failed', 'tls_failed'),
        ('UDPv4 link remote:', 'transport_start'),
        ('TCPv4_CLIENT link remote:', 'transport_start'),
        ('Attempting to establish TCP connection with', 'transport_start'),
        ('TLS: Initial packet from', 'server_replied'),
        ('TUN/TAP device ', 'route_setup'), ('net_addr_v4_add:', 'route_setup'),
        ('Options error:', 'configuration_failed'),
        ('ERROR: Linux route add command failed', 'route_failed'),
        ('ERROR: Linux IPv4', 'route_failed'), ('dco_new_peer: netlink error', 'dco_failed'),
        ('Initialization Sequence Completed', 'tunnel_ready'),
        ('Control Channel: TLS', 'tls_ready'), ('VERIFY OK: depth=0', 'peer_verified'),
        ('TLS: soft reset', 'rekey'), ('SIGUSR1[', 'reconnecting'),
    ):
        if message.startswith(marker):
            return event
    if message.startswith(('read UDP', 'write UDP', 'read TCP', 'write TCP')):
        if any(word in message for word in ('Network is unreachable', 'Connection refused')):
            return 'network_failed'
    return None


def parse_details(line):
    message = public_message(line)
    if message is None:
        return {}
    endpoint = re.match(r'^(UDPv4|TCPv4_CLIENT) link remote: \[AF_INET\]([0-9.]+):([0-9]{1,5})$', message)
    if endpoint:
        result = {'server_ipv4': endpoint[2], 'server_port': int(endpoint[3]),
                  'protocol': 'udp4' if endpoint[1] == 'UDPv4' else 'tcp4-client'}
        try:
            return validate_details(result)
        except ChannelError:
            return {}
    device = re.match(r'^(?:TUN/TAP|DCO) device ([A-Za-z0-9_][A-Za-z0-9_.-]{0,14}) opened', message)
    if device:
        return {'tunnel_interface': device[1]}
    version = re.match(r'^OpenVPN ([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,4})?)\b', message)
    if version:
        return {'openvpn_version': version[1]}
    if message.startswith('library versions:'):
        version = re.search(r'\bOpenSSL ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4})\b', message)
        return {'openssl_version': version[1]} if version else {}
    tls = re.match(r'^Control Channel: (TLSv1\.[23]), cipher TLSv1\.[23] ([A-Z0-9_-]+)(?:,|$)', message)
    if tls and tls[2] in CONTROL_CIPHERS:
        return {'tls_version': tls[1], 'control_cipher': tls[2]}
    cipher = re.match(r"^Data Channel: cipher '([A-Z0-9-]+)'(?:,|$)", message)
    return {'data_cipher': cipher[1]} if cipher and cipher[1] in DATA_CIPHERS else {}


def validate_details(details):
    if not isinstance(details, dict) or set(details)-set(DETAIL_LABELS):
        raise ChannelError('Unsupported diagnostic fields.')
    for key, value in details.items():
        valid = False
        if key.endswith('_ipv4'):
            try:
                valid = isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value
            except ValueError:
                valid = False
        elif key in ('tunnel_mtu', 'mssfix'):
            valid = type(value) is int and 68 <= value <= 65535
        elif key.endswith('_port'):
            valid = type(value) is int and 1 <= value <= 65535
        elif key.endswith('_interface'):
            valid = isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}', value) is not None
        elif key.endswith('_verified') or key == 'ipv6_kernel_disabled':
            valid = type(value) is bool
        elif key in ('openvpn_version', 'openssl_version'):
            valid = isinstance(value, str) and re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,4})?', value) is not None
        elif key == 'expected_tls_name':
            valid = isinstance(value, str) and value == value.strip() and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_. -]{0,252}', value) is not None
        elif key == 'preflight_reason':
            valid = isinstance(value, str) and value in REFUSALS
        elif key == 'dns_health':
            valid = isinstance(value, str) and value in DNS_HEALTH
        elif key == 'dns_latency_ms':
            valid = type(value) is int and 0 <= value <= 10000
        else:
            choices = {'protocol': {'udp4', 'tcp4-client'}, 'tls_version': {'TLSv1.2', 'TLSv1.3'},
                       'control_cipher': CONTROL_CIPHERS, 'data_cipher': DATA_CIPHERS}
            valid = isinstance(value, str) and value in choices.get(key, set())
        if not valid:
            raise ChannelError('Invalid typed diagnostic value.')
    return details


class Events:
    def __init__(self):
        self.lock = threading.Lock()
        self.rows = deque(maxlen=300)
        self.sequence = 0
        self.state = 'starting'
        self.failed = False
        self.started = time.monotonic()
        self.details = {}

    def add(self, code):
        if code not in MESSAGES:
            raise ChannelError('Unsupported session event.')
        with self.lock:
            self.sequence += 1
            row = {'sequence': self.sequence,
                   'utc': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'code': code,
                   'elapsed_ms': int(max(0, time.monotonic()-self.started)*1000)}
            self.rows.append(row)
            if code in FAILURES:
                self.failed = True
            self.state = {'credentials': 'authenticating', 'tunnel_ready': 'tunnel_ready',
                          'transport_start': 'connecting', 'server_replied': 'tls_negotiating',
                          'route_setup': 'configuring_tunnel',
                          'auth_failed': 'error', 'tls_failed': 'error', 'network_failed': 'error',
                          'process_failed': 'error', 'reconnecting': 'reconnecting',
                          'stopping': 'stopping', 'stopped': 'stopped'}.get(code, self.state)
            if code in FAILURES or (code == 'stopped' and self.failed):
                self.state = 'error'
            if code == 'tunnel_ready':
                self.failed = False
            return dict(row)

    def set_details(self, updates):
        validate_details(updates)
        with self.lock:
            changed = {key: value for key, value in updates.items() if self.details.get(key) != value}
            self.details.update(changed)
            return changed

    def snapshot(self):
        with self.lock:
            return {'version': 2, 'state': self.state, 'events': list(self.rows), 'details': dict(self.details)}


def validate_snapshot(value):
    if not isinstance(value, dict) or set(value) != {'version', 'state', 'events', 'details'}:
        raise ChannelError('Unsupported session status.')
    if (type(value['version']) is not int or value['version'] != 2
            or not isinstance(value['state'],str) or value['state'] not in STATES
            or not isinstance(value['events'], list) or len(value['events']) > 300):
        raise ChannelError('Unsupported session status.')
    validate_details(value['details'])
    previous = 0
    for row in value['events']:
        if not isinstance(row, dict) or set(row) != {'sequence', 'utc', 'code', 'elapsed_ms'}:
            raise ChannelError('Unsupported session event.')
        if (type(row['sequence']) is not int or row['sequence'] <= previous
                or not isinstance(row['code'],str) or row['code'] not in MESSAGES
                or type(row['elapsed_ms']) is not int or not 0 <= row['elapsed_ms'] <= 10**12):
            raise ChannelError('Unsupported session event.')
        if (not isinstance(row['utc'], str)
                or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\+00:00', row['utc']) is None):
            raise ChannelError('Unsupported session timestamp.')
        try:
            stamp = datetime.fromisoformat(row['utc'])
        except ValueError:
            raise ChannelError('Unsupported session timestamp.') from None
        if stamp.utcoffset() is None or stamp.utcoffset().total_seconds() != 0:
            raise ChannelError('Unsupported session timestamp.')
        previous = row['sequence']
    return value


def peer_uid(channel):
    return struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def protected_parent(path):
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ChannelError('Unprotected local session directory.')


def kernel_ipv6_disabled():
    try:
        protected_parent(IPV6_FLAG.parent)
        fd = os.open(IPV6_FLAG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False
            return stream.read(16).strip() in (b'1', b'Y', b'y')
    except (OSError, ChannelError):
        return False


class Server:
    def __init__(self, owner, events, stop, path=SOCKET):
        if os.geteuid() != 0 or type(owner) is not int or owner <= 0:
            raise ChannelError('A local desktop owner and protected root helper are required.')
        self.owner, self.events, self.stop, self.path = owner, events, stop, Path(path)
        self.done = threading.Event()

    def __enter__(self):
        self.path.parent.mkdir(mode=0o755, exist_ok=True)
        protected_parent(self.path.parent)
        # sudo uses umask 077. Make only this public, root-owned directory
        # traversable; socket mode and OS peer credentials protect its data.
        self.path.parent.chmod(0o755)
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            pass
        else:
            # The outer session lock serializes server startup. Never unlink a
            # different file type or something outside the protected parent.
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.owner:
                raise ChannelError('Unexpected local session socket.')
            self.path.unlink()
        self.channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.channel.bind(str(self.path))
        os.chmod(self.path, 0o600)
        os.chown(self.path, self.owner, -1)
        self.channel.listen(4)
        self.channel.settimeout(.2)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self

    def serve(self):
        while not self.done.is_set():
            try:
                connection, _ = self.channel.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                try:
                    connection.settimeout(.3)
                    uid = peer_uid(connection)
                    if uid not in (0, self.owner):
                        continue
                    request = b''
                    while b'\n' not in request and len(request) <= 128:
                        chunk = connection.recv(129-len(request))
                        if not chunk:
                            break
                        request += chunk
                    if request == b'status\n':
                        result = self.events.snapshot()
                    elif request == b'stop\n' and uid == 0:
                        self.stop()
                        result = {'stop_requested': True}
                    else:
                        continue
                    connection.sendall(json.dumps(result, separators=(',', ':')).encode()+b'\n')
                except (OSError, ValueError, ChannelError):
                    continue

    def __exit__(self, *args):
        self.done.set()
        self.channel.close()
        self.thread.join(timeout=1)
        self.path.unlink(missing_ok=True)


def request(action='status', path=SOCKET):
    if action not in ('status', 'stop') or (action == 'stop' and os.geteuid() != 0):
        raise ChannelError('Stopping requires the protected terminal-authenticated helper.')
    path = Path(path)
    protected_parent(path.parent)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode):
        raise ChannelError('The local session endpoint is not a socket.')
    if os.geteuid() != 0 and info.st_uid != os.getuid():
        raise ChannelError('This session belongs to another desktop owner.')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(1)
        channel.connect(str(path))
        if peer_uid(channel) != 0:
            raise ChannelError('The session endpoint is not the protected root helper.')
        channel.sendall(action.encode('ascii')+b'\n')
        data = b''
        while b'\n' not in data and len(data) <= LIMIT:
            chunk = channel.recv(min(8192, LIMIT+1-len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) > LIMIT or not data.endswith(b'\n') or data.count(b'\n') != 1:
            raise ChannelError('Unsupported local session response.')
        value = json.loads(data)
        if action == 'status':
            return validate_snapshot(value)
        if value != {'stop_requested': True}:
            raise ChannelError('Session stop was not acknowledged.')
        return value


def format_events(snapshot):
    validate_snapshot(snapshot)
    text = format_details(snapshot['details'], include_unknown=True)+'\n\n'+'\n'.join(format_event(row) for row in snapshot['events'])+'\n'
    if snapshot['details'].get('dns_health', 'unchecked') not in ('unchecked', 'checking', 'ok'):
        text += '\n'+DNS_RECOVERY+'\n'
    if snapshot['state'] in ('error', 'stopped'):
        text += ('\nAfter stopping the VPN, use Restore normal networking or run:\n'
                 'sudo -- /usr/bin/python3 -I -B /usr/local/libexec/vpn-desk/privileged.py network-restore\n')
    return text


def format_event(row):
    return row['utc']+' (+'+format(row['elapsed_ms']/1000, '.3f')+'s) '+MESSAGES[row['code']]


def format_details(details, *, include_unknown=False):
    validate_details(details)
    return '\n'.join(label+': '+(REFUSALS[details[key]] if key == 'preflight_reason' and key in details else
                               str(details[key]) if key in details else 'not observed')
                     for key, label in DETAIL_LABELS.items() if key in details or include_unknown)


def save_last(owner, snapshot, exit_status):
    """Private, bounded local history; never used for privileged decisions."""
    if os.geteuid() != 0 or type(owner) is not int or not 1 <= owner < 2**32-1:
        raise ChannelError('History requires the protected helper and desktop owner.')
    validate_snapshot(snapshot)
    if exit_status is not None and (type(exit_status) is not int or not -128 <= exit_status <= 255):
        raise ChannelError('Unsupported process exit status.')
    HISTORY.mkdir(mode=0o711, exist_ok=True)
    protected_parent(HISTORY)
    HISTORY.chmod(0o711)  # sudo's umask must not block the owner's traversal.
    record = {'version': 1, 'owner_uid': owner, 'exit_status': exit_status, 'snapshot': snapshot}
    value = (json.dumps(record, separators=(',', ':'))+'\n').encode()
    if len(value) > LIMIT:
        raise ChannelError('History exceeds the local event limit.')
    fd, temporary = tempfile.mkstemp(prefix='.session-', dir=HISTORY)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
            # Root keeps ownership. A named-user read ACL permits only the
            # desktop owner to inspect history without being able to edit it.
            # Unsupported ACL filesystems fail rather than widening access.
            os.setxattr(stream.fileno(), 'system.posix_acl_access', history_acl(owner))
            os.fsync(stream.fileno())
        os.replace(temporary, HISTORY/(str(owner)+'.json'))
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_last():
    """Read-only, root-written history is distinct from a live helper reply."""
    owner = os.getuid()
    protected_parent(HISTORY)
    fd = os.open(HISTORY/(str(owner)+'.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o640
                or os.getxattr(stream.fileno(), 'system.posix_acl_access') != history_acl(owner)):
            raise ChannelError('Unsafe local session history.')
        value = stream.read(LIMIT+1)
    if len(value) > LIMIT:
        raise ChannelError('Local history exceeds the event limit.')
    record = json.loads(value)
    if (not isinstance(record, dict) or set(record) != {'version', 'owner_uid', 'exit_status', 'snapshot'}
            or type(record['version']) is not int or record['version'] != 1
            or type(record['owner_uid']) is not int or record['owner_uid'] != owner
            or (record['exit_status'] is not None
                and (type(record['exit_status']) is not int or not -128 <= record['exit_status'] <= 255))):
        raise ChannelError('Unsupported local session history.')
    validate_snapshot(record['snapshot'])
    return record


def history_acl(owner):
    # Linux POSIX ACL xattr v2: owner rw, named desktop user r, group/other
    # none, mask r. UID 0 retains administrative access; no extra group reads.
    if type(owner) is not int or not 1 <= owner < 2**32-1:
        raise ChannelError('Unsupported history owner.')
    undefined = 2**32-1
    entries = ((1, 6, undefined), (2, 4, owner), (4, 0, undefined),
               (16, 4, undefined), (32, 0, undefined))
    return struct.pack('<I', 2)+b''.join(struct.pack('<HHI', *entry) for entry in entries)
