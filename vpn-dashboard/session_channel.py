"""Local session events and a credential-free Unix control channel.

The protected helper owns the socket's parent. The desktop owner can read
status. Only root can request a stop, after explicit terminal sudo. Neither
party supplies commands, profile paths, PIDs or credentials through this API.
"""
from collections import deque
from datetime import datetime, timezone
import json
import os
import re
from pathlib import Path
import socket
import stat
import struct
import threading

DIRECTORY = Path('/run/vpn-desk')
SOCKET = DIRECTORY/'session.sock'
LIMIT = 131072
MESSAGES = {
    'starting': 'Starting the protected VPN session.',
    'guard_checked': 'The configured firewall baseline passed its startup check.',
    'dns_configured': 'DNS is configured to use the private VPN resolver.',
    'dns_repaired': 'The resolver file changed; the private VPN DNS policy was restored under the guard.',
    'credentials': 'Enter VPN credentials in the authentication terminal.',
    'peer_verified': 'The configured TLS peer verification succeeded.',
    'tls_ready': 'An encrypted TLS control channel was negotiated.',
    'tunnel_ready': 'OpenVPN initialized the tunnel; DNS and leak behavior still require validation.',
    'rekey': 'OpenVPN is renegotiating its encrypted session.',
    'auth_failed': 'VPN authentication was rejected.',
    'tls_failed': 'TLS verification or negotiation failed.',
    'network_failed': 'The VPN transport reported a network error.',
    'reconnecting': 'OpenVPN is reconnecting; tunnel readiness is unconfirmed.',
    'stopping': 'A stop was requested for this app-owned VPN session.',
    'stopped': 'The app-owned OpenVPN process exited. Firewall rules remain in place.',
    'process_failed': 'The VPN process exited with an error.',
    'unavailable': 'No live session information is available.',
}
STATES = {'starting', 'authenticating', 'tunnel_ready', 'reconnecting', 'stopping', 'stopped', 'error'}


class ChannelError(RuntimeError):
    pass


def classify(line):
    """Return only a fixed event code. Never retain, redact or display raw logs."""
    if len(line) > 8192:
        return None
    # Ignore secret-bearing messages as a whole, including misleading status
    # substrings inside a password, token, certificate or pushed option.
    lowered = line.lower()
    if any(word in lowered for word in ('auth-token', 'sess_id_', 'password=', 'password:',
                                        'private key', 'begin certificate', 'push_reply')):
        return None
    message = re.sub(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ', '', line, count=1)
    for marker, event in (
        ('AUTH: Received control message: AUTH_FAILED', 'auth_failed'), ('VERIFY ERROR', 'tls_failed'),
        ('TLS Error:', 'tls_failed'), ('TLS handshake failed', 'tls_failed'),
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


class Events:
    def __init__(self):
        self.lock = threading.Lock()
        self.rows = deque(maxlen=300)
        self.sequence = 0
        self.state = 'starting'

    def add(self, code):
        if code not in MESSAGES:
            raise ChannelError('Unsupported session event.')
        with self.lock:
            self.sequence += 1
            self.rows.append({'sequence': self.sequence,
                              'utc': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'code': code})
            self.state = {'credentials': 'authenticating', 'tunnel_ready': 'tunnel_ready',
                          'auth_failed': 'error', 'tls_failed': 'error', 'network_failed': 'error',
                          'process_failed': 'error', 'reconnecting': 'reconnecting',
                          'stopping': 'stopping', 'stopped': 'stopped'}.get(code, self.state)

    def snapshot(self):
        with self.lock:
            return {'version': 1, 'state': self.state, 'events': list(self.rows)}


def validate_snapshot(value):
    if not isinstance(value, dict) or set(value) != {'version', 'state', 'events'}:
        raise ChannelError('Unsupported session status.')
    if (type(value['version']) is not int or value['version'] != 1
            or not isinstance(value['state'],str) or value['state'] not in STATES
            or not isinstance(value['events'], list) or len(value['events']) > 300):
        raise ChannelError('Unsupported session status.')
    previous = 0
    for row in value['events']:
        if not isinstance(row, dict) or set(row) != {'sequence', 'utc', 'code'}:
            raise ChannelError('Unsupported session event.')
        if (type(row['sequence']) is not int or row['sequence'] <= previous
                or not isinstance(row['code'],str) or row['code'] not in MESSAGES):
            raise ChannelError('Unsupported session event.')
        if not isinstance(row['utc'], str) or len(row['utc']) != 25:
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
    return '\n'.join(row['utc']+' '+MESSAGES[row['code']] for row in snapshot['events'])+'\n'
