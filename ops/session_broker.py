"""Authorize one enrolled OpenVPN session and maintain a short kernel lease.

The only identity source is the root-protected OpenVPN management socket.
OpenVPN verifies certificates and its distribution PAM plugin verifies initial
passwords. Never expose this protocol as an HTTP or client-reachable service.
"""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import stat
import subprocess
import time

REGISTRY = Path('/etc/openvpn/lab/devices.json')
SOCKET = '/run/openvpn-server/vpn-lab.management'
RUNTIME = Path('/run/vpn-lab-control')
LEASE_SECONDS = 20
SESSION_SECONDS = 86400
DEVICE_NAMES = ('kali', 'iphone', 'android')
ENV_KEYS = {'common_name', 'username', 'tls_digest_sha256_0',
            'ifconfig_pool_remote_ip', 'session_state'}


class BrokerError(RuntimeError):
    pass


def protected_read(path):
    path = Path(path)
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise BrokerError('Unprotected registry path.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise BrokerError('Unprotected registry file.')
        value = stream.read(32769)
        if len(value) > 32768:
            raise BrokerError('Oversized device registry.')
        return value


def registry(value):
    devices = json.loads(value)
    if not isinstance(devices, dict) or set(devices) - set(DEVICE_NAMES) or not devices:
        raise BrokerError('Invalid device registry.')
    fingerprints, addresses, names = set(), set(), set()
    for name, device in devices.items():
        if not isinstance(device, dict) or set(device) != {'cn', 'sha256', 'address', 'enabled'}:
            raise BrokerError('Invalid device record.')
        if not re.fullmatch(r'[A-Za-z0-9-]{1,64}', device['cn']):
            raise BrokerError('Invalid certificate name.')
        if not re.fullmatch(r'[0-9a-f]{64}', device['sha256']):
            raise BrokerError('Invalid certificate pin.')
        address = ipaddress.IPv4Address(device['address'])
        if address not in ipaddress.ip_network('172.27.240.0/24') or int(address) & 255 not in range(10, 250):
            raise BrokerError('Invalid device address.')
        if type(device['enabled']) is not bool:
            raise BrokerError('Invalid device status.')
        if device['sha256'] in fingerprints or device['address'] in addresses or device['cn'] in names:
            raise BrokerError('Duplicate device identity.')
        fingerprints.add(device['sha256'])
        addresses.add(device['address'])
        names.add(device['cn'])
    return devices


def identifier(value):
    if not re.fullmatch(r'[0-9]{1,10}', value) or int(value) > 2**32 - 1:
        raise BrokerError('Invalid management connection identity.')
    return int(value)


class Parser:
    """Bounded atomic CLIENT events; discard passwords/tokens, never log lines."""
    def __init__(self):
        self.event = None
        self.size = 0

    def feed(self, line):
        if len(line) > 16384:
            raise BrokerError('Oversized management line.')
        if line.startswith('>BYTECOUNT_CLI:'):
            fields = line.split(':', 1)[1].split(',')
            if len(fields) != 3 or not all(re.fullmatch(r'[0-9]{1,20}', v) for v in fields):
                raise BrokerError('Invalid bytecount notification.')
            return 'LIVE', identifier(fields[0]), None, {}
        if not line.startswith('>CLIENT:'):
            return None
        body = line[8:]
        if body.startswith('ADDRESS,'):
            return None
        if body.startswith('ENV,'):
            if self.event is None:
                raise BrokerError('Unexpected management environment.')
            self.size += len(line)
            if self.size > 65536:
                raise BrokerError('Oversized management event.')
            if body == 'ENV,END':
                result, self.event = self.event, None
                return result
            key, separator, value = body[4:].partition('=')
            if separator and key in ENV_KEYS:
                if key in self.event[3]:
                    raise BrokerError('Duplicate management identity field.')
                self.event[3][key] = value
            return None
        fields = body.split(',')
        kind = fields[0]
        count = 3 if kind in ('CONNECT', 'REAUTH') else 2
        if kind not in ('CONNECT', 'REAUTH', 'ESTABLISHED', 'DISCONNECT') or len(fields) != count or self.event:
            raise BrokerError('Unsupported management notification.')
        self.event = (kind, identifier(fields[1]), identifier(fields[2]) if count == 3 else None, {})
        self.size = len(line)
        return None


class Policy:
    """Single-threaded state machine, keyed by daemon-assigned CID, never IP alone."""
    def __init__(self, devices, send, grant, clear, now=time.monotonic):
        self.devices, self.send, self.grant, self.clear, self.now = devices, send, grant, clear, now
        self.owner = None
        self.pending = None
        self.stopping = False

    def deny(self, cid, kid):
        self.send(f'client-deny {cid} {kid} "Access denied" "Access denied"\n')

    def kill(self, cid, token_reconnect=False):
        # A bare RESTART retains the session token on some clients. Tell a new
        # token-only connection to discard it and authenticate again; a revoked
        # or expired owner receives HALT instead of retrying forever.
        message = 'AUTH_FAILED,SESSION' if token_reconnect else 'HALT,VPN authorization ended'
        self.send(f'client-kill {cid} "{message}"\n')

    def revoke(self):
        self.clear()  # Never release ownership until packet access is removed.
        if self.owner:
            self.kill(self.owner['cid'])
            self.stopping = True

    def event(self, kind, cid, kid, environment):
        if kind in ('CONNECT', 'ESTABLISHED', 'LIVE'):
            self.tick(self.devices)
        current = self.now()
        if kind == 'CONNECT':
            # New connections must prove the known password through PAM. A token
            # from a previous connection is not an admission credential here.
            digest = environment.get('tls_digest_sha256_0', '').replace(':', '').lower()
            matches = [(name, d) for name, d in self.devices.items()
                       if d['enabled'] and d['sha256'] == digest
                       and d['cn'] == environment.get('common_name')]
            if (self.owner or self.pending or self.stopping or len(matches) != 1
                    or environment.get('username') != 'vpn-lab-client'
                    or environment.get('session_state') != 'Initial'):
                self.deny(cid, kid)
                return
            name, device = matches[0]
            self.pending = {'cid': cid, 'device': name, 'address': device['address'],
                            'sha256': device['sha256'], 'cn': device['cn'],
                            'since': current, 'last': current, 'cancelled': False}
            self.send(f'client-auth {cid} {kid}\nifconfig-push {device["address"]} 255.255.255.0\nEND\n')
        elif kind == 'ESTABLISHED':
            if (not self.pending or self.pending['cid'] != cid or self.pending['cancelled']
                    or self.owner or self.stopping
                    or environment.get('ifconfig_pool_remote_ip') != self.pending['address']):
                self.kill(cid, token_reconnect=True)
                return
            # PAM and OpenVPN TLS must both have succeeded before ESTABLISHED.
            # No forwarding is granted while admission is only pending.
            self.owner, self.pending = self.pending, None
            self.owner['last'] = current
            self.grant(self.owner['address'])
        elif kind == 'LIVE':
            if self.owner and self.owner['cid'] == cid and not self.stopping:
                self.owner['last'] = current
                self.grant(self.owner['address'])
        elif kind == 'REAUTH':
            # Valid OpenVPN auth tokens are handled inside OpenVPN. Any external
            # reauthentication request is denied: do not fall back to the known
            # password or trust a client-provided session-state string.
            self.deny(cid, kid)
        elif kind == 'DISCONNECT':
            if self.owner and self.owner['cid'] == cid:
                self.clear()
                self.owner = None
                self.stopping = False
            if self.pending and self.pending['cid'] == cid:
                self.pending = None

    def tick(self, devices):
        self.devices = devices
        current = self.now()
        if self.pending and (current - self.pending['since'] > 15
                             or not devices.get(self.pending['device'], {}).get('enabled')
                             or any(devices[self.pending['device']][key] != self.pending[key]
                                    for key in ('sha256', 'cn', 'address'))):
            if not self.pending['cancelled']:
                self.kill(self.pending['cid'])
                self.pending['cancelled'] = True
            # Retain the reservation until the daemon confirms DISCONNECT.
        if self.owner and not self.stopping:
            if (not devices.get(self.owner['device'], {}).get('enabled')
                    or any(devices[self.owner['device']][key] != self.owner[key]
                           for key in ('sha256', 'cn', 'address'))
                    or current - self.owner['last'] > 12
                    or current - self.owner['since'] >= SESSION_SECONDS):
                self.revoke()


def nft(address=None):
    script = 'flush set inet vpn_lab authorized\n'
    if address is not None:
        parsed = ipaddress.IPv4Address(address)
        if parsed not in ipaddress.ip_network('172.27.240.0/24'):
            raise BrokerError('Invalid forwarding grant.')
        script += f'add element inet vpn_lab authorized {{ {parsed} timeout {LEASE_SECONDS}s }}\n'
    result = subprocess.run(['/usr/sbin/nft', '-f', '-'], input=script, text=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=3, env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise BrokerError('Forwarding lease update failed.')


def main():
    if os.geteuid() != 0:
        raise BrokerError('Broker requires local root.')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def terminate(signum, frame):
        raise BrokerError('Broker stop requested.')
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    RUNTIME.mkdir(mode=0o700, exist_ok=True)
    info = RUNTIME.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise BrokerError('Unprotected broker runtime.')
    lock = os.open(RUNTIME/'broker.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(lock)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
        raise BrokerError('Unprotected broker lock.')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    nft()
    devices = registry(protected_read(REGISTRY))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(3)
        for attempt in range(30):
            try:
                path = Path(SOCKET)
                for parent in reversed(path.parents):
                    info = parent.lstat()
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                        raise BrokerError('Unprotected management socket path.')
                info = path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                    raise BrokerError('Unprotected management socket.')
                # OpenVPN creates permissive socket bits, but the service's
                # root-only runtime directory and management-client-user root
                # check protect it. The broker's read-only filesystem sandbox
                # deliberately cannot chmod files in the daemon's runtime.
                channel.connect(SOCKET)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if attempt == 29:
                    raise BrokerError('Management channel unavailable.') from None
                time.sleep(.2)
        def send(value):
            channel.sendall(value.encode('ascii'))
        policy = Policy(devices, send, nft, nft)
        # OpenVPN starts held and management-signal restarts it on broker loss.
        # Never restore an old owner after reconnect; unsolicited ESTABLISHED
        # events are killed and the kernel grant begins empty.
        send('hold release\nbytecount 3\n')
        parser, buffer, last_tick = Parser(), b'', 0.0
        try:
            while True:
                if time.monotonic() - last_tick >= 1:
                    policy.tick(registry(protected_read(REGISTRY)))
                    last_tick = time.monotonic()
                if not select.select([channel], [], [], .25)[0]:
                    continue
                chunk = channel.recv(16384)
                if not chunk:
                    raise BrokerError('Management channel closed.')
                buffer += chunk
                if len(buffer) > 65536:
                    raise BrokerError('Management input overflow.')
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    if line.startswith(b'ERROR:'):
                        raise BrokerError('Management command rejected.')
                    event = parser.feed(line.rstrip(b'\r').decode('utf-8', errors='strict'))
                    if event:
                        policy.event(*event)
        finally:
            nft()


if __name__ == '__main__':
    try:
        main()
    except (BrokerError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        # No raw management lines, env values, passwords or tokens in journals.
        print('VPN authorization broker stopped; forwarding lease is denied or expiring.', flush=True)
        raise SystemExit(1)
