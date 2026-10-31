"""Read-only privileged observations for the private, unprivileged VPN panel.

The collector never accesses OpenVPN management IPC, credentials or journals.
An unsuccessful collection leaves the old snapshot for the web stale-state check.
"""
import argparse
from collections import deque
from datetime import datetime, timezone
import grp
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys
import tempfile
import time

CODE = Path('/opt/vpn-lab-admin')
RUNTIME = Path('/run/vpn-lab-admin')
REGISTRY = Path('/etc/openvpn/lab/devices.json')
GROUP = 'vpn-lab-admin'
ROOT_UID = 0


def trusted_directory(path):
    path = Path(path)
    for entry in (*reversed(path.parents), path):
        info = entry.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise ValueError('Unprotected collector directory.')


def protected_read(path, *, private=False, limit=32768):
    path = Path(path)
    trusted_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1
                or info.st_mode & (0o077 if private else 0o022)):
            raise ValueError('Unprotected collector input.')
        value = stream.read(limit+1)
    if len(value) > limit:
        raise ValueError('Oversized collector input.')
    return value


def load_modules():
    if not sys.flags.isolated or Path(__file__) != CODE/'collector.py':
        raise ValueError('Use the protected installed collector with system Python -I -B.')
    for name in ('collector.py', 'schema.py', 'server_diagnostics.py'):
        protected_read(CODE/name, limit=2_000_000)
    sys.path.insert(0, str(CODE))
    import schema
    import server_diagnostics
    return schema, server_diagnostics


def registry_devices(raw, names):
    registry = json.loads(raw)
    if not isinstance(registry, dict) or set(registry) != set(names):
        raise ValueError('Unsupported private device registry.')
    devices, pins, addresses, common_names = [], set(), set(), set()
    for name in names:
        value = registry[name]
        if not isinstance(value, dict) or set(value) != {'cn', 'sha256', 'address', 'enabled'}:
            raise ValueError('Unsupported private device registry.')
        cn, pin, ip = value['cn'], value['sha256'], value['address']
        if (not isinstance(cn, str) or re.fullmatch(r'[A-Za-z0-9-]{1,64}', cn) is None
                or not isinstance(pin, str) or re.fullmatch(r'[0-9a-f]{64}', pin) is None
                or not isinstance(ip, str) or type(value['enabled']) is not bool):
            raise ValueError('Unsupported private device registry.')
        parsed = ipaddress.IPv4Address(ip)
        if (str(parsed) != ip or parsed not in ipaddress.IPv4Network('172.27.240.0/24')
                or not 10 <= (int(parsed) & 255) <= 249
                or pin in pins or ip in addresses or cn in common_names):
            raise ValueError('Unsupported private device registry.')
        pins.add(pin)
        addresses.add(ip)
        common_names.add(cn)
        # Common names and all other registry fields stay out of public output.
        devices.append({'name': name, 'enabled': value['enabled'], 'address': ip,
                        'certificate_sha256': pin})
    return devices


def kernel_text(path):
    try:
        value = Path(path).read_bytes()
        if len(value) > 65536:
            return None
        return value.decode('ascii').strip()
    except (OSError, UnicodeError):
        return None


def ipv6_state():
    value = kernel_text('/sys/module/ipv6/parameters/disable')
    disabled = True if value in ('1', 'Y', 'y') else False if value in ('0', 'N', 'n') else None
    cmdline = kernel_text('/proc/cmdline')
    arguments = None if cmdline is None else [item for item in cmdline.split() if item.startswith('ipv6.disable=')]
    boot = None if arguments is None or len(arguments) > 1 else arguments == ['ipv6.disable=1']
    return {'kernel_disabled': disabled, 'boot_argument_active': boot}


class Collector:
    def __init__(self, schema, diagnostics, *, now=time.monotonic, stamp=None):
        self.schema = schema
        self.diagnostics = diagnostics
        self.now = now
        self.stamp = stamp or (lambda: datetime.now(timezone.utc).isoformat(timespec='seconds'))
        self.events = deque(maxlen=schema.MAX_EVENTS)
        self.previous = None
        self.failed = False

    def collect(self):
        # Start the age budget before any observation: commands and the DNS
        # probe can take time, and an earlier lease sample must not look new.
        started = self.now()
        observation = self.diagnostics.validate_report(self.diagnostics.collect())
        devices = registry_devices(protected_read(REGISTRY, private=True), self.schema.DEVICE_NAMES)
        snapshot = {'version': 1, 'generated_at': self.stamp(), 'monotonic': started,
            'services': observation['services'], 'tunnel': observation['tunnel'],
            'authorization': observation['authorization'], 'devices': devices,
            'dns_probe': observation['dns_probe'], 'ipv6': ipv6_state(), 'events': []}
        self.schema.validate_snapshot(snapshot)
        # Only fixed event kinds and already-validated public fields enter history.
        pending = []
        def event(code, **fields):
            pending.append({'utc': snapshot['generated_at'], 'code': code, **fields})
        if self.previous is None:
            event('snapshot_ready')
        else:
            for previous, current in zip(self.previous['services'], snapshot['services']):
                if previous['active_state'] != current['active_state']:
                    event('service_state_changed', unit=current['unit'], state=current['active_state'] or 'unknown')
            def leases(value):
                if value is None:
                    return None
                return {item['ipv4'] for item in value['addresses']}
            old, new = leases(self.previous['authorization']), leases(snapshot['authorization'])
            # Unknown samples do not manufacture a disconnect or a grant.
            if old is not None and new is not None:
                for ip in sorted(old-new):
                    event('authorization_released', address=ip)
                for ip in sorted(new-old):
                    event('authorization_granted', address=ip)
            if self.previous['ipv6']['kernel_disabled'] != snapshot['ipv6']['kernel_disabled']:
                state = snapshot['ipv6']['kernel_disabled']
                event('ipv6_state_changed', state='disabled' if state is True else 'enabled' if state is False else 'unknown')
        if self.failed:
            event('collector_error')
        history = list(self.events)+pending
        snapshot['events'] = history[-self.schema.MAX_EVENTS:]
        self.schema.validate_snapshot(snapshot)
        return snapshot, pending

    def publish(self, snapshot, pending, gid):
        write_snapshot(snapshot, gid, self.schema)
        self.events.extend(pending)
        self.previous = snapshot
        self.failed = False


def runtime_directory(gid):
    trusted_directory(RUNTIME.parent)
    try:
        RUNTIME.mkdir(mode=0o750)
    except FileExistsError:
        pass
    trusted_directory(RUNTIME)
    os.chown(RUNTIME, ROOT_UID, gid, follow_symlinks=False)
    os.chmod(RUNTIME, 0o750, follow_symlinks=False)


def write_snapshot(snapshot, gid, schema):
    schema.validate_snapshot(snapshot)
    value = (json.dumps(snapshot, sort_keys=True, separators=(',', ':'))+'\n').encode('ascii')
    if len(value) > schema.MAX_BYTES:
        raise ValueError('Oversized public snapshot.')
    runtime_directory(gid)
    target = RUNTIME/'status.json'
    if os.path.lexists(target):
        protected_read(target, limit=schema.MAX_BYTES)
    fd, temporary = tempfile.mkstemp(prefix='.snapshot-', dir=RUNTIME)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o640)
            os.fchown(stream.fileno(), ROOT_UID, gid)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        directory = os.open(RUNTIME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != ROOT_UID:
        raise ValueError('Collector requires its protected root service.')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    os.chdir('/')
    schema, diagnostics = load_modules()
    gid = grp.getgrnam(GROUP).gr_gid
    collector = Collector(schema, diagnostics)
    while True:
        try:
            snapshot, pending = collector.collect()
            collector.publish(snapshot, pending, gid)
        except (OSError, ValueError, KeyError, TypeError):
            # No raw exception text, command output or credential-bearing file data.
            collector.failed = True
            if args.once:
                raise ValueError('Initial public snapshot could not be collected.') from None
        if args.once:
            return
        time.sleep(10)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError):
        raise SystemExit('Panel collector unavailable; private details withheld.') from None
