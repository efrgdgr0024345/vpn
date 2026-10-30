#!/usr/bin/python3
"""Explicit IPv6 disablement for a GRUB-based, inactive VPN Desk Kali host.

Use system Python -I -B after independently verifying this standalone file.
This does not stop connections, release a guard, change DNS or reboot the host.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile

SYSCTL = Path('/etc/sysctl.d/90-vpn-desk-ipv4-only.conf')
GRUB = Path('/etc/default/grub.d/99-vpn-desk-ipv4-only.cfg')
GRUB_BASE = Path('/etc/default/grub')
UPDATE_GRUB = Path('/usr/sbin/update-grub')
STATE = Path('/etc/vpn-desk/network-state.json')
LOCK = Path('/run/vpn-dashboard-portal.lock')
PROC = Path('/proc')
IPV6_CONF = Path('/proc/sys/net/ipv6/conf')
MODULE_DISABLED = Path('/sys/module/ipv6/parameters/disable')
HELPER = Path('/usr/local/libexec/vpn-desk/vpn_session_helper.py')
IPV4_CAPABLE_HELPER = '8a168e37acd56d7ca4cfd51a553cab8bda4d5152707a250ffd180f5b24362052'
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}
SYSCTL_CONTENT = (b'# Disable IPv6 on current and newly created interfaces.\n'
    b'# Leading \'-\' also permits booting with the IPv6 subsystem disabled entirely.\n'
    b'-net.ipv6.conf.all.disable_ipv6 = 1\n'
    b'-net.ipv6.conf.default.disable_ipv6 = 1\n')
GRUB_CONTENT = (b'# Preserve existing kernel arguments and disable the IPv6 subsystem at boot.\n'
    b'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} ipv6.disable=1"\n')


class DisableError(RuntimeError):
    pass


def trusted_directory(path):
    path = Path(path)
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise DisableError('A configuration directory is not protected by root.')


def read_owned(path, limit=65536):
    path = Path(path)
    trusted_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or info.st_mode & 0o022):
            raise DisableError('A configuration file has unsafe metadata.')
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise DisableError('A configuration file exceeds its size limit.')
    return value


def check_destination(path, expected):
    # lexists/read_owned refuse dangling links as well as links to real files.
    if os.path.lexists(path):
        if read_owned(path) != expected:
            raise DisableError('An existing IPv6 configuration differs; preserved without changes.')
    else:
        parent = path.parent
        trusted_directory(parent if parent.exists() else parent.parent)


def run(argv, timeout=10):
    # Never print arbitrary command output or subprocess exception details.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT,
                                timeout=timeout, env=ENV, stdin=subprocess.DEVNULL)
        output.seek(0)
        data = output.read(262145)
    if result.returncode or len(data) > 262144:
        raise DisableError('A required system check or configuration command failed.')
    return data


def document(argv):
    try:
        return json.loads(run(argv))
    except (ValueError, UnicodeError):
        raise DisableError('A system network check returned an invalid result.') from None


@contextmanager
def action_lock():
    trusted_directory(LOCK.parent)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or info.st_mode & 0o022):
            raise DisableError('The VPN action lock has unsafe metadata.')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DisableError('A VPN action is running; stop it before changing IPv6.') from None
        yield
    finally:
        os.close(fd)


def require_inactive():
    if os.path.lexists(STATE):
        raise DisableError('Use Restore normal networking before changing IPv6.')
    # /proc/<pid>/exe identifies the executable without exposing credential-bearing argv.
    for path in PROC.iterdir():
        if not path.name.isdigit():
            continue
        try:
            executable = os.readlink(path/'exe')
        except FileNotFoundError:
            continue
        except PermissionError:
            raise DisableError('Running VPN processes could not be verified.') from None
        if Path(executable.removesuffix(' (deleted)')).name in ('openvpn', 'openvpn3'):
            raise DisableError('Stop all VPN sessions before changing IPv6.')
    firewall = document(['/usr/sbin/nft', '-j', 'list', 'ruleset'])
    if not isinstance(firewall, dict) or not isinstance(firewall.get('nftables'), list):
        raise DisableError('Firewall state could not be verified.')
    for entry in firewall['nftables']:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise DisableError('Firewall state could not be verified.')
        kind, item = next(iter(entry.items()))
        if not isinstance(item, dict):
            raise DisableError('Firewall state could not be verified.')
        if item.get('table') == 'vpn_guard' or kind == 'table' and item.get('name') == 'vpn_guard':
            raise DisableError('Use Restore normal networking before changing IPv6.')
    links = document(['/usr/sbin/ip', '-j', '-d', 'link', 'show'])
    tunnel_kinds = {'tun', 'wireguard', 'gre', 'gretap', 'ip6gre', 'ip6gretap', 'ipip',
        'sit', 'vti', 'vti6', 'xfrm', 'ovpn', 'ovpn-dco', 'ovpn-dco-v2', 'vxlan', 'geneve'}
    if not isinstance(links, list) or not all(isinstance(row, dict) for row in links):
        raise DisableError('Network interfaces could not be verified.')
    for row in links:
        info = row.get('linkinfo', {})
        if (not isinstance(row.get('ifname'), str) or not isinstance(info, dict)
                or row['ifname'].startswith(('tun', 'tap', 'wg', 'ovpn'))
                or info.get('info_kind') in tunnel_kinds):
            raise DisableError('Stop all tunnels before changing IPv6.')
    routes = document(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'])
    if not isinstance(routes, list) or not all(isinstance(row, dict) for row in routes):
        raise DisableError('IPv4 routes could not be verified.')
    defaults = [row for row in routes if row.get('dst') == 'default']
    if (len(defaults) != 1 or not isinstance(defaults[0].get('dev'), str)
            or defaults[0].get('dev') == 'lo' or not defaults[0].get('gateway')
            or defaults[0].get('multipath') or defaults[0].get('nexthops')
            or any('encap' in row or str(row.get('dev', '')).startswith(('tun', 'tap', 'wg', 'ovpn'))
                   for row in routes)):
        raise DisableError('One ordinary IPv4 default route is required before changing IPv6.')
    try:
        gateway = ipaddress.IPv4Address(defaults[0]['gateway'])
        if gateway.is_unspecified or gateway.is_multicast or gateway.is_loopback:
            raise ValueError()
    except (ValueError, TypeError):
        raise DisableError('The IPv4 default gateway could not be verified.') from None


def publish(path, value):
    if os.path.lexists(path):
        if read_owned(path) != value:
            raise DisableError('IPv6 configuration changed during setup; preserved.')
        return
    trusted_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix='.vpn-desk-ipv4-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        # link publishes only into an absent destination, never overwriting a race.
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def kernel_text(path):
    try:
        with open(path, 'rb') as stream:
            value = stream.read(65537)
        if len(value) > 65536:
            raise DisableError('A kernel IPv6 check exceeded its size limit.')
        return value.decode('ascii').strip()
    except FileNotFoundError:
        return None


def status():
    module = kernel_text(MODULE_DISABLED)
    kernel_disabled = module in ('1', 'Y', 'y')
    commandline = kernel_text(PROC/'cmdline')
    boot_disabled = commandline is not None and 'ipv6.disable=1' in commandline.split()
    values = []
    if IPV6_CONF.exists():
        for interface in IPV6_CONF.iterdir():
            value = kernel_text(interface/'disable_ipv6')
            if value not in ('0', '1'):
                raise DisableError('An interface IPv6 setting could not be verified.')
            values.append(value)
    # With ipv6.disable=1, ip -6 can return EAFNOSUPPORT rather than an empty list.
    try:
        addresses = document(['/usr/sbin/ip', '-j', '-6', 'address', 'show'])
    except DisableError:
        if not kernel_disabled:
            raise
        addresses = []
    if not isinstance(addresses, list) or not all(isinstance(row, dict) for row in addresses):
        raise DisableError('IPv6 addresses could not be verified.')
    count = 0
    for row in addresses:
        info = row.get('addr_info', [])
        if not isinstance(info, list) or not all(isinstance(item, dict) for item in info):
            raise DisableError('IPv6 addresses could not be verified.')
        count += sum(item.get('family') == 'inet6' for item in info)
    persistence = all(os.path.lexists(path) and read_owned(path) == value
                      for path, value in ((SYSCTL, SYSCTL_CONTENT), (GRUB, GRUB_CONTENT)))
    return {'version': 1, 'persistence_installed': persistence,
        'kernel_ipv6_disabled': kernel_disabled, 'boot_parameter_active': boot_disabled,
        'interface_ipv6_disabled': kernel_disabled or bool(values) and all(v == '1' for v in values),
        'ipv6_address_count': count,
        'reboot_required': not (kernel_disabled and boot_disabled)}


def apply():
    if os.geteuid() != 0:
        raise DisableError('Run this checked setup with sudo and system Python.')
    with action_lock():
        require_inactive()
        if hashlib.sha256(read_owned(HELPER, limit=2_000_000)).hexdigest() != IPV4_CAPABLE_HELPER:
            raise DisableError('Install the reviewed IPv4-capable VPN Desk transport update first.')
        read_owned(GRUB_BASE)
        # Validate the resolved root-owned system program without rejecting normal distro symlinks.
        trusted_directory(UPDATE_GRUB.parent)
        program = UPDATE_GRUB.resolve(strict=True)
        read_owned(program, limit=2_000_000)
        if not os.access(program, os.X_OK):
            raise DisableError('This host requires a supported GRUB update program.')
        check_destination(SYSCTL, SYSCTL_CONTENT)
        check_destination(GRUB, GRUB_CONTENT)
        if not GRUB.parent.exists():
            GRUB.parent.mkdir(mode=0o755)
            trusted_directory(GRUB.parent)
        # Both destinations are checked before the first write. A rerun accepts
        # only completed publications of these exact contents. A crash inside
        # hardlink publication can leave nlink=2 and deliberately requires review.
        publish(SYSCTL, SYSCTL_CONTENT)
        publish(GRUB, GRUB_CONTENT)
        run([str(UPDATE_GRUB)], timeout=120)
        require_inactive()
        run(['/usr/sbin/sysctl', '-p', str(SYSCTL)])
        result = status()
        if not result['persistence_installed'] or not result['interface_ipv6_disabled'] or result['ipv6_address_count']:
            raise DisableError('IPv6 settings were written but immediate disablement was not verified.')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Read status only, including after reboot.')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    if os.geteuid() != 0:
        raise DisableError('Run this checked setup with sudo and system Python.')
    result = status() if args.check else apply()
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (DisableError, OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, DisableError) else 'A required system check failed; stop and review.'
        print('IPv6 setup stopped: ' + detail, file=sys.stderr)
        raise SystemExit(1) from None
