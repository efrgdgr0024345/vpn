"""Narrow, root-only IPv4 migration; existing VPN identities and IPv4 policy stay intact."""
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import socket
import stat
import subprocess
import sys

if __name__ == '__main__':
    library = Path('/usr/local/libexec/vpn-lab/server_foundation.py')
    for entry in (*reversed(library.parents), library):
        info = entry.lstat()
        wanted = stat.S_ISREG if entry == library else stat.S_ISDIR
        if info.st_uid != 0 or info.st_mode & 0o022 or not wanted(info.st_mode):
            raise SystemExit('Installed administrator library is not protected.')
    sys.path.insert(0, str(library.parent))
import server_foundation as server

ROOT_UID = 0
SERVER_CONFIG = Path('/etc/openvpn/server/vpn-lab.conf')
FIREWALL_CONFIG = Path('/etc/nftables.conf')
SYSCTL_CONFIG = Path('/etc/sysctl.d/90-vpn-lab-ipv4-only.conf')
FOUNDATION_SYSCTL = Path('/etc/sysctl.d/70-vpn-lab.conf')
FOUNDATION_SYSCTL_CONTENT = '''net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.forwarding=0
'''
STAGE = 'preflight'
GRUB_CONFIG = Path('/etc/default/grub.d/99-vpn-lab-ipv4-only.cfg')
GRUB_OUTPUT = Path('/boot/grub/grub.cfg')
SELFTEST = Path('/usr/local/libexec/vpn-lab/server_selftest.py')
SYSCTL_CONTENT = ('# VPN lab: current and future interfaces are IPv4-only.\n'
                  '-net.ipv6.conf.all.disable_ipv6=1\n'
                  '-net.ipv6.conf.default.disable_ipv6=1\n')
GRUB_CONTENT = ('# VPN lab: retain existing arguments; disable IPv6 at boot.\n'
                'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} ipv6.disable=1"\n')
UNITS = ('openvpn-server@vpn-lab.service', 'vpn-lab-broker.service', 'unbound.service')
BOOL_FIELDS = frozenset(('server_configuration_ipv4_only', 'firewall_ipv6_blocked',
    'interface_ipv6_disabled', 'kernel_ipv6_disabled', 'ipv6_addresses_absent',
    'ipv6_routes_absent', 'boot_argument_configured', 'boot_argument_active',
    'reboot_required', 'server_service_active', 'broker_service_active',
    'resolver_service_active', 'credential_contents_returned'))
REPORT_FIELDS = BOOL_FIELDS | {'version', 'operation'}


def validate_report(report):
    if (not isinstance(report, dict) or set(report) != REPORT_FIELDS
            or type(report['version']) is not int or report['version'] != 1
            or report['operation'] not in ('enable-ipv4-only', 'ipv4-only-status')
            or any(type(report[key]) is not bool for key in BOOL_FIELDS)
            or report['credential_contents_returned']):
        raise ValueError('Invalid IPv4-only report.')
    if report['reboot_required'] != (not report['kernel_ipv6_disabled'] or not report['boot_argument_active']):
        raise ValueError('Inconsistent IPv4-only reboot state.')
    return report


def protected_file(path, missing=False):
    """Validate every ancestor before reading, without following a final symlink."""
    path = Path(path)
    for entry in reversed(path.parents):
        try:
            info = entry.lstat()
        except FileNotFoundError:
            if missing:
                return None
            raise
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise server.SetupError('Unsafe IPv4 migration directory.')
    try:
        return server.read_owned(path)
    except FileNotFoundError:
        if missing:
            return None
        raise


def write_known(path, expected, mode=0o644):
    current = protected_file(path, missing=True)
    if current not in (None, expected):
        raise server.SetupError('Existing IPv4 migration file differs; preserved.')
    if current != expected:
        server.write(path, expected, mode)


def converted_server(value):
    """Only remove the three known legacy IPv6 directives."""
    return (value.replace('server-ipv6 fd47:27:240::/64\n', '')
            .replace('push "redirect-gateway def1 ipv6"\n', 'push "redirect-gateway def1"\n')
            .replace('push "block-ipv6"\n', ''))


def converted_firewall(value):
    for chain in ('input', 'forward'):
        marker = f' chain {chain} {{\n  type filter hook {chain} priority 0; policy drop;\n'
        rule = f'  meta nfproto ipv6 counter drop comment "vpn-lab-block-ipv6-{chain}"\n'
        if rule not in value:
            if value.count(marker) != 1:
                raise server.SetupError('Unrecognized persistent firewall chain.')
            value = value.replace(marker, marker+rule)
    marker = ' chain output { type filter hook output priority 0; policy accept; }'
    expanded = (' chain output {\n  type filter hook output priority 0; policy accept;\n'
                '  meta nfproto ipv6 counter drop comment "vpn-lab-block-ipv6-output"\n }')
    if 'comment "vpn-lab-block-ipv6-output"' not in value:
        if value.count(marker) != 1:
            raise server.SetupError('Unrecognized persistent output firewall chain.')
        value = value.replace(marker, expanded)
    return value


def expected_configurations():
    state = json.loads(protected_file(server.CONFIG/'state.json'))
    routes = json.loads(server.run(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'default']))
    if len(routes) != 1 or not isinstance(routes[0].get('dev'), str):
        raise server.SetupError('Expected one IPv4 default interface.')
    interface = routes[0]['dev']
    server.validate(state['endpoint'], state['ssh_port'], interface)
    value = protected_file(SERVER_CONFIG)
    plugins = re.findall(r'^plugin (/usr/lib/[^\s]+openvpn-plugin-auth-pam\.so) vpn-lab$', value, re.M)
    if len(plugins) != 1:
        raise server.SetupError('Unrecognized VPN authentication configuration.')
    baseline = server.server_configuration(plugins[0])
    converted = converted_server(baseline)
    if value not in (baseline, converted):
        raise server.SetupError('VPN configuration differs from the installed foundation; preserved.')
    old_firewall = server.firewall(interface, state['ssh_port'])
    new_firewall = converted_firewall(old_firewall)
    persistent = protected_file(FIREWALL_CONFIG)
    if persistent not in (old_firewall, new_firewall):
        raise server.SetupError('Persistent firewall differs from the installed foundation; preserved.')
    return value, converted, persistent, new_firewall


def firewall_state():
    document = json.loads(server.run(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'vpn_lab']))
    objects = document.get('nftables')
    if not isinstance(objects, list):
        raise server.SetupError('Unrecognized live firewall.')
    chains = {item['chain']['name']: item['chain'] for item in objects if 'chain' in item}
    if any(chains.get(name, {}).get('hook') != name for name in ('input', 'forward', 'output')):
        raise server.SetupError('VPN firewall base chains are unavailable.')
    authorized = [item['set'] for item in objects if 'set' in item and item['set'].get('name') == 'authorized']
    if len(authorized) != 1 or authorized[0].get('type') != 'ipv4_addr':
        raise server.SetupError('VPN authorization set is unavailable.')
    busy = bool(authorized[0].get('elem'))
    # nft can return separate element objects instead of inline set elements.
    busy = busy or any(item.get('element', {}).get('name') == 'authorized'
                       and item['element'].get('elem') for item in objects)
    missing = []
    for name in ('input', 'forward', 'output'):
        rules = [item['rule'] for item in objects if 'rule' in item and item['rule'].get('chain') == name]
        comment = 'vpn-lab-block-ipv6-'+name
        matching = [rule for rule in rules if rule.get('comment') == comment]
        if not matching:
            missing.append(name)
            continue
        if (len(matching) != 1 or not rules or matching[0] != rules[0]
                or not ipv6_drop(matching[0].get('expr'))):
            raise server.SetupError('Existing IPv6 guard differs; preserved.')
    return missing, bool(busy)


def ipv6_drop(expressions):
    return (isinstance(expressions, list) and len(expressions) == 3
            and expressions[0] == {'match': {'op': '==', 'left': {'meta': {'key': 'nfproto'}}, 'right': 'ipv6'}}
            and set(expressions[1]) == {'counter'} and expressions[2] == {'drop': None})


def boot_configured():
    if protected_file(GRUB_CONFIG, missing=True) != GRUB_CONTENT:
        return False
    commands = [line.split() for line in protected_file(GRUB_OUTPUT).splitlines()
                if line.lstrip().startswith(('linux ', 'linux\t', 'linuxefi ', 'linuxefi\t'))]
    return bool(commands) and all('ipv6.disable=1' in line and 'ipv6.disable=0' not in line for line in commands)


def kernel_disabled():
    try:
        return Path('/sys/module/ipv6/parameters/disable').read_text().strip() in ('1', 'Y', 'y')
    except FileNotFoundError:
        # An absent module alone does not prove it cannot be loaded later.
        return False


def report(operation):
    current, desired, _, _ = expected_configurations()
    missing, _ = firewall_state()
    disabled = kernel_disabled()
    active = 'ipv6.disable=1' in Path('/proc/cmdline').read_text().split()
    if disabled:
        # iproute2 may itself fail with EAFNOSUPPORT once the subsystem is off.
        # Confirm socket creation is unavailable instead of treating arbitrary
        # command failures as empty network state.
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM):
                raise server.SetupError('IPv6 module state and socket availability disagree.')
        except OSError as error:
            if error.errno != errno.EAFNOSUPPORT:
                raise
        addresses, routes = [], []
    else:
        addresses = json.loads(server.run(['/usr/sbin/ip', '-j', '-6', 'address', 'show']))
        routes = json.loads(server.run(['/usr/sbin/ip', '-j', '-6', 'route', 'show', 'table', 'all']))
    interface_disabled = disabled
    if not disabled:
        interface_disabled = all(Path('/proc/sys/net/ipv6/conf', name, 'disable_ipv6').read_text().strip() == '1'
                                 for name in ('all', 'default'))
    services = [server.run(['/usr/bin/systemctl', 'show', '--property=ActiveState', '--value', unit]).strip() == 'active'
                for unit in UNITS]
    return validate_report(dict(version=1, operation=operation,
        server_configuration_ipv4_only=current == desired and 'server-ipv6 ' not in current,
        firewall_ipv6_blocked=not missing, interface_ipv6_disabled=interface_disabled,
        kernel_ipv6_disabled=disabled,
        ipv6_addresses_absent=not any(row.get('addr_info') for row in addresses),
        ipv6_routes_absent=not routes, boot_argument_configured=boot_configured(),
        boot_argument_active=active, reboot_required=not disabled or not active,
        server_service_active=services[0], broker_service_active=services[1], resolver_service_active=services[2],
        credential_contents_returned=False))


def administer(operation):
    global STAGE
    STAGE = 'preflight'
    if os.geteuid() != 0 or operation not in ('enable-ipv4-only', 'ipv4-only-status'):
        raise server.SetupError('IPv4 migration requires root and a fixed operation.')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    if operation == 'ipv4-only-status':
        return report(operation)
    # The privileged channel must not depend on IPv6 that this action removes.
    connection = os.environ.get('SSH_CONNECTION')
    if connection:
        fields = connection.split()
        if len(fields) != 4 or any(ipaddress.ip_address(fields[index]).version != 4 for index in (0, 2)):
            raise server.SetupError('Use the pinned IPv4 administrator connection.')
    server.directory(server.CONFIG, 0o700)
    lock_fd = os.open(server.CONFIG/'install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'w') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1 or info.st_mode & 0o077:
            raise server.SetupError('Unsafe migration lock.')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before, desired, old_firewall, desired_firewall = expected_configurations()
        missing, busy = firewall_state()
        if busy:
            raise server.SetupError('A VPN forwarding session is active; no migration applied.')
        for path in (Path('/etc/default/grub'), GRUB_OUTPUT, Path('/usr/sbin/update-grub')):
            protected_file(path)
        if not os.access('/usr/sbin/update-grub', os.X_OK):
            raise server.SetupError('The supported GRUB updater is unavailable.')
        foundation_sysctl = protected_file(FOUNDATION_SYSCTL)
        desired_foundation_sysctl = FOUNDATION_SYSCTL_CONTENT.replace('net.ipv6.conf.all.forwarding=0', '-net.ipv6.conf.all.forwarding=0')
        if foundation_sysctl not in (FOUNDATION_SYSCTL_CONTENT, desired_foundation_sysctl):
            raise server.SetupError('Foundation forwarding sysctls differ; preserved.')
        for path, content in ((SYSCTL_CONFIG, SYSCTL_CONTENT), (GRUB_CONFIG, GRUB_CONTENT)):
            server.directory(path.parent)
            if protected_file(path, missing=True) not in (None, content):
                raise server.SetupError('Existing IPv4-only configuration differs; preserved.')
        selftest = globals().get('SELFTEST_SOURCE')
        prior_hash = globals().get('SELFTEST_PREVIOUS_SHA256')
        installed_test = protected_file(SELFTEST)
        if (not isinstance(selftest, str) or not selftest or not isinstance(prior_hash, str)
                or hashlib.sha256(installed_test.encode()).hexdigest() not in
                   (prior_hash, hashlib.sha256(selftest.encode()).hexdigest())):
            raise server.SetupError('The installed VPN self-test differs; preserved.')
        compile(selftest, str(SELFTEST), 'exec')
        recovery = server.EXPORT/'recovery'
        server.directory(recovery, 0o700)
        for name, value in (('vpn-lab.before-ipv4-only.conf', before), ('nftables.before-ipv4-only.conf', old_firewall)):
            backup = recovery/name
            existing = protected_file(backup, missing=True)
            # A retry may see the converted live file but retains the original backup.
            compatible = (converted_server(existing) == desired if name.startswith('vpn-lab')
                          else converted_firewall(existing) == desired_firewall) if existing is not None else True
            if not compatible:
                raise server.SetupError('IPv4 migration recovery copy differs; preserved.')
            if existing is None:
                server.write(backup, value)
        STAGE = 'persistent boot configuration'
        write_known(SYSCTL_CONFIG, SYSCTL_CONTENT)
        server.write(FOUNDATION_SYSCTL, desired_foundation_sysctl, 0o644)
        write_known(GRUB_CONFIG, GRUB_CONTENT)
        server.run(['/usr/sbin/update-grub'], timeout=120)
        if not boot_configured():
            raise server.SetupError('GRUB did not include the IPv6 boot argument; VPN not changed.')
        # First add fail-closed rules in one transaction. Never load the whole
        # persistent file: it contains legacy flush ruleset and would erase leases/unrelated tables.
        STAGE = 'IPv6 firewall rules'
        if missing:
            commands = ''.join('insert rule inet vpn_lab '+name+' meta nfproto ipv6 counter drop comment "vpn-lab-block-ipv6-'+name+'"\n' for name in missing)
            server.run(['/usr/sbin/nft', '--check', '-f', '-'], data=commands)
            server.run(['/usr/sbin/nft', '-f', '-'], data=commands)
        server.write(FIREWALL_CONFIG, desired_firewall, 0o644)
        STAGE = 'VPN service conversion'
        server.run(['/usr/bin/systemctl', 'stop', UNITS[0], UNITS[1]])
        server.write(SERVER_CONFIG, desired)
        server.write(SELFTEST, selftest, 0o644)
        server.run(['/usr/sbin/sysctl', '-p', str(SYSCTL_CONFIG)])
        # On error, deliberately leave services stopped for independent recovery;
        # restarting a partly converted configuration would obscure the failure.
        server.run(['/usr/bin/systemctl', 'start', UNITS[1], UNITS[0]])
        STAGE = 'live verification'
        result = report(operation)
        required = ('server_configuration_ipv4_only', 'firewall_ipv6_blocked', 'interface_ipv6_disabled',
                    'ipv6_addresses_absent', 'ipv6_routes_absent', 'boot_argument_configured',
                    'server_service_active', 'broker_service_active', 'resolver_service_active')
        if not all(result[name] for name in required):
            raise server.SetupError('IPv4-only migration verification failed; independent recovery may be needed.')
        return result


if __name__ == '__main__':
    try:
        print(json.dumps(administer(globals().get('IPV4_ONLY_OPERATION', '')), sort_keys=True))
    except (server.SetupError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'error': 'setup_failed', 'detail': 'IPv4-only administration failed during '+STAGE+'. Inspect locally through the independent recovery console.'}))
        raise SystemExit(1)
