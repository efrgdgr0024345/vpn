#!/usr/bin/python3
"""Guided Debian/Kali installation. Never applies firewall or DNS changes."""
import argparse
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent
HELPER_DIR = Path('/usr/local/libexec/vpn-desk')
APP_DIR = Path('/opt/vpn-desk')
CONFIG_DIR = Path('/etc/vpn-desk')
BIN_DIR = Path('/usr/local/bin')
MENU_DIR = Path('/usr/local/share/applications')
LOCK = Path('/run/vpn-dashboard-portal.lock')
ENVIRONMENT = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}
HELPERS = ('privileged.py', 'security.py', 'safe_io.py', 'portal_helper.py', 'vpn_session_helper.py','session_channel.py','network_setup.py','firewall_policy.py')
APPLICATION = ('app.py', 'connections.py', 'connections_ui.py', 'launch_vpn.py',
               'portal_terminal.py', 'security.py', 'safe_io.py', 'recovery.txt',
               'README.md', 'INSTALL.md','session_channel.py','session_ui.py','install_audit.py')
LAUNCHER = b'''#!/bin/sh
if [ "$(/usr/bin/id -u)" = 0 ]; then
    printf '%s\\n' 'Run VPN Desk as your ordinary desktop user.' >&2
    exit 1
fi
exec /usr/bin/python3 -E -s -B /opt/vpn-desk/app.py "$@"
'''
DESKTOP = b'''[Desktop Entry]
Type=Application
Name=VPN Desk
Comment=Local VPN diagnostics and protected terminal launcher
Exec=/usr/local/bin/vpn-desk
Icon=network-vpn
Terminal=false
Categories=Network;
'''


class InstallationError(RuntimeError):
    pass


def ask(label, default=None):
    suffix = f' [{default}]' if default else ''
    value = input(label + suffix + ': ').strip()
    return value or default or ''


def confirm(label, default=False):
    value = input(label + (' [Y/n]: ' if default else ' [y/N]: ')).strip().lower()
    return default if not value else value in ('y', 'yes')


def required_packages():
    required = {
        'openvpn': ('/usr/sbin/openvpn', '/usr/bin/openvpn'),
        'iproute2': ('/usr/sbin/ip',),
        'nftables': ('/usr/sbin/nft',),
        'sudo': ('/usr/bin/sudo',),
        'passwd': ('/usr/sbin/useradd',),
    }
    missing = [package for package, paths in required.items()
               if not any(os.access(path, os.X_OK) for path in paths)]
    if not os.access('/usr/bin/ss', os.X_OK) and 'iproute2' not in missing:
        missing.append('iproute2')
    if not any(os.access(path, os.X_OK) for path in ('/usr/bin/x-terminal-emulator', '/usr/bin/xterm')):
        missing.append('xterm')
    result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', 'import tkinter'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=10, env=ENVIRONMENT, check=False)
    if result.returncode:
        missing.append('python3-tk')
    return sorted(set(missing))


def ensure_dependencies():
    missing = required_packages()
    if missing:
        print('Missing distribution packages: ' + ', '.join(missing))
        if not os.access('/usr/bin/apt-get', os.X_OK):
            raise InstallationError('Install these prerequisites with your distribution package manager, then rerun.')
        print('Distribution package scripts may start/restart system services.')
        if not confirm('Install these packages using apt now?'):
            raise InstallationError('No packages installed. Rerun after installing the listed prerequisites.')
        subprocess.run(['/usr/bin/apt-get', 'update'], check=True, env=ENVIRONMENT)
        subprocess.run(['/usr/bin/apt-get', 'install', '--yes', '--no-install-recommends', *missing],
                       check=True, env=ENVIRONMENT)
        if required_packages():
            raise InstallationError('Required programs are still unavailable at the supported system paths.')
    binary = next((path for path in ('/usr/sbin/openvpn', '/usr/bin/openvpn') if os.access(path, os.X_OK)), None)
    if binary is None:
        raise InstallationError('OpenVPN is unavailable.')
    result = subprocess.run([binary, '--version'], capture_output=True, text=True,
                            timeout=10, env=ENVIRONMENT, check=False)
    version = re.search(r'^OpenVPN (\d+)\.(\d+)', result.stdout)
    if result.returncode or version is None or tuple(map(int, version.groups())) < (2, 5):
        raise InstallationError('OpenVPN 2.5 or later is required for the enforced crypto/compression policy.')


def check_directory(path):
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        if info.st_uid != 0 or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise InstallationError('Install destinations must be root-owned, without links or group/other write access.')


def ensure_directory(path, mode=0o755):
    if path == path.parent:
        check_directory(path)
        return
    try:
        check_directory(path)
    except FileNotFoundError:
        ensure_directory(path.parent)
        path.mkdir(mode=mode)
        path.chmod(mode)
        check_directory(path)


def existing_bytes(path, private=False):
    check_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_mode & (0o077 if private else 0o022)):
            raise InstallationError('An existing destination file has unsafe ownership, type or permissions.')
        value = stream.read(2_000_001)
        if len(value) > 2_000_000:
            raise InstallationError('Existing destination file is oversized.')
        return value


def publish_file(path, data, mode):
    """Create, never overwrite. A complete inode is published with link(2)."""
    check_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix='.vpn-desk-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
    finally:
        os.unlink(temporary)


def verify_destinations(directory, contents, private=False):
    """Preflight every existing managed file before making any file changes."""
    try:
        check_directory(directory)
    except FileNotFoundError:
        # Verify the existing ancestor chain even if the destination is absent.
        parent = directory.parent
        while not parent.exists():
            parent = parent.parent
        check_directory(parent)
        return
    for name, data in contents.items():
        try:
            if existing_bytes(directory / name, private) != data:
                raise InstallationError('A different existing installation/configuration was found. Nothing will be overwritten; review an upgrade separately.')
        except FileNotFoundError:
            continue


def install_files(directory, contents, *, mode=0o644, private=False):
    verify_destinations(directory, contents, private)
    ensure_directory(directory, 0o700 if private else 0o755)
    for name, data in contents.items():
        path = directory / name
        try:
            old = existing_bytes(path, private)
        except FileNotFoundError:
            publish_file(path, data, mode)
        else:
            if old != data:
                raise InstallationError('Destination changed during installation; refusing overwrite.')
            # The generated application launcher must remain executable on rerun.
            if mode & 0o111 and path.stat().st_mode & 0o111 != mode & 0o111:
                raise InstallationError('Existing application launcher is not executable.')


def snapshot_bundle(invoking_uid):
    names = set(HELPERS + APPLICATION + ('firewall_policy.py',))
    contents = {}
    for name in sorted(names):
        path = SOURCE / name
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise InstallationError('Cannot safely open installation source ' + name + '.') from None
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise InstallationError('Installation source ' + name + ' must be a regular file with one link.')
            if info.st_uid not in (0, invoking_uid):
                raise InstallationError('Installation source ' + name + ' must belong to you or root.')
            if info.st_mode & 0o022:
                raise InstallationError('Installation source ' + name + ' is group/other writable. Remove group/other write permission from the extracted source files and retry.')
            if info.st_size > 1_000_000:
                raise InstallationError('Installation source ' + name + ' is oversized.')
            data = stream.read(1_000_001)
        if len(data) > 1_000_000:
            raise InstallationError('Installation bundle member is oversized.')
        if name.endswith('.py'):
            try:
                compile(data, name, 'exec')
            except SyntaxError:
                raise InstallationError('Installation source ' + name + ' contains invalid Python syntax.') from None
        contents[name] = data
    return contents


@contextmanager
def staged_modules(contents):
    # Root imports use a private, immutable snapshot, never sibling checkout code.
    check_directory(Path('/run'))
    with tempfile.TemporaryDirectory(prefix='vpn-desk-install-', dir='/run') as temporary:
        stage = Path(temporary)
        for name, data in contents.items():
            (stage / name).write_bytes(data)
            (stage / name).chmod(0o600)
        old_path = sys.path[:]
        try:
            sys.path.insert(0, str(stage))
            import security
            import firewall_policy
            import safe_io
            if any(Path(module.__file__).parent != stage for module in (security, firewall_policy, safe_io)):
                raise InstallationError('Unexpected installer module binding.')
            yield security, firewall_policy
        finally:
            sys.path[:] = old_path


def read_profile_source(path, invoking_uid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, invoking_uid)
                or info.st_mode & 0o022 or info.st_nlink != 1):
            raise InstallationError('Source profile must be a regular file owned by you/root, without links or group/other write access.')
        data = stream.read(1_000_001)
        if len(data) > 1_000_000:
            raise InstallationError('Source profile is oversized.')
        return data.decode('utf-8')


def profile_defaults(text):
    """Read suggestions only. Final policy/profile still undergo strict validation."""
    options, block = {}, False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('<'):
            block = not line.startswith('</')
            continue
        if block or not line or line.startswith(('#', ';')):
            continue
        try:
            parts = shlex.split(line, comments=True)
        except ValueError:
            continue
        if parts and parts[0] in ('remote', 'proto', 'verify-x509-name'):
            options[parts[0]] = parts[1:]
    remote = options.get('remote', [])
    identity = options.get('verify-x509-name', [])
    protocol = options.get('proto', [])
    return {'vpn_server_ipv4': remote[0] if remote else None,
            'vpn_port': remote[1] if len(remote) > 1 else '1194',
            'vpn_protocol': protocol[0] if protocol else 'udp',
            'server_name': identity[0] if identity else None}


def network_read(argv):
    """Bounded, read-only local diagnostics; never print raw command output."""
    import safe_io
    try:
        result = safe_io.bounded_run(argv, timeout=5, limit=65536, env=ENVIRONMENT)
        return result.stdout if result.returncode == 0 else ''
    except (OSError, ValueError, subprocess.SubprocessError):
        return ''


def valid_interface(value):
    return (isinstance(value, str)
            and re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}', value) is not None
            and value not in ('lo', 'tun0'))


def wifi_interface_for(server):
    """Use the kernel's selected route, never the first device in a list."""
    try:
        routes = json.loads(network_read(['/usr/sbin/ip', '-j', '-4', 'route', 'get', server]))
    except ValueError:
        return None
    if not isinstance(routes, list) or len(routes) != 1 or not isinstance(routes[0], dict):
        return None
    route = routes[0]
    interface = route.get('dev')
    if not valid_interface(interface) or route.get('multipath') or route.get('nexthops'):
        return None
    device = Path('/sys/class/net') / interface
    if not (device.joinpath('wireless').is_dir() or device.joinpath('phy80211').is_dir()):
        return None
    return interface


def dhcp_server_for(interface):
    """Only an explicit DHCP server identifier is a usable lease suggestion."""
    if not valid_interface(interface):
        return None
    output = network_read(['/usr/bin/nmcli', '-g', 'DHCP4.OPTION', 'device', 'show', interface])
    # nmcli versions emit individual lines or a pipe-separated options line.
    values = re.findall(r'(?:^|\n|[ \t]+\|[ \t]+)dhcp_server_identifier[ \t]*=[ \t]*([^\s|]+)', output)
    if not values or len(set(values)) != 1:
        return None
    try:
        address = ipaddress.IPv4Address(values[0])
    except ValueError:
        return None
    if address.is_unspecified or address.is_loopback or address.is_multicast or int(address) == 0xffffffff:
        return None
    return str(address)


def show_configuration(policy):
    # Only validated, public policy fields are displayed, never profile contents.
    print('\nInstallation settings:')
    print('  Wi-Fi interface: ' + policy['wifi_interface'])
    print('  VPN endpoint: ' + policy['vpn_server_ipv4'] + ':' + str(policy['vpn_port'])
          + ' (' + policy['vpn_protocol'] + ')')
    print('  Wi-Fi DHCP server: ' + policy['dhcp_server_ipv4'])
    print('  Expected TLS certificate name: ' + policy['server_name'])
    print('  Installation leaves routes, DNS and firewall unchanged.\n')


def collect_configuration(security, invoking_uid, *, manual=False):
    policy_path, profile_path = CONFIG_DIR / 'policy.json', CONFIG_DIR / 'client.ovpn'
    if policy_path.exists() or profile_path.exists():
        policy = security.validate_policy(json.loads(existing_bytes(policy_path, True)))
        text = existing_bytes(profile_path, True).decode('utf-8')
        security.validate_profile(text, policy)
        print('Reusing the existing protected configuration; it will not be overwritten.')
        show_configuration(policy)
        return policy, text
    try:
        home = Path(pwd.getpwuid(invoking_uid).pw_dir)
    except KeyError:
        home = Path('/')
    print('Import a supported self-contained .ovpn profile. Its contents/keys will not be printed.')
    source = home / 'vpn-lab/client.ovpn'
    if manual or not source.exists():
        source = Path(ask('Profile file path', str(source)))
    if not source.is_absolute():
        raise InstallationError('Use an absolute profile path.')
    text = read_profile_source(source, invoking_uid)
    defaults = profile_defaults(text)
    # Validate the complete profile before using any of its fields in commands
    # or output. Temporary network fields are replaced with actual local values.
    policy = security.validate_policy({**defaults, 'vpn_port': int(defaults['vpn_port']),
                                      'wifi_interface': 'wlan0', 'dhcp_server_ipv4': '192.0.2.1'})
    security.validate_profile(text, policy)
    interface = wifi_interface_for(policy['vpn_server_ipv4'])
    if manual or interface is None:
        if interface is None:
            print('Could not determine one Wi-Fi interface from the route to the VPN.')
        interface = ask('Wi-Fi interface', interface)
    if not valid_interface(interface):
        raise InstallationError('Invalid Wi-Fi interface.')
    dhcp = dhcp_server_for(interface)
    if manual or dhcp is None:
        if dhcp is None:
            print('No unambiguous DHCP server identifier is available from the current Wi-Fi lease.')
        dhcp = ask('Current Wi-Fi DHCP server IPv4', dhcp)
    policy.update(wifi_interface=interface, dhcp_server_ipv4=dhcp)
    policy = security.validate_policy(policy)
    security.validate_profile(text, policy)
    show_configuration(policy)
    return policy, text


def ensure_account(security):
    try:
        pwd.getpwnam('vpn-desk')
    except KeyError:
        import grp
        try:
            grp.getgrnam('vpn-desk')
        except KeyError:
            subprocess.run(['/usr/sbin/useradd', '--system', '--user-group', '--no-create-home',
                            '--shell', '/usr/sbin/nologin', 'vpn-desk'], check=True, env=ENVIRONMENT)
        else:
            raise InstallationError('A vpn-desk group already exists without its account; inspect it before continuing.')
    return security.service_account()


@contextmanager
def installation_lock():
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise InstallationError('Unsafe installation/action lock.')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def install(security, firewall_policy, contents, policy, profile):
    helper_files = {name: contents[name] for name in HELPERS if name != 'privileged.py'}
    helper_files['privileged.py'] = contents['privileged.py']  # Publish entry last.
    app_files = {name: contents[name] for name in APPLICATION}
    # This public-code inventory excludes policies, profiles, keys and passwords.
    manifest_files={HELPER_DIR/name:data for name,data in helper_files.items()}
    manifest_files.update({APP_DIR/name:data for name,data in app_files.items()})
    manifest_files[BIN_DIR/'vpn-desk']=LAUNCHER
    manifest_files[MENU_DIR/'vpn-desk.desktop']=DESKTOP
    import hashlib
    manifest={'version':1,'files':{str(path):hashlib.sha256(data).hexdigest()
                                  for path,data in sorted(manifest_files.items(),key=lambda row:str(row[0]))}}
    app_files['install-manifest.json']=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    # All known destination conflicts are diagnosed before account/file changes.
    for directory, files in ((HELPER_DIR, helper_files), (APP_DIR, app_files),
                             (BIN_DIR, {'vpn-desk': LAUNCHER}),
                             (MENU_DIR, {'vpn-desk.desktop': DESKTOP})):
        verify_destinations(directory, files)
    with installation_lock():
        account = ensure_account(security)
        candidate = json.dumps(firewall_policy.render_batch(policy, account.pw_uid), indent=2) + '\n'
        config = {'policy.json': (json.dumps(policy, indent=2) + '\n').encode(),
                  'client.ovpn': profile.encode(),
                  'vpn-guard.candidate.json': candidate.encode()}
        # Existing valid policy JSON may have different formatting. Preserve it.
        if (CONFIG_DIR / 'policy.json').exists():
            config['policy.json'] = existing_bytes(CONFIG_DIR / 'policy.json', True)
        verify_destinations(CONFIG_DIR, config, True)
        install_files(HELPER_DIR, helper_files)
        install_files(APP_DIR, app_files)
        install_files(CONFIG_DIR, config, mode=0o600, private=True)
        install_files(BIN_DIR, {'vpn-desk': LAUNCHER}, mode=0o755)
        install_files(MENU_DIR, {'vpn-desk.desktop': DESKTOP})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check source files and dependencies; make no changes.')
    parser.add_argument('--manual', action='store_true', help='Review profile path and local network values interactively.')
    parser.add_argument('--root', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if sys.version_info < (3, 10) or sys.platform != 'linux':
        raise InstallationError('Linux and Python 3.10+ are required.')
    if args.check:
        snapshot_bundle(os.getuid())
        missing = required_packages()
        print('Missing packages: ' + ', '.join(missing) if missing else
              'Source files and required programs passed checks. Nothing installed; run bash install.sh to install.')
        return 2 if missing else 0
    if os.geteuid() != 0:
        if args.root:
            raise InstallationError('Root installation requires sudo authorization.')
        if not sys.stdin.isatty():
            raise InstallationError('Run bash install.sh in an interactive terminal.')
        snapshot_bundle(os.getuid())
        print('VPN Desk will request sudo to install protected files, a dedicated account and local configuration.', flush=True)
        print('No application firewall/DNS migration or sudoers rule will be applied.', flush=True)
        arguments = ['/usr/bin/sudo', '--', '/usr/bin/python3', '-I', '-B', str(SOURCE / 'install.py'), '--root']
        if args.manual:
            arguments.append('--manual')
        return subprocess.run(arguments, check=False).returncode
    if not sys.flags.isolated:
        raise InstallationError('Use bash install.sh or /usr/bin/python3 -I -B install.py.')
    if not sys.stdin.isatty():
        raise InstallationError('An interactive terminal is required for local setup.')
    invoking_uid = int(os.environ.get('SUDO_UID', '0'))
    os.umask(0o077)
    contents = snapshot_bundle(invoking_uid)
    print('VPN Desk installation: existing differing files are preserved; firewall changes are separate.')
    ensure_dependencies()
    with staged_modules(contents) as (security, firewall_policy):
        policy, profile = collect_configuration(security, invoking_uid, manual=args.manual)
        if not confirm('Install the validated configuration, protected app/helpers, launcher and dedicated account?', default=True):
            print('Application installation cancelled.')
            return 1
        install(security, firewall_policy, contents, policy, profile)
    print('\nInstalled. Open VPN Desk from the applications menu, or run vpn-desk as your desktop user.')
    print('Installation has not changed networking. Connect enables the app-owned guard and private VPN DNS.')
    print('An existing unrelated firewall is preserved and causes Connect to stop for migration review.')
    print('Disconnect keeps the guard on; Restore normal networking explicitly releases it. See INSTALL.md.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        # Our validation exceptions contain fixed descriptions, never raw data.
        print('Installation stopped: ' + str(error), file=sys.stderr)
        print('Existing differing files were preserved. See INSTALL.md for the supported setup.', file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        # Never include a profile line, key material or subprocess output in errors.
        print('Installation stopped. Existing differing files were not overwritten.', file=sys.stderr)
        print('Check prerequisites and the supported profile/policy format in INSTALL.md; rerun to resume.', file=sys.stderr)
        raise SystemExit(1)
    except (EOFError, KeyboardInterrupt):
        print('\nInstallation interrupted. Rerun to resume; no firewall changes were applied.', file=sys.stderr)
        raise SystemExit(1)
