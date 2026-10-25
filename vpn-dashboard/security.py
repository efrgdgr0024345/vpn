"""Shared trust and policy checks. Root callers load only installed copies."""
import ipaddress
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import stat

INSTALL_DIR = Path('/usr/local/libexec/vpn-desk')
CONFIG_DIR = Path('/etc/vpn-desk')
PROFILE = CONFIG_DIR / 'client.ovpn'
POLICY = CONFIG_DIR / 'policy.json'
HELPER_FILES = ('privileged.py', 'security.py', 'safe_io.py',
                'portal_helper.py', 'vpn_session_helper.py')
SERVICE_USER = 'vpn-desk'


class Refused(RuntimeError):
    pass


def trusted_path(path, private=False):
    """Reject links, untrusted owners, writable ancestors and nonregular files."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise Refused('Expected a protected absolute path.')
    for current in (*reversed(path.parents), path):
        info = current.lstat()
        if (info.st_uid != 0 or info.st_mode & 0o022 or
                not (stat.S_ISREG(info.st_mode) if current == path else stat.S_ISDIR(info.st_mode))):
            raise Refused('Privileged files and their directories must be root-owned, without links or group/other write access.')
    if private and info.st_mode & 0o077:
        raise Refused('The installed profile must have owner-only permissions (0600).')
    return path


def read_trusted(path, *, private=False, limit=1_000_000):
    trusted_path(path, private)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_nlink != 1 or info.st_mode & (0o077 if private else 0o022)):
            raise Refused('Unsafe installed file.')
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise Refused('Installed file is too large.')
        return data.decode('utf-8')


def installed_command(action):
    if action not in ('connect', 'portal-close', 'portal-status'):
        raise Refused('Unsupported privileged action; portal opening is disabled.')
    for filename in HELPER_FILES:
        trusted_path(INSTALL_DIR / filename)
    return ['/usr/bin/sudo', '--', '/usr/bin/python3', '-I', '-B',
            str(INSTALL_DIR / 'privileged.py'), action]


def validate_policy(policy):
    keys = {'wifi_interface', 'vpn_server_ipv4', 'vpn_port', 'vpn_protocol',
            'dhcp_server_ipv4', 'server_name'}
    if not isinstance(policy, dict) or set(policy) != keys:
        raise Refused('Policy has missing or unsupported fields.')
    if not isinstance(policy['wifi_interface'], str) or not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}', policy['wifi_interface']):
        raise Refused('Invalid Wi-Fi interface.')
    if policy['wifi_interface'] in ('lo', 'tun0'):
        raise Refused('Wi-Fi interface must differ from loopback and tun0.')
    for key in ('vpn_server_ipv4', 'dhcp_server_ipv4'):
        if not isinstance(policy[key], str):
            raise Refused('Policy addresses must be IPv4 strings.')
        try:
            address = ipaddress.IPv4Address(policy[key])
        except (ValueError, TypeError, ipaddress.AddressValueError) as exc:
            raise Refused('Policy requires literal IPv4 addresses.') from exc
        if address.is_unspecified or address.is_loopback or address.is_multicast or str(address) == '255.255.255.255':
            raise Refused('Invalid policy address.')
    if type(policy['vpn_port']) is not int or not 1 <= policy['vpn_port'] <= 65535:
        raise Refused('Invalid VPN port.')
    if policy['vpn_protocol'] not in ('udp', 'tcp-client'):
        raise Refused('Unsupported VPN protocol.')
    # This is a certificate common name, not necessarily a DNS hostname.
    # Keep a bounded text subset, permitting internal spaces while rejecting
    # control characters and ambiguous leading/trailing whitespace.
    name = policy['server_name']
    if (not isinstance(name, str) or name != name.strip()
            or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_. -]{0,252}', name)):
        raise Refused('Invalid expected certificate name.')
    return dict(policy)


def load_policy():
    try:
        return validate_policy(json.loads(read_trusted(POLICY, limit=8192)))
    except (ValueError, UnicodeError) as exc:
        raise Refused('Invalid installed policy.') from exc


def service_account():
    try:
        account = pwd.getpwnam(SERVICE_USER)
    except KeyError as exc:
        raise Refused('Create the dedicated vpn-desk system account before connecting.') from exc
    if account.pw_uid <= 0 or account.pw_gid <= 0 or account.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'):
        raise Refused('vpn-desk must be an unprivileged account with login disabled.')
    try:
        group = grp.getgrnam(SERVICE_USER)
        users = pwd.getpwall()
        if (group.gr_gid != account.pw_gid or any(member != SERVICE_USER for member in group.gr_mem)
                or set(os.getgrouplist(SERVICE_USER, account.pw_gid)) != {account.pw_gid}
                or any(user.pw_uid != account.pw_uid and user.pw_gid == account.pw_gid for user in users)
                or any(user.pw_uid == account.pw_uid and user.pw_name != SERVICE_USER for user in users)):
            raise Refused('vpn-desk requires a dedicated group without other users or supplementary groups.')
    except KeyError as exc:
        raise Refused('The dedicated vpn-desk group is missing.') from exc
    return account


def validate_profile(text, policy):
    """Small supported OpenVPN subset; arbitrary directives/files are refused."""
    if not text.isascii() or any(ord(char) < 32 and char not in '\r\n\t' for char in text) or '\x7f' in text:
        raise Refused('Profile must use ASCII text without ambiguous control characters.')
    blocks, options = set(), {}
    block = None
    content = []
    for line in text.splitlines():
        line = line.strip()
        if block:
            if line == '</' + block + '>':
                if not any(content):
                    raise Refused('Empty inline profile asset.')
                blocks.add(block)
                block, content = None, []
            else:
                if '<' in line or '>' in line:
                    raise Refused('Malformed inline profile asset boundary.')
                content.append(line)
            continue
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('<'):
            name = line[1:-1]
            if line != '<' + name + '>' or name not in ('ca', 'cert', 'key', 'tls-crypt', 'tls-auth') or name in blocks:
                raise Refused('Unsupported or duplicate inline profile asset.')
            block = name
            continue
        try:
            parts = shlex.split(line, comments=True)
        except ValueError as exc:
            raise Refused('Malformed profile directive.') from exc
        if not parts:
            continue
        name, values = parts[0], parts[1:]
        if name in options:
            raise Refused('Duplicate profile directive.')
        options[name] = values
    if block:
        raise Refused('Unclosed inline profile asset.')
    required = {
        'client': [], 'dev': ['tun0'], 'proto': [policy['vpn_protocol']],
        'remote': [policy['vpn_server_ipv4'], str(policy['vpn_port'])],
        'remote-cert-tls': ['server'],
        'verify-x509-name': [policy['server_name'], 'name'],
    }
    optional = {
        'nobind': [[]], 'persist-key': [[]], 'persist-tun': [[]],
        'auth-user-pass': [[]], 'auth-nocache': [[]], 'resolv-retry': [['infinite']],
        'key-direction': [['0'], ['1']], 'verb': [[str(n)] for n in range(0, 5)],
        'tls-version-min': [['1.2'], ['1.3']],
        'data-ciphers': [['AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305'],
                         ['AES-256-GCM:AES-128-GCM'], ['AES-256-GCM'], ['AES-128-GCM']],
        'auth': [['SHA256'], ['SHA384'], ['SHA512']],
        'mssfix': [['1300']],
    }
    if any(options.get(key) != values for key, values in required.items()):
        raise Refused('Profile must pin the local policy endpoint, tun0 and expected TLS server identity.')
    if not {'tls-version-min', 'data-ciphers'} <= options.keys():
        raise Refused('An explicit TLS minimum and AEAD data-ciphers policy are required.')
    for key, values in options.items():
        if key not in required and (key not in optional or values not in optional[key]):
            raise Refused('Unsupported profile directive/value; scripts, plugins, management, external files and daemon mode are forbidden.')
    if not {'ca', 'cert', 'key'} <= blocks or not (('tls-auth' in blocks) ^ ('tls-crypt' in blocks)):
        raise Refused('Inline CA, client certificate/key and exactly one TLS control-channel key are required.')
    if 'tls-auth' in blocks and options.get('key-direction') != ['1']:
        raise Refused('tls-auth clients require key-direction 1.')
    if 'key-direction' in options and 'tls-auth' not in blocks:
        raise Refused('key-direction is only supported with tls-auth.')
    return text
