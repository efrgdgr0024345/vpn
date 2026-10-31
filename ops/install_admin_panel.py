"""Install the private read-only VPN panel without restarting the working VPN."""
import base64
import fcntl
import grp
import hashlib
import http.client
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import ssl
import socket
import stat
import subprocess
import sys
import tempfile
import time

if __name__ == '__main__':
    library = Path('/usr/local/libexec/vpn-lab/server_foundation.py')
    for path in (*reversed(library.parents), library):
        info = path.lstat()
        wanted = stat.S_ISREG if path == library else stat.S_ISDIR
        if info.st_uid != 0 or info.st_mode & 0o022 or not wanted(info.st_mode):
            raise SystemExit('Installed administrator library is not protected.')
    sys.path.insert(0, str(library.parent))
import server_foundation as server

USER = 'vpn-lab-admin'
CODE = Path('/opt/vpn-lab-admin')
CONFIG = Path('/etc/vpn-lab-admin')
EXPORT = Path('/root/vpn-lab/admin')
FIREWALL = Path('/etc/nftables.conf')
VPN_CONFIG = Path('/etc/openvpn/server/vpn-lab.conf')
MANIFEST = CONFIG/'install-manifest.json'
UNITS = Path('/etc/systemd/system')
COMMENT = 'vpn-lab-admin'
SOURCE_FILES = frozenset(('server.py', 'schema.py', 'collector.py', 'server_diagnostics.py', 'history.py', 'observer.py',
                          'static/index.html', 'static/app.js', 'static/style.css'))
PRESERVED_UNITS = ('openvpn-server@vpn-lab.service', 'vpn-lab-broker.service', 'unbound.service')
PANEL_UNITS = ('vpn-lab-admin-collector.service', 'vpn-lab-admin.service', 'vpn-lab-admin-observer.service')
URL = 'http://172.27.240.1:8080'
RULE = ('  iifname "tun-lab" ip saddr @authorized ip daddr 172.27.240.1 '
        'tcp dport 8080 counter accept comment "vpn-lab-admin"\n')
LEGACY_RULE = RULE.replace('8080', '8443')
HOST_DROP = '  iifname "tun-lab" counter drop comment "vpn-lab-block-host"\n'
STAGE = 'preflight'
REPORT_FIELDS = frozenset(('version', 'source_commit', 'panel_url', 'web_service_active',
    'collector_service_active', 'history_service_active', 'vpn_runtime_preserved', 'firewall_rule_verified',
    'vpn_only_listener', 'credential_contents_returned', 'legacy_https_closed', 'transport'))
BOOL_FIELDS = frozenset(('web_service_active', 'collector_service_active', 'history_service_active', 'vpn_runtime_preserved',
                        'firewall_rule_verified', 'vpn_only_listener', 'credential_contents_returned', 'legacy_https_closed'))


def certificate_der(value):
    if (not isinstance(value, str) or len(value) > 4096
            or not re.fullmatch(r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n', value)):
        raise ValueError('Unsupported public panel certificate.')
    return ssl.PEM_cert_to_DER_cert(value)


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != REPORT_FIELDS
            or type(value['version']) is not int or value['version'] != 2
            or not isinstance(value['source_commit'], str) or not re.fullmatch(r'[0-9a-f]{40}', value['source_commit'])
            or value['panel_url'] != URL or any(type(value[k]) is not bool for k in BOOL_FIELDS)
            or value['credential_contents_returned'] or value['transport'] != 'http-over-vpn'):
        raise ValueError('Unsupported panel installation report.')
    return value


def owned(path, missing=False):
    path = Path(path)
    for parent in reversed(path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            if missing:
                return None
            raise
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise server.SetupError('Unsafe panel file ancestry.')
    try:
        return server.read_owned(path)
    except FileNotFoundError:
        if missing:
            return None
        raise


def directory(path, mode=0o755, gid=None):
    server.directory(path, mode)
    if gid is not None:
        os.chown(path, 0, gid)
    Path(path).chmod(mode)


def write(path, value, mode=0o644, gid=None):
    server.write(path, value, mode)
    if gid is not None:
        os.chown(path, 0, gid)
        Path(path).chmod(mode)


def public_parent():
    # Do not broaden an unrelated ancestor to make service code executable.
    # /opt is a normal public-code location, but verify its actual metadata.
    for path in (*reversed(CODE.parent.parents), CODE.parent):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not info.st_mode & 0o001):
            raise server.SetupError('The public panel code parent is not safely traversable.')


def configuration():
    return {'version': 1, 'bind': '172.27.240.1', 'port': 8080, 'origin': URL,
            'snapshot': '/run/vpn-lab-admin/status.json', 'auth': str(CONFIG/'auth.json'),
            'static': str(CODE/'static')}


def service_units():
    common = '''Restart=on-failure
RestartSec=3s
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
LimitCORE=0
UMask=0077
TasksMax=64
LimitNOFILE=128
MemoryMax=256M
'''
    web = '''[Unit]
Description=Private VPN administration panel
After=openvpn-server@vpn-lab.service vpn-lab-admin-collector.service
Wants=vpn-lab-admin-collector.service

[Service]
Type=simple
User=vpn-lab-admin
Group=vpn-lab-admin
WorkingDirectory=/
ExecStart=/usr/bin/python3 -I -B /opt/vpn-lab-admin/server.py
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_UNIX
IPAddressDeny=any
IPAddressAllow=172.27.240.0/24
SocketBindDeny=any
SocketBindAllow=ipv4:tcp:8080
InaccessiblePaths=-/etc/openvpn -/etc/shadow -/etc/gshadow -/etc/vpn-lab-admin/ca-private -/etc/vpn-lab-admin/server.key
'''+common+'''
[Install]
WantedBy=multi-user.target
'''
    collector = '''[Unit]
Description=Read-only VPN panel status collector
After=openvpn-server@vpn-lab.service

[Service]
Type=simple
User=root
Group=vpn-lab-admin
WorkingDirectory=/
ExecStart=/usr/bin/python3 -I -B /opt/vpn-lab-admin/collector.py
RuntimeDirectory=vpn-lab-admin
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=restart
ReadWritePaths=/run/vpn-lab-admin
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK
IPAddressDeny=any
IPAddressAllow=172.27.240.1/32
IPAddressAllow=127.0.0.0/8
InaccessiblePaths=-/etc/shadow -/etc/gshadow -/etc/openvpn/lab/pki -/etc/openvpn/lab/tls-crypt.key -/etc/openvpn/server -/etc/vpn-lab-admin
'''+common+'''
[Install]
WantedBy=multi-user.target
'''
    observer = '''[Unit]
Description=Private VPN destination and DNS metadata observer
After=openvpn-server@vpn-lab.service

[Service]
Type=simple
User=root
Group=vpn-lab-admin
WorkingDirectory=/
ExecStart=/usr/bin/python3 -I -B /opt/vpn-lab-admin/observer.py
StateDirectory=vpn-lab-admin
StateDirectoryMode=0750
ReadWritePaths=/var/lib/vpn-lab-admin
CapabilityBoundingSet=CAP_NET_RAW
RestrictAddressFamilies=AF_PACKET AF_UNIX
InaccessiblePaths=-/etc/shadow -/etc/gshadow -/etc/openvpn/lab/pki -/etc/openvpn/lab/tls-crypt.key -/etc/openvpn/server -/etc/vpn-lab-admin -/run/vpn-lab-admin
'''+common+'''
[Install]
WantedBy=multi-user.target
'''
    return dict(zip(PANEL_UNITS, (collector, web, observer)))


def ipv4_firewall(value):
    for chain in ('input', 'forward'):
        marker = f' chain {chain} {{\n  type filter hook {chain} priority 0; policy drop;\n'
        rule = f'  meta nfproto ipv6 counter drop comment "vpn-lab-block-ipv6-{chain}"\n'
        if rule not in value:
            if value.count(marker) != 1:
                raise server.SetupError('Unrecognized persistent firewall chain.')
            value = value.replace(marker, marker+rule)
    if 'comment "vpn-lab-block-ipv6-output"' not in value:
        marker = ' chain output { type filter hook output priority 0; policy accept; }'
        if value.count(marker) != 1:
            raise server.SetupError('Unrecognized persistent output chain.')
        value = value.replace(marker, ' chain output {\n  type filter hook output priority 0; policy accept;\n'
                              '  meta nfproto ipv6 counter drop comment "vpn-lab-block-ipv6-output"\n }')
    return value


def firewall_configuration():
    state = json.loads(owned(server.CONFIG/'state.json'))
    routes = json.loads(server.run(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'default']))
    if len(routes) != 1:
        raise server.SetupError('Expected one IPv4 external interface.')
    interface = routes[0]['dev']
    server.validate(state['endpoint'], state['ssh_port'], interface)
    baseline = ipv4_firewall(server.firewall(interface, state['ssh_port']))
    # The deployed legacy generator retained two now-unreachable IPv6 input
    # exceptions during the narrow IPv4 migration. Recognize only these exact
    # old/new public templates; preserve whichever one is actually installed.
    dhcp6 = f'  iifname "{interface}" udp sport 547 udp dport 546 accept\n'
    icmp6 = f'  iifname "{interface}" meta l4proto ipv6-icmp accept\n'
    icmp4 = f'  iifname "{interface}" ip protocol icmp accept\n'
    fresh = baseline.replace(dhcp6, '').replace(icmp6, '')
    if fresh.count(icmp4) != 1 or fresh.count(HOST_DROP) != 1:
        raise server.SetupError('Unrecognized VPN host filtering.')
    legacy = fresh.replace(icmp4, dhcp6+icmp4+icmp6)
    current = owned(FIREWALL)
    for candidate in (fresh, legacy):
        desired = candidate.replace(HOST_DROP, RULE+HOST_DROP)
        if current in (candidate, desired, candidate.replace(HOST_DROP, LEGACY_RULE+HOST_DROP)):
            return current, desired
    raise server.SetupError('Persistent firewall differs; preserved.')



def admin_expression(port=8080):
    return [
        {'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'tun-lab'}},
        {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '@authorized'}},
        {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}}, 'right': '172.27.240.1'}},
        {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': port}},
        {'counter': {}}, {'accept': None}]


def live_rule(allow_legacy=False):
    document = json.loads(server.run(['/usr/sbin/nft', '-j', 'list', 'chain', 'inet', 'vpn_lab', 'input']))
    objects = document['nftables']
    chains = [o['chain'] for o in objects if 'chain' in o]
    if (len(chains) != 1 or any(chains[0].get(k) != v for k, v in
            (('family', 'inet'), ('table', 'vpn_lab'), ('name', 'input'), ('hook', 'input'), ('type', 'filter'), ('policy', 'drop')))):
        raise server.SetupError('Unexpected live input chain.')
    rules = [o['rule'] for o in objects if 'rule' in o]
    drops = [r for r in rules if r.get('comment') == 'vpn-lab-block-host']
    matches = [r for r in rules if r.get('comment') == COMMENT]
    if (len(drops) != 1 or type(drops[0].get('handle')) is not int or drops[0]['handle'] < 1
            or not rules or rules[0].get('comment') != 'vpn-lab-block-ipv6-input'):
        raise server.SetupError('Expected VPN host and IPv6 guards.')
    guard = [{'match': {'op': '==', 'left': {'meta': {'key': 'nfproto'}}, 'right': 'ipv6'}},
             {'counter': {}}, {'drop': None}]
    host = [{'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'tun-lab'}},
            {'counter': {}}, {'drop': None}]
    def normalize(expressions):
        if not isinstance(expressions, list) or not all(isinstance(item, dict) for item in expressions):
            return None
        return [{key: ({} if key == 'counter' else value) for key, value in item.items()} for item in expressions]
    if normalize(rules[0].get('expr')) != guard or normalize(drops[0].get('expr')) != host:
        raise server.SetupError('Live VPN host and IPv6 guards differ; preserved.')
    if not matches:
        return False, drops[0]['handle']
    expr = matches[0].get('expr')
    normalized = normalize(expr)
    if (len(matches) != 1 or normalized not in ([admin_expression(), admin_expression(8443)] if allow_legacy else [admin_expression()])
            or rules.index(matches[0]) >= rules.index(drops[0])):
        raise server.SetupError('Existing panel firewall exception differs; preserved.')
    return True, drops[0]['handle']


def legacy_rule_handle():
    document = json.loads(server.run(['/usr/sbin/nft', '-j', 'list', 'chain', 'inet', 'vpn_lab', 'input']))
    for item in document['nftables']:
        rule = item.get('rule', {})
        if rule.get('comment') == COMMENT:
            expr = [{key: ({} if key == 'counter' else value) for key,value in entry.items()}
                    for entry in rule['expr']]
            if expr == admin_expression(8443):
                handle = rule.get('handle')
                if type(handle) is not int or handle < 1:
                    raise server.SetupError('Unrecognized legacy panel rule handle.')
                return handle
    return None


def account():
    try:
        value = pwd.getpwnam(USER)
    except KeyError:
        server.run(['/usr/sbin/useradd', '--system', '--user-group', '--home-dir', '/nonexistent',
                    '--no-create-home', '--shell', '/usr/sbin/nologin', USER])
        value = pwd.getpwnam(USER)
    group = grp.getgrnam(USER)
    if (value.pw_uid <= 0 or value.pw_gid <= 0 or value.pw_gid != group.gr_gid
            or value.pw_dir != '/nonexistent' or value.pw_shell != '/usr/sbin/nologin'
            or set(os.getgrouplist(USER, value.pw_gid)) != {value.pw_gid}
            or set(group.gr_mem) - {USER}
            or any(g.gr_gid == group.gr_gid and g.gr_name != USER for g in grp.getgrall())
            or any((p.pw_uid == value.pw_uid or p.pw_gid == value.pw_gid) and p.pw_name != USER for p in pwd.getpwall())):
        raise server.SetupError('Panel account conflicts with existing local permissions.')
    return value.pw_uid, group.gr_gid


def password_verifier(password, salt):
    return hashlib.scrypt(password.encode('ascii'), salt=salt, n=32768, r=8, p=1,
                          dklen=32, maxmem=64*1024*1024)


def credentials(gid):
    login = EXPORT/'login.txt'
    auth = CONFIG/'auth.json'
    existing = owned(login, missing=True)
    saved = owned(auth, missing=True)
    if existing is not None and stat.S_IMODE(login.lstat().st_mode) != 0o600:
        raise server.SetupError('Protected panel password permissions are unsafe.')
    if saved is not None and (stat.S_IMODE(auth.lstat().st_mode) not in (0o600, 0o640)
                              or auth.lstat().st_gid not in (0, gid)):
        raise server.SetupError('Protected panel verifier permissions are unsafe.')
    if existing is None:
        if saved is not None:
            raise server.SetupError('Panel password original is missing; preserved verifier.')
        existing = secrets.token_urlsafe(32)+'\n'
        write(login, existing, 0o600)
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}\n', existing):
        raise server.SetupError('Protected panel password has an unexpected shape.')
    if saved is None:
        salt = secrets.token_bytes(16)
        record = {'version': 1, 'salt': base64.b64encode(salt).decode('ascii'),
                  'hash': base64.b64encode(password_verifier(existing.strip(), salt)).decode('ascii'),
                  'n': 32768, 'r': 8, 'p': 1}
        write(auth, json.dumps(record, sort_keys=True)+'\n', 0o640, gid)
    else:
        record = json.loads(saved)
        if (set(record) != {'version', 'salt', 'hash', 'n', 'r', 'p'}
                or record['version'] != 1 or (record['n'], record['r'], record['p']) != (32768, 8, 1)):
            raise server.SetupError('Panel password verifier differs; preserved.')
        salt, digest = base64.b64decode(record['salt'], validate=True), base64.b64decode(record['hash'], validate=True)
        if len(salt) != 16 or len(digest) != 32 or not hmac.compare_digest(password_verifier(existing.strip(), salt), digest):
            raise server.SetupError('Panel password and verifier disagree; preserved.')
        os.chown(auth, 0, gid)
        auth.chmod(0o640)


def public_binary(argv, data=None):
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, input=data, stdout=output, stderr=subprocess.DEVNULL,
                                timeout=15, env=server.ENV)
        output.seek(0)
        value = output.read(2_000_001)
    if result.returncode or len(value) > 2_000_000:
        raise server.SetupError('Public certificate inspection failed.')
    return value


def certificates(gid):
    private = CONFIG/'ca-private'
    directory(private, 0o700)
    ca_key, ca = private/'ca.key', private/'ca.crt'
    key, certificate = CONFIG/'server.key', CONFIG/'server.crt'
    for path in (ca_key, ca, key, certificate):
        if os.path.lexists(path):
            owned(path)
    if ca_key.exists() and stat.S_IMODE(ca_key.lstat().st_mode) != 0o600:
        raise server.SetupError('Protected panel CA key permissions are unsafe.')
    if key.exists() and (stat.S_IMODE(key.lstat().st_mode) not in (0o600, 0o640)
                         or key.lstat().st_gid not in (0, gid)):
        raise server.SetupError('Protected panel TLS key permissions are unsafe.')
    if not ca_key.exists():
        if ca.exists():
            raise server.SetupError('Panel CA key is missing; preserved existing CA.')
        server.run(['/usr/bin/openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(ca_key)])
    if not ca.exists():
        server.run(['/usr/bin/openssl', 'req', '-new', '-x509', '-sha256', '-days', '3650',
                    '-key', str(ca_key), '-subj', '/CN=VPN Lab Panel CA', '-out', str(ca),
                    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                    '-addext', 'nameConstraints=critical,permitted;IP:172.27.240.1/255.255.255.255,permitted;DNS:.vpn.invalid'])
    if not key.exists():
        if certificate.exists():
            raise server.SetupError('Panel leaf key is missing; preserved existing certificate.')
        server.run(['/usr/bin/openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(key)])
    if not certificate.exists():
        with tempfile.TemporaryDirectory(prefix='.panel-certificate-', dir=private) as temporary:
            request, extensions = Path(temporary)/'request.csr', Path(temporary)/'extensions'
            write(extensions, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                  'extendedKeyUsage=serverAuth\nsubjectAltName=IP:172.27.240.1\n')
            server.run(['/usr/bin/openssl', 'req', '-new', '-sha256', '-key', str(key),
                        '-subj', '/CN=VPN Lab Admin', '-out', str(request)])
            server.run(['/usr/bin/openssl', 'x509', '-req', '-sha256', '-days', '365', '-in', str(request),
                        '-CA', str(ca), '-CAkey', str(ca_key), '-set_serial', str(secrets.randbits(127)+1),
                        '-extfile', str(extensions), '-out', str(certificate)])
    # Reject combined certificate/private-key files BEFORE publishing a public
    # CA copy or sharing any leaf file with the unprivileged web group.
    ca_public = owned(ca)
    try:
        ca_der = certificate_der(ca_public)
        certificate_der(owned(certificate))
    except ValueError:
        raise server.SetupError('Panel certificate files must contain only one public certificate.') from None
    server.run(['/usr/bin/openssl', 'verify', '-CAfile', str(ca), '-purpose', 'sslserver', '-verify_ip', '172.27.240.1', str(certificate)])
    constraints = server.run(['/usr/bin/openssl', 'x509', '-in', str(certificate), '-noout', '-ext', 'basicConstraints'])
    if [line.strip() for line in constraints.splitlines()] != ['X509v3 Basic Constraints: critical', 'CA:FALSE']:
        raise server.SetupError('The web TLS credential must not be a certificate authority.')
    # Check that the key actually corresponds to the certificate before sharing
    # only the leaf key with the isolated web account.
    leaf_public = server.run(['/usr/bin/openssl', 'x509', '-in', str(certificate), '-pubkey', '-noout'])
    key_public = server.run(['/usr/bin/openssl', 'pkey', '-in', str(key), '-pubout'])
    if leaf_public != key_public:
        raise server.SetupError('Panel TLS key does not match its certificate.')
    for path in (CONFIG/'ca.crt', EXPORT/'ca.crt'):
        prior = owned(path, missing=True)
        if prior not in (None, ca_public):
            raise server.SetupError('Existing panel CA copy differs; preserved.')
        write(path, ca_public, 0o644)
    os.chown(key, 0, gid)
    key.chmod(0o640)
    os.chown(certificate, 0, gid)
    certificate.chmod(0o640)
    ca_key.chmod(0o600)
    ca.chmod(0o600)
    public_der = public_binary(['/usr/bin/openssl', 'pkey', '-pubin', '-outform', 'DER'], leaf_public.encode('ascii'))
    return hashlib.sha256(ca_der).hexdigest(), 'sha256//'+base64.b64encode(hashlib.sha256(public_der).digest()).decode('ascii'), ca_public


def runtime_identity():
    result = {}
    for unit in PRESERVED_UNITS:
        fields = dict(line.split('=', 1) for line in server.run(['/usr/bin/systemctl', 'show',
            '--property=MainPID,ActiveState,ActiveEnterTimestampMonotonic', unit]).splitlines() if '=' in line)
        if fields.get('ActiveState') != 'active' or not fields.get('MainPID', '').isdigit() or int(fields['MainPID']) < 2:
            raise server.SetupError('The existing VPN services must be active before panel installation.')
        result[unit] = (fields['MainPID'], fields.get('ActiveEnterTimestampMonotonic'))
    return result


def public_files(sources):
    values = {str(CODE/name): content for name, content in sources.items()}
    values.update({str(UNITS/name): content for name, content in service_units().items()})
    values[str(CONFIG/'config.json')] = json.dumps(configuration(), sort_keys=True)+'\n'
    return values


def validated_sources(sources, revision):
    if not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise server.SetupError('Use an immutable panel source revision.')
    if (not isinstance(sources, dict) or set(sources) != SOURCE_FILES
            or any(not isinstance(value, str) or not value or len(value.encode()) > 2_000_000 for value in sources.values())):
        raise server.SetupError('Unexpected panel source bundle.')
    for name, value in sources.items():
        if name.endswith('.py'):
            compile(value, name, 'exec')
    return public_files(sources)


def preflight_files(values):
    old = owned(MANIFEST, missing=True)
    if old is not None:
        record = json.loads(old)
        legacy_paths = set(values)-{str(CODE/'history.py'),str(CODE/'observer.py'),str(UNITS/'vpn-lab-admin-observer.service')}
        if (not isinstance(record, dict) or set(record) != {'version', 'source_commit', 'files'}
                or record['version'] != 1 or not re.fullmatch(r'[0-9a-f]{40}', record['source_commit'])
                or not isinstance(record['files'], dict) or set(record['files']) not in (set(values),legacy_paths)
                or any(not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest) for digest in record['files'].values())):
            raise server.SetupError('The previous panel manifest is unrecognized.')
        for path in set(values)-set(record['files']):
            current = owned(path, missing=True)
            if current not in (None,values[path]):
                raise server.SetupError('An added panel file differs; preserved.')
        for path, digest in record['files'].items():
            current = owned(path, missing=True)
            candidate = hashlib.sha256(values[path].encode()).hexdigest()
            if current is None or hashlib.sha256(current.encode()).hexdigest() not in (digest, candidate):
                raise server.SetupError('Existing panel code/configuration differs; preserved.')
    else:
        for path, desired in values.items():
            current = owned(path, missing=True)
            if current not in (None, desired):
                raise server.SetupError('Existing panel source/configuration differs; preserved.')
    # An unlisted file could shadow trusted imports; do not silently install
    # over an unrelated directory or accept hidden additions after deployment.
    if CODE.exists():
        seen = set()
        for path in CODE.rglob('*'):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                if path != CODE/'static':
                    raise server.SetupError('Unexpected directory in the panel code directory.')
            elif stat.S_ISREG(info.st_mode):
                seen.add(str(path))
            else:
                raise server.SetupError('Unexpected link/type in the panel code directory.')
        expected = {str(CODE/name) for name in SOURCE_FILES}
        if seen != {path for path in expected if Path(path).exists()}:
            raise server.SetupError('Unexpected files in the panel code directory.')


def port_listeners(port=8080):
    lines = server.run(['/usr/bin/ss', '-H', '-lntu'], timeout=5).splitlines()
    listeners = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 6 and fields[4].rsplit(':', 1)[-1] == str(port):
            listeners.append((fields[0], fields[4]))
    return listeners


def port_in_use():
    return bool(port_listeners())


def listener_private():
    listeners = port_listeners()
    return bool(listeners) and all(item == ('tcp', '172.27.240.1:8080') for item in listeners)


def tls_matches_certificate():
    try:
        context = ssl.create_default_context(cafile=str(CONFIG/'ca.crt'))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        expected = ssl.PEM_cert_to_DER_cert(owned(CONFIG/'server.crt'))
        with socket.create_connection(('172.27.240.1', 8443), timeout=2) as transport:
            with context.wrap_socket(transport, server_hostname='172.27.240.1') as channel:
                return hmac.compare_digest(channel.getpeercert(binary_form=True), expected)
    except (OSError, ValueError, ssl.SSLError):
        return False



def http_ready():
    connection = http.client.HTTPConnection('172.27.240.1', 8080, timeout=2)
    try:
        # The server itself is not an authorized client; its request must fail.
        connection.request('GET', '/api/status')
        response = connection.getresponse()
        return (response.status == 403 and response.read(1024) == b'{"error":"Request refused."}'
                and response.getheader('Cache-Control') == 'no-store')
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def install(sources, revision):
    global STAGE
    if os.geteuid() != 0:
        raise server.SetupError('Panel installation requires root.')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    values = validated_sources(sources, revision)
    public_parent()
    directory(server.CONFIG, 0o700)
    fd = os.open(server.CONFIG/'install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise server.SetupError('Unsafe installation lock.')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = runtime_identity()
        before_server_config = owned(VPN_CONFIG)
        _, desired_firewall = firewall_configuration()
        exists, position = live_rule(allow_legacy=True)
        legacy_handle = legacy_rule_handle()
        preflight_files(values)
        if port_in_use() and owned(CONFIG/'config.json', missing=True) != values[str(CONFIG/'config.json')]:
            raise server.SetupError('The panel port is already occupied; preserved unrelated listener.')
        _, gid = account()
        directory(CONFIG, 0o750, gid)
        directory(EXPORT, 0o700)
        directory(CODE)
        directory(CODE/'static')
        STAGE = 'private credentials'
        credentials(gid)
        STAGE = 'protected panel files'
        for path, content in values.items():
            write(path, content, 0o640 if path == str(CONFIG/'config.json') else 0o644,
                  gid if path == str(CONFIG/'config.json') else None)
        record = {'version': 1, 'source_commit': revision,
                  'files': {path: hashlib.sha256(content.encode()).hexdigest() for path, content in values.items()}}
        write(MANIFEST, json.dumps(record, sort_keys=True)+'\n', 0o600)
        STAGE = 'private panel startup'
        server.run(['/usr/bin/systemctl', 'daemon-reload'])
        server.run(['/usr/bin/systemctl', 'enable', *PANEL_UNITS])
        server.run(['/usr/bin/systemctl', 'restart', *PANEL_UNITS])
        deadline = time.monotonic()+20
        while not (listener_private() and http_ready()):
            if time.monotonic() >= deadline:
                raise server.SetupError('The private HTTP listener did not start.')
            time.sleep(.2)
        # Bind and authenticate the private web service before permitting packets.
        STAGE = 'VPN-only firewall exception'
        if not exists or legacy_handle is not None:
            command = ('insert rule inet vpn_lab input position '+str(position)+' '
                       +RULE.strip()+'\n')
            if legacy_handle is not None:
                command += 'delete rule inet vpn_lab input handle '+str(legacy_handle)+'\n'
            server.run(['/usr/sbin/nft', '--check', '-f', '-'], data=command)
            server.run(['/usr/sbin/nft', '-f', '-'], data=command)
        write(FIREWALL, desired_firewall)
        verified, _ = live_rule()
        active = [server.run(['/usr/bin/systemctl', 'is-active', unit]).strip() == 'active' for unit in PANEL_UNITS]
        preserved = runtime_identity() == before and owned(VPN_CONFIG) == before_server_config
        legacy_closed = not port_listeners(8443)
        if not verified or not preserved or not all(active) or not legacy_closed:
            raise server.SetupError('Panel post-install verification failed.')
        return validate_report({'version': 2, 'source_commit': revision, 'panel_url': URL,
            'web_service_active': active[1], 'collector_service_active': active[0], 'history_service_active': active[2],
            'vpn_runtime_preserved': preserved, 'firewall_rule_verified': verified,
            'vpn_only_listener': True, 'credential_contents_returned': False,
            'legacy_https_closed': legacy_closed, 'transport': 'http-over-vpn'})


if __name__ == '__main__':
    try:
        print(json.dumps(install(globals().get('ADMIN_SOURCES'), globals().get('SOURCE_REVISION')), sort_keys=True))
    except (server.SetupError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'error': 'setup_failed', 'detail': 'Panel installation failed during '+STAGE+'.'}))
        raise SystemExit(1)
