"""Install the single-account OpenVPN lab foundation on disposable Debian 13."""
import argparse
import fcntl
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import stat
import subprocess
import tempfile

CONFIG = Path('/etc/openvpn/lab')
EXPORT = Path('/root/vpn-lab')
PKI = CONFIG / 'pki'
CLIENT = 'vpn-lab-client'
TRANSPORT = 'vpn-lab-transport'
POOL = '172.27.240.0/24'
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C',
       'DEBIAN_FRONTEND':'noninteractive', 'NEEDRESTART_MODE':'a'}
for _proxy_name in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY',
                    'http_proxy','https_proxy','all_proxy','no_proxy'):
    if _proxy_name in os.environ:
        ENV[_proxy_name]=os.environ[_proxy_name]
STAGE = 'preflight'


class SetupError(RuntimeError):
    pass


def run(argv, data=None, timeout=120, environment=None):
    # Never let subprocess exceptions print password-bearing input or dump raw
    # command output. Package/tool output stays in an anonymous private file.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, input=None if data is None else data.encode(),
                                stdout=output, stderr=subprocess.STDOUT, timeout=timeout,
                                env=ENV if environment is None else environment)
        if result.returncode:
            raise SetupError('Command failed during ' + STAGE + '; exit ' + str(result.returncode))
        output.seek(0)
        value = output.read(2_000_001)
        if len(value) > 2_000_000:
            raise SetupError('Command output exceeded the setup limit.')
        return value.decode('utf-8')


def directory(path, mode=0o755):
    path = Path(path)
    if path != path.parent:
        directory(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=mode)
        info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SetupError('Managed directory ownership/type/permissions are unsafe.')
    if mode == 0o700:
        path.chmod(mode)


def read_owned(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or info.st_mode & 0o022):
            raise SetupError('Managed file ownership/type/permissions are unsafe.')
        value = stream.read(2_000_001)
        if len(value) > 2_000_000:
            raise SetupError('Managed file is oversized.')
        return value.decode('utf-8')


def write(path, value, mode=0o600):
    path = Path(path)
    directory(path.parent)
    try:
        read_owned(path)
    except FileNotFoundError:
        pass
    fd, temporary = tempfile.mkstemp(prefix='.vpn-lab-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def validate(endpoint, ssh_port, interface):
    address = ipaddress.IPv4Address(endpoint)
    if address.is_loopback or address.is_multicast or address.is_unspecified or endpoint == '255.255.255.255':
        raise SetupError('Invalid lab endpoint.')
    if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
        raise SetupError('Invalid recovery SSH port.')
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}', interface) or interface == 'lo':
        raise SetupError('Invalid external interface.')


def firewall(interface, ssh_port):
    validate('192.0.2.10', ssh_port, interface)
    return f'''flush ruleset
table inet vpn_lab {{
 set nonpublic {{
  type ipv4_addr; flags interval;
  elements = {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
   169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
   192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
   224.0.0.0/4, 240.0.0.0/4 }}
 }}
 set authorized {{ type ipv4_addr; flags timeout; timeout 20s; size 1; }}
 chain input {{
  type filter hook input priority 0; policy drop;
  iifname "lo" accept
  iifname "tun-lab" counter drop comment "vpn-lab-block-host"
  ct state invalid drop
  ct state established,related accept
  iifname "{interface}" tcp dport {ssh_port} accept
  iifname "{interface}" udp dport 1194 accept
  iifname "{interface}" udp sport 67 udp dport 68 accept
  iifname "{interface}" udp sport 547 udp dport 546 accept
  iifname "{interface}" ip protocol icmp accept
  iifname "{interface}" meta l4proto ipv6-icmp accept
 }}
 chain forward {{
  type filter hook forward priority 0; policy drop;
  ct state invalid drop
  iifname "tun-lab" meta nfproto ipv6 counter drop comment "vpn-lab-block-ipv6"
  iifname "tun-lab" ip daddr @nonpublic counter drop comment "vpn-lab-block-private"
  iifname "tun-lab" oifname "{interface}" ip saddr @authorized ct state new,established,related counter accept
  iifname "{interface}" oifname "tun-lab" ip daddr @authorized ct state established,related counter accept
 }}
 chain output {{ type filter hook output priority 0; policy accept; }}
}}
table ip vpn_lab_nat {{
 chain postrouting {{
  type nat hook postrouting priority srcnat; policy accept;
  oifname "{interface}" ip saddr {POOL} masquerade
 }}
}}
'''


def server_configuration(plugin):
    if not re.fullmatch(r'/usr/lib/(?:[A-Za-z0-9_-]+/)*openvpn/(?:plugins/)?openvpn-plugin-auth-pam\.so', plugin):
        raise SetupError('Unexpected PAM plugin location.')
    return f'''port 1194
proto udp4
dev tun-lab
topology subnet
server 172.27.240.0 255.255.255.0
server-ipv6 fd47:27:240::/64
ca {PKI}/ca.crt
cert {PKI}/issued/VPNLabServer.crt
key {PKI}/private/VPNLabServer.key
dh none
tls-crypt {CONFIG}/tls-crypt.key
crl-verify /etc/openvpn/server/vpn-lab-crl.pem
remote-cert-tls client
verify-client-cert require
plugin {plugin} vpn-lab
management /run/openvpn-server/vpn-lab.management unix
management-client-user root
management-client-auth
management-hold
management-signal
tls-version-min 1.3
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
allow-compression no
auth SHA256
auth-gen-token 86400 120
reneg-sec 120
max-clients 1
keepalive 10 60
persist-key
persist-tun
user {TRANSPORT}
group {TRANSPORT}
push "redirect-gateway def1 ipv6"
push "block-ipv6"
push "dhcp-option DNS 9.9.9.9"
push "dhcp-option DNS 149.112.112.112"
verb 3
'''


def client_configuration(endpoint, cn=CLIENT, portable=False):
    validate(endpoint, 22, 'eth0')
    lines = f'''client
dev {'tun' if portable else 'tun0'}
proto udp
remote {endpoint} 1194
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name VPNLabServer name
tls-version-min 1.3
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
auth-user-pass
auth-nocache
mssfix 1300
verb 3
'''
    for name, path in (('ca', PKI/'ca.crt'), ('cert', PKI/'issued'/f'{cn}.crt'),
                       ('key', PKI/'private'/f'{cn}.key'), ('tls-crypt', CONFIG/'tls-crypt.key')):
        value = read_owned(path)
        if name in ('ca', 'cert'):
            begin, end = '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'
            value = value[value.index(begin):value.index(end)+len(end)]
        lines += '<'+name+'>\n'+value.strip()+'\n</'+name+'>\n'
    return lines


def enroll_devices(endpoint):
    """Administrator-only enrollment; never reachable through VPN credentials."""
    target = CONFIG/'devices.json'
    previous = json.loads(read_owned(target)) if target.exists() else {}
    devices = {}
    for index, name in enumerate(('kali', 'iphone', 'android')):
        cn = CLIENT if name == 'kali' else 'vpn-lab-'+name
        cert = PKI/'issued'/f'{cn}.crt'
        if not cert.exists():
            easyrsa('build-client-full', cn, 'nopass')
        run(['/usr/bin/openssl','verify','-CAfile',str(PKI/'ca.crt'),'-purpose','sslclient',str(cert)])
        fingerprint = run(['/usr/bin/openssl','x509','-in',str(cert),'-noout','-fingerprint','-sha256'])
        digest = fingerprint.strip().split('=',1)[-1].replace(':','').lower()
        if not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise SetupError('Invalid enrolled certificate fingerprint.')
        device = {'cn':cn,'sha256':digest,'address':'172.27.240.'+str(10+index),
                  'enabled':previous.get(name,{}).get('enabled',True)}
        if name in previous and any(previous[name].get(k)!=device[k] for k in ('cn','sha256','address')):
            raise SetupError('Existing device identity differs; review replacement explicitly.')
        devices[name] = device
        destination = EXPORT/'devices'/name
        directory(destination,0o700)
        write(destination/'client.ovpn',client_configuration(endpoint,cn,portable=name!='kali'))
        write(destination/'login.txt',read_owned(EXPORT/'login.txt'))
    write(target,json.dumps(devices,sort_keys=True)+'\n')
    return devices


def account(name):
    try:
        value = pwd.getpwnam(name)
    except KeyError:
        run(['/usr/sbin/useradd','--system','--user-group','--home-dir','/nonexistent',
             '--no-create-home','--shell','/usr/sbin/nologin',name])
        value = pwd.getpwnam(name)
    group = grp.getgrnam(name)
    if (value.pw_uid <= 0 or value.pw_gid <= 0 or value.pw_gid != group.gr_gid
            or value.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin','/bin/false')
            or set(os.getgrouplist(name,value.pw_gid)) != {value.pw_gid}):
        raise SetupError('A managed service-account name conflicts with an existing account.')


def easyrsa(*arguments):
    environment = {**ENV, 'EASYRSA_BATCH':'1', 'EASYRSA_PKI':str(PKI),
                   'EASYRSA_ALGO':'ec', 'EASYRSA_CURVE':'secp384r1',
                   'EASYRSA_DIGEST':'sha384', 'EASYRSA_CA_EXPIRE':'3650',
                   'EASYRSA_CERT_EXPIRE':'90', 'EASYRSA_CRL_DAYS':'365'}
    if arguments and arguments[0]=='build-ca':
        environment['EASYRSA_REQ_CN']='VPNLabCA'
    return run(['/usr/share/easy-rsa/easyrsa',*arguments], environment=environment)


def retire_old_runners():
    global STAGE
    names = run(['/usr/bin/systemctl','list-unit-files','--type=service','--no-legend',
                 '--no-pager','actions.runner.*.service'])
    count = 0
    for line in names.splitlines():
        fields=line.split()
        unit = fields[0]
        if not re.fullmatch(r'actions\.runner\.[A-Za-z0-9_.@-]+\.service',unit):
            raise SetupError('Unexpected runner service name.')
        if len(fields)>1 and fields[1]=='masked':
            continue
        STAGE='old runner inspection'
        work=run(['/usr/bin/systemctl','show','--property=WorkingDirectory','--value',unit]).strip()
        # Stop every process in the old runner cgroup, including worker children.
        subprocess.run(['/usr/bin/systemctl','kill','--kill-whom=all','--signal=SIGTERM',unit],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,env=ENV)
        STAGE='old runner stop'
        run(['/usr/bin/systemctl','stop',unit])
        STAGE='old runner disable'
        run(['/usr/bin/systemctl','disable',unit])
        STAGE='old runner registration cleanup'
        path=Path(work)
        if path.is_absolute() and len(path.parts)>=3:
            safe=True
            for parent in (*reversed(path.parents),path):
                try:
                    info=parent.lstat()
                except FileNotFoundError:
                    safe=False
                    break
                if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
                    safe=False
                    break
            if safe:
                # Erase obsolete runner registration material by metadata only;
                # never read, print or transfer its credential contents.
                for name in ('.credentials','.credentials_rsaparams','.runner'):
                    target=path/name
                    try:
                        info=target.lstat()
                    except FileNotFoundError:
                        continue
                    if stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1:
                        target.unlink()
        # mask cannot replace a regular unit file in /etc/systemd/system.
        source = Path('/etc/systemd/system')/unit
        STAGE='old runner unit cleanup'
        remove_runner_unit(source)
        run(['/usr/bin/systemctl','daemon-reload'])
        STAGE='old runner mask'
        run(['/usr/bin/systemctl','mask',unit])
        count += 1
    return count


def remove_runner_unit(path):
    try:
        info=path.lstat()
    except FileNotFoundError:
        return
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
        raise SetupError('Unexpected old runner unit file type.')
    # Deleting the directory entry never follows its target. Its controlled
    # /etc/systemd/system parent is trusted; old file content need not be read.
    path.unlink()


def deny_vpn_accounts_ssh():
    # A nologin shell alone does not prevent SSH forwarding/SFTP. Deny these
    # accounts at sshd while preserving the existing administrator configuration.
    target=Path('/etc/ssh/sshd_config')
    before=read_owned(target)
    rule='DenyUsers '+CLIENT+' '+TRANSPORT
    content=before if rule in before.splitlines() else rule+'\n'+before
    candidate=Path('/etc/ssh/sshd_config.vpn-lab-candidate')
    write(candidate,content)
    try:
        run(['/usr/sbin/sshd','-t','-f',str(candidate)])
        effective=run(['/usr/sbin/sshd','-T','-f',str(candidate)])
        denied={name for line in effective.splitlines() if line.startswith('denyusers ')
                for name in line.split()[1:]}
        if not {CLIENT,TRANSPORT}<=denied:
            raise SetupError('VPN credential accounts must be denied SSH.')
        backup=EXPORT/'recovery/sshd_config.before'
        if not backup.exists():
            write(backup,before)
        write(target,content,0o644)
        run(['/usr/bin/systemctl','reload','ssh.service'])
    finally:
        candidate.unlink(missing_ok=True)


def install(endpoint, ssh_port, container_test=False):
    global STAGE
    if os.geteuid() != 0:
        raise SetupError('Installation requires root on the disposable lab server.')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    release = Path('/etc/os-release').read_text()
    if not re.search(r'^ID=debian$',release,re.M) or not re.search(r'^VERSION_ID="?13"?$',release,re.M):
        raise SetupError('This installer is tested for Debian 13 only.')
    if container_test and (not Path('/.dockerenv').is_file() or os.environ.get('VPN_LAB_DISPOSABLE_SERVER_TEST')!='1'):
        raise SetupError('Container test mode is restricted to the disposable test harness.')
    validate(endpoint,ssh_port,'preflight')
    os.umask(0o077)
    directory(CONFIG,0o700)
    directory(EXPORT,0o700)
    lock_fd = os.open(CONFIG/'install.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(lock_fd,'w') as lock:
        info=os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:
            raise SetupError('Unsafe installer lock.')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        STAGE='distribution packages'
        run(['/usr/bin/apt-get','update'],timeout=600)
        run(['/usr/bin/apt-get','install','--yes','--no-install-recommends',
             'openvpn','easy-rsa','openssl','nftables','iproute2','passwd','ca-certificates'],timeout=900)
        routes=json.loads(run(['/usr/sbin/ip','-j','-4','route','show']))
        defaults=[r for r in routes if r.get('dst')=='default' and r.get('dev')]
        if len(defaults)!=1:
            raise SetupError('Expected one IPv4 default interface.')
        interface=defaults[0]['dev']
        validate(endpoint,ssh_port,interface)
        for route in routes:
            if route.get('dst') and route['dst']!='default' and route.get('dev')!='tun-lab':
                if ipaddress.ip_network(route['dst'],strict=False).overlaps(ipaddress.ip_network(POOL)):
                    raise SetupError('VPN subnet conflicts with an existing route.')
        marker=CONFIG/'state.json'
        if marker.exists():
            state=json.loads(read_owned(marker))
            if state.get('endpoint')!=endpoint or state.get('ssh_port')!=ssh_port:
                raise SetupError('Existing lab deployment settings differ; review migration separately.')
        STAGE='retiring obsolete runner services'
        retired=0 if container_test else retire_old_runners()
        STAGE='dedicated accounts and PAM'
        account(TRANSPORT)
        account(CLIENT)
        login=EXPORT/'login.txt'
        if not login.exists():
            password=secrets.token_urlsafe(32)
            run(['/usr/sbin/chpasswd'],data=CLIENT+':'+password+'\n')
            write(login,CLIENT+'\n'+password+'\n')
        else:
            values=read_owned(login).splitlines()
            if len(values)!=2 or values[0]!=CLIENT or len(values[1])<40:
                raise SetupError('Stored VPN credential file is invalid.')
            login.chmod(0o600)
        write(CONFIG/'allowed-users',CLIENT+'\n')
        write('/etc/pam.d/vpn-lab',f'''auth requisite pam_listfile.so item=user sense=allow file={CONFIG}/allowed-users onerr=fail
auth required pam_unix.so
account required pam_unix.so
''',0o644)
        STAGE='PKI and protected profiles'
        if not PKI.exists():
            easyrsa('init-pki')
        if not (PKI/'ca.crt').exists():
            easyrsa('build-ca','nopass')
        if not (PKI/'issued/VPNLabServer.crt').exists():
            easyrsa('build-server-full','VPNLabServer','nopass')
        if not (PKI/'issued'/f'{CLIENT}.crt').exists():
            easyrsa('build-client-full',CLIENT,'nopass')
        easyrsa('gen-crl')
        for name,purpose in (('VPNLabServer','sslserver'),(CLIENT,'sslclient')):
            run(['/usr/bin/openssl','verify','-CAfile',str(PKI/'ca.crt'),'-purpose',purpose,
                 str(PKI/'issued'/f'{name}.crt')])
            subject=run(['/usr/bin/openssl','x509','-in',str(PKI/'issued'/f'{name}.crt'),
                         '-noout','-subject','-nameopt','RFC2253']).strip()
            if subject!='subject=CN='+name:
                raise SetupError('The issued certificate has an unexpected identity.')
        control=CONFIG/'tls-crypt.key'
        if not control.exists():
            run(['/usr/sbin/openvpn','--genkey','tls-crypt',str(control)])
        read_owned(control)
        control.chmod(0o600)
        candidates=sorted({str(Path(line).resolve(strict=True))
                           for line in run(['/usr/bin/dpkg','-L','openvpn']).splitlines()
                           if line.endswith('/openvpn-plugin-auth-pam.so')})
        if len(candidates)!=1:
            raise SetupError('Expected one distribution PAM plugin.')
        directory('/etc/openvpn/server')
        write('/etc/openvpn/server/vpn-lab.conf',server_configuration(candidates[0]))
        write('/etc/openvpn/server/vpn-lab-crl.pem',read_owned(PKI/'crl.pem'),0o644)
        write(EXPORT/'client.ovpn',client_configuration(endpoint))
        enroll_devices(endpoint)
        broker=globals().get('BROKER_SOURCE')
        if not broker:
            broker=read_owned(Path(__file__).resolve().with_name('session_broker.py'))
        write('/usr/local/libexec/vpn-lab/session_broker.py',broker,0o644)
        selftest=globals().get('SELFTEST_SOURCE')
        if not selftest:
            candidate=Path(__file__).resolve().with_name('server_selftest.py')
            selftest=read_owned(candidate)
        write('/usr/local/libexec/vpn-lab/server_selftest.py',selftest,0o644)
        own_source=globals().get('FOUNDATION_SOURCE')
        if not own_source:
            own_source=read_owned(Path(__file__).resolve())
        write('/usr/local/libexec/vpn-lab/server_foundation.py',own_source,0o644)
        notices=globals().get('NOTICES_SOURCE')
        if notices:
            write('/usr/local/share/doc/vpn-lab/THIRD_PARTY_NOTICES.md',notices,0o644)
        versions=run(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\n',
                      'openvpn','easy-rsa','openssl','nftables','libpam-modules','python3'])
        write('/usr/local/share/doc/vpn-lab/package-versions.txt',versions,0o644)
        STAGE='firewall validation and recovery snapshot'
        candidate=CONFIG/'nftables.candidate'
        write(candidate,firewall(interface,ssh_port))
        run(['/usr/sbin/nft','--check','--file',str(candidate)])
        directory(EXPORT/'recovery',0o700)
        backup=EXPORT/'recovery/nftables.before'
        if not backup.exists():
            write(backup,'flush ruleset\n'+run(['/usr/sbin/nft','list','ruleset']))
        STAGE='applying lab firewall'
        write('/etc/nftables.conf',read_owned(candidate))
        run(['/usr/sbin/nft','--file','/etc/nftables.conf'])
        if not container_test:
            STAGE='persistent service setup'
            deny_vpn_accounts_ssh()
            write('/etc/sysctl.d/70-vpn-lab.conf','''net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.forwarding=0
''',0o644)
            run(['/usr/sbin/sysctl','-p','/etc/sysctl.d/70-vpn-lab.conf'])
            write('/etc/systemd/system/openvpn-server@vpn-lab.service.d/hardening.conf','''[Unit]
Wants=vpn-lab-broker.service
After=nftables.service

[Service]
Restart=on-failure
RestartSec=3s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/run/openvpn-server
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LockPersonality=yes
RestrictRealtime=yes
LimitCORE=0
UMask=0077
''',0o644)
            write('/etc/systemd/system/vpn-lab-broker.service','''[Unit]
Description=Single-session VPN authorization broker
After=nftables.service
PartOf=openvpn-server@vpn-lab.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -I -B /usr/local/libexec/vpn-lab/session_broker.py
Restart=on-failure
RestartSec=2
RuntimeDirectory=vpn-lab-control
RuntimeDirectoryMode=0700
UMask=0077
LimitCORE=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/vpn-lab-control
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_UNIX AF_NETLINK
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
''',0o644)
            run(['/usr/bin/systemctl','daemon-reload'])
            run(['/usr/bin/systemctl','enable','nftables.service','vpn-lab-broker.service','openvpn-server@vpn-lab.service'])
            run(['/usr/bin/systemctl','restart','openvpn-server@vpn-lab.service'])
            run(['/usr/bin/systemctl','is-active','--quiet','openvpn-server@vpn-lab.service'])
        revision=globals().get('DEPLOYED_REVISION','local-test')
        write(marker,json.dumps({'version':1,'endpoint':endpoint,'ssh_port':ssh_port,
                                 'source_commit':revision},sort_keys=True)+'\n')
        return {'version':1,'server_service_active':not container_test,
                'vpn_udp_port':1194,'recovery_ssh_port':ssh_port,
                'max_clients':1,'required_factors':['client certificate','PAM password'],
                'retired_runner_services':retired,'client_profile':str(EXPORT/'client.ovpn'),
                'credential_file':str(login),'staged_login_implemented':True,'source_commit':revision}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint',required=True)
    parser.add_argument('--ssh-port',type=int,default=22)
    parser.add_argument('--container-test',action='store_true')
    args=parser.parse_args()
    print(json.dumps(install(args.endpoint,args.ssh_port,args.container_test),sort_keys=True))


if __name__=='__main__':
    try:
        main()
    except (SetupError,OSError,ValueError,KeyError,subprocess.SubprocessError):
        print(json.dumps({'error':'setup_failed','detail':'Setup failed during '+STAGE+'.'}))
        raise SystemExit(1)
