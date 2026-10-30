"""Synthetic HTTPS and SSH peer; only in an unexposed disposable container."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys


def run(argv):
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def main():
    if os.geteuid()!=0 or not Path('/.dockerenv').exists():
        raise SystemExit('Use only the disposable peer fixture.')
    os.umask(0o077)
    if sys.argv[1:] in (['prepare'],['proxy']):
        # SSH deliberately drops the Docker environment. Keep the disposable
        # runner's required package proxy in a private apt fixture, not reports.
        proxy=os.environ.get('http_proxy') or os.environ.get('HTTP_PROXY')
        if proxy:
            if not proxy.isascii() or any(ord(char)<32 for char in proxy):
                raise SystemExit('Unsupported fixture proxy.')
            target=Path('/etc/apt/apt.conf.d/90-vpn-peer-fixture-proxy')
            target.write_text('Acquire::http::Proxy '+json.dumps(proxy)+';\n'
                              'Acquire::https::Proxy '+json.dumps(proxy)+';\n')
            target.chmod(0o600)
        if sys.argv[1:]==['proxy']:
            return
    if sys.argv[1:] == ['prepare']:
        Path('/dev/net').mkdir(exist_ok=True)
        if not Path('/dev/net/tun').exists():
            import stat
            os.mknod('/dev/net/tun',stat.S_IFCHR|0o600,os.makedev(10,200))
        Path('/run/sshd').mkdir(exist_ok=True)
        run(['/usr/bin/passwd','-d','root'])
        run(['/usr/bin/ssh-keygen','-A'])
        configuration=Path('/run/peer-sshd.conf')
        configuration.write_text('''Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/peer-sshd.pid
PermitRootLogin prohibit-password
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes yes
AuthorizedKeysFile .ssh/authorized_keys
AllowTcpForwarding no
X11Forwarding no
''')
        run(['/usr/sbin/sshd','-f',str(configuration)])
        base=Path('/run/peer-https')
        base.mkdir(mode=0o700)
        run(['/usr/bin/openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
             '-nodes','-keyout',str(base/'ca.key'),'-out',str(base/'ca.crt'),'-days','1',
             '-subj','/CN=VPN peer fixture CA','-addext','basicConstraints=critical,CA:TRUE',
             '-addext','keyUsage=critical,keyCertSign,cRLSign'])
        run(['/usr/bin/openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
             '-nodes','-keyout',str(base/'server.key'),'-out',str(base/'server.csr'),'-subj','/CN=example.com'])
        (base/'extensions').write_text('subjectAltName=DNS:example.com\nbasicConstraints=critical,CA:FALSE\n'
                                       'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
        run(['/usr/bin/openssl','x509','-req','-in',str(base/'server.csr'),'-CA',str(base/'ca.crt'),
             '-CAkey',str(base/'ca.key'),'-set_serial','1','-days','1','-extfile',str(base/'extensions'),
             '-out',str(base/'server.crt')])
        trust=Path('/usr/local/share/ca-certificates/vpn-peer-fixture.crt')
        trust.write_bytes((base/'ca.crt').read_bytes())
        trust.chmod(0o644)
        run(['/usr/sbin/update-ca-certificates'])
        return
    if sys.argv[1:] == ['authorize']:
        sys.path.insert(0,'/test/ops')
        import bootstrap_runner_key as bootstrap
        import prepare_test_access
        import datetime
        value=prepare_test_access.validate_report(json.loads(sys.stdin.read(4097)))
        directory=Path('/root/.ssh')
        directory.mkdir(mode=0o700,exist_ok=True)
        expires=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).strftime('%Y%m%d%H%M%SZ')
        bootstrap.authorize(directory,value['ssh_public_key'],expires)
        blob=Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[1]
        print('SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip('='))
        return
    if sys.argv[1:] != ['https']:
        raise SystemExit('Unknown fixture mode.')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/run/peer-https/server.crt','/run/peer-https/server.key')
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server.bind(('93.184.216.34',443))
        server.listen(8)
        while True:
            connection,_=server.accept()
            try:
                connection.settimeout(5)
                with context.wrap_socket(connection,server_side=True) as channel:
                    channel.recv(8192)
                    channel.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            except (OSError,ssl.SSLError):
                connection.close()


if __name__=='__main__':
    main()
