"""Actual key bootstrap, host pinning, SSH inventory and expiry rejection."""
import base64
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci'))
sys.path.insert(0, str(ROOT / 'ops'))
import lab_admin
import bootstrap_runner_key
import configure_download
import server_foundation


def main():
    if (os.environ.get('VPN_LAB_DISPOSABLE_SSH_TEST') != '1'
            or not Path('/.dockerenv').is_file() or os.geteuid() != 0):
        raise SystemExit('Run only through test_ssh_container.sh in its disposable container.')
    Path('/run/sshd').mkdir(exist_ok=True)
    # Test container only: enable its root account, while requiring public-key
    # authentication and disabling all password authentication in the daemon.
    subprocess.run(['/usr/bin/passwd', '-d', 'root'], check=True, capture_output=True)
    subprocess.run(['/usr/bin/ssh-keygen', '-A'], check=True, capture_output=True)
    configuration = Path('/run/vpn-lab-test-sshd.conf')
    configuration.write_text('''Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/vpn-lab-test-sshd.pid
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
    subprocess.run(['/usr/sbin/sshd', '-f', str(configuration)], check=True, capture_output=True)
    subprocess.run(['/usr/bin/python3', '-I', '-B', str(ROOT/'ops/bootstrap_runner_key.py')], check=True)
    key = Path('/root/.vpn-lab-actions/id_ed25519')
    original = key.read_text()
    host_blob = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[1]
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(host_blob)).digest()).decode().rstrip('=')
    settings = {'VPN_LAB_HOST':socket.gethostbyname(socket.gethostname()), 'VPN_LAB_PORT':'22',
                'VPN_LAB_HOST_FINGERPRINT':fingerprint, 'VPN_LAB_SSH_PRIVATE_KEY':original}
    lab_admin.execute('connectivity', settings)
    lab_admin.execute('inventory', settings)
    public = subprocess.check_output(['/usr/bin/ssh-keygen','-y','-f',str(key)], text=True)
    bootstrap_runner_key.authorize(Path('/root/.ssh'), public, '20000101000000Z')
    try:
        lab_admin.execute('inventory', settings)
    except lab_admin.LabError as exc:
        if 'SSH inventory failed' not in str(exc):
            raise
    else:
        raise SystemExit('Expired runner key was accepted.')
    subprocess.run(['/usr/bin/python3', '-I', '-B', str(ROOT/'ops/bootstrap_runner_key.py')], check=True)
    if key.read_text() != original:
        raise SystemExit('Renewal replaced the existing private key.')
    lab_admin.execute('inventory', settings)
    # A different client key gets only a chrooted, read-only SFTP view. The root
    # administrative key and its files must be inaccessible through that view.
    server_foundation.directory('/root/vpn-lab',0o700)
    server_foundation.write('/root/vpn-lab/client.ovpn','fixture profile\n')
    server_foundation.write('/root/vpn-lab/login.txt','vpn-lab-client\n'+'x'*43+'\n')
    private=Path('/run/download-client-key')
    subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(private)],
                   check=True,capture_output=True)
    configure_download.configure(private.with_suffix('.pub').read_text(),configuration,False)
    os.kill(int(Path('/run/vpn-lab-test-sshd.pid').read_text()),1)
    import time
    time.sleep(.5)
    known=Path('/run/download-known-hosts')
    known.write_text(settings['VPN_LAB_HOST']+' '+' '.join(Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[:2])+'\n')
    options=['-F','/dev/null','-i',str(private),'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
             '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),
             '-o','GlobalKnownHostsFile=/dev/null','-o','ConnectTimeout=5']
    target='vpn-lab-download@'+settings['VPN_LAB_HOST']
    def sftp(batch):
        return subprocess.run(['/usr/bin/sftp',*options,'-b','-',target],input=batch,
                              text=True,capture_output=True,timeout=15)
    result=sftp('get /files/client.ovpn /run/downloaded-profile\n')
    if result.returncode or Path('/run/downloaded-profile').read_text()!='fixture profile\n':
        # SFTP's normal diagnostic contains paths/status, never file contents.
        print('SFTP fixture diagnostic: '+result.stderr[:2000],flush=True)
        raise SystemExit('Read-only download did not return the selected fixture.')
    Path('/root/sftp-private-sentinel').write_text('DO NOT SHARE TEST SENTINEL')
    if sftp('get /root/sftp-private-sentinel /run/escaped\n').returncode==0 or Path('/run/escaped').exists():
        raise SystemExit('Download escaped its chroot.')
    if sftp('chmod 600 /files/client.ovpn\n').returncode==0:
        raise SystemExit('Read-only download allowed a file mutation.')
    shell=subprocess.run(['/usr/bin/ssh',*options,'-T',target,'id -u'],capture_output=True,timeout=10)
    if shell.stdout.strip().isdigit():
        raise SystemExit('Download key obtained a shell.')
    configure_download.revoke()
    if sftp('get /files/client.ovpn /run/after-revoke\n').returncode==0 or Path('/run/after-revoke').exists():
        raise SystemExit('Revoked download key was accepted.')
    if (configure_download.BASE/'files/client.ovpn').exists():
        raise SystemExit('Private export copy survived revocation.')
    lab_admin.execute('inventory', settings)
    print('PASS: real chrooted SFTP download, parent-file isolation, mutation refusal, no shell and revocation.')
    print('PASS: real SSH host pinning, root inventory, expired-key refusal and same-key renewal on Debian 13.')


if __name__ == '__main__':
    main()
