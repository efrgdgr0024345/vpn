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
    print('PASS: real SSH host pinning, root inventory, expired-key refusal and same-key renewal on Debian 13.')


if __name__ == '__main__':
    main()
