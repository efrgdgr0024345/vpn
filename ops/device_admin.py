"""Fixed root-only device revocation and independent VPN recovery operations."""
import json
import os
from pathlib import Path
import resource
import subprocess
import sys

if __name__ == '__main__':
    library = Path('/usr/local/libexec/vpn-lab/server_foundation.py')
    import stat
    for path in (*reversed(library.parents), library):
        info = path.lstat()
        if (info.st_uid != 0 or info.st_mode & 0o022 or not
                (stat.S_ISREG(info.st_mode) if path == library else stat.S_ISDIR(info.st_mode))):
            raise SystemExit('Installed administrator library is not protected.')
    sys.path.insert(0, str(library.parent))
import server_foundation as server


def administer(operation, device='kali'):
    if os.geteuid() != 0 or device not in ('kali', 'iphone', 'android'):
        raise server.SetupError('Device administration requires lab root and a fixed device name.')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    path = server.CONFIG/'devices.json'
    devices = json.loads(server.read_owned(path))
    if operation in ('revoke-device', 'enable-device'):
        devices[device]['enabled'] = operation == 'enable-device'
        server.write(path, json.dumps(devices, sort_keys=True)+'\n')
        if operation == 'revoke-device':
            # Invalidate outstanding export authorization and remove private
            # copies too; a revoked device cannot download an old profile.
            Path('/etc/ssh/vpn-lab-export.keys').unlink(missing_ok=True)
            for name in ('client.ovpn', 'login.txt'):
                Path('/var/lib/vpn-lab-export/files', name).unlink(missing_ok=True)
    elif operation == 'reset-sessions':
        # End forwarding first. A full service restart also changes OpenVPN's
        # in-memory token signing secret; no persistent token secret is used.
        server.run(['/usr/sbin/nft', 'flush', 'set', 'inet', 'vpn_lab', 'authorized'])
        server.run(['/usr/bin/systemctl', 'restart', 'openvpn-server@vpn-lab.service'])
    elif operation == 'reboot-lab':
        server.run(['/usr/bin/systemd-run', '--quiet', '--on-active=10s',
                    '--unit=vpn-lab-validation-reboot', '/usr/sbin/reboot'])
    elif operation != 'device-status':
        raise server.SetupError('Unsupported device operation.')
    return {'devices': {name: {'enabled': record['enabled'], 'certificate_sha256': record['sha256']}
                        for name, record in devices.items()},
            'session_reset': operation == 'reset-sessions',
            'reboot_scheduled': operation == 'reboot-lab', 'credential_contents_returned': False}


if __name__ == '__main__':
    try:
        print(json.dumps(administer(globals().get('DEVICE_OPERATION', ''),
                                   globals().get('DEVICE_NAME', 'kali')), sort_keys=True))
    except (server.SetupError, OSError, ValueError, KeyError, subprocess.SubprocessError):
        print(json.dumps({'error': 'setup_failed', 'detail': 'Device administration failed.'}))
        raise SystemExit(1)
