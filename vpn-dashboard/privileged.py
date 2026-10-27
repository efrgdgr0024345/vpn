#!/usr/bin/python3
"""Installed entry point. Start only using the system Python with -I -B."""
import os
import resource
from pathlib import Path
import stat
import sys

ROOT = Path('/usr/local/libexec/vpn-desk')
FILES = ('privileged.py', 'security.py', 'safe_io.py', 'portal_helper.py', 'vpn_session_helper.py','session_channel.py','network_setup.py','firewall_policy.py')


def verify_installation():
    if not sys.flags.isolated or Path(__file__) != ROOT / 'privileged.py':
        raise RuntimeError('Use the installed helper with /usr/bin/python3 -I -B.')
    # No project imports until all code and ancestor directories are trusted.
    for name in FILES:
        path = ROOT / name
        for current in (*reversed(path.parents), path):
            info = current.lstat()
            regular = stat.S_ISREG(info.st_mode) if current == path else stat.S_ISDIR(info.st_mode)
            if info.st_uid != 0 or info.st_mode & 0o022 or not regular:
                raise RuntimeError('Unsafe helper installation; refusing privileged execution.')
    if os.geteuid() != 0:
        raise RuntimeError('Explicit sudo authorization is required.')


def main():
    try:
        verify_installation()
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        if len(sys.argv) != 2 or sys.argv[1] not in ('connect','disconnect','network-restore', 'portal-close', 'portal-status'):
            raise RuntimeError('Unsupported action; portal opening is disabled.')
        os.chdir('/')
        os.umask(0o077)
        owner_uid=int(os.environ.get('SUDO_UID','0'))
        os.environ.clear()
        os.environ.update(PATH='/usr/sbin:/usr/bin', LC_ALL='C')
        sys.path.insert(0, str(ROOT))
        if sys.argv[1] == 'connect':
            import vpn_session_helper
            return vpn_session_helper.main(owner_uid)
        if sys.argv[1] == 'disconnect':
            import session_channel
            print(session_channel.request('stop'),flush=True)
            return 0
        if sys.argv[1]=='network-restore':
            import network_setup
            import json
            import fcntl
            fd=os.open('/run/vpn-dashboard-portal.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w') as lock:
                info=os.fstat(lock.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:
                    raise RuntimeError('Unsafe action lock.')
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                print(json.dumps(network_setup.restore()),flush=True)
            return 0
        import portal_helper
        return portal_helper.main(sys.argv[1].removeprefix('portal-'))
    except (OSError, RuntimeError) as error:
        print('Action refused: ' + str(error), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
