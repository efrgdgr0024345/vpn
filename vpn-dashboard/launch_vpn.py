#!/usr/bin/env python3
"""Run only inside a visible terminal. Authentication belongs to sudo/OpenVPN."""
import os
import fcntl
import stat
import subprocess
import tempfile
from pathlib import Path
import sys
from security import Refused, installed_command
from safe_io import bounded_run


def argv(action='connect'):
    if action not in ('connect','disconnect','network-restore'):
        raise Refused('Unsupported session action.')
    return installed_command(action)


def existing_openvpn():
    """Fail closed if a process check is unavailable. Never collects argv."""
    try:
        result = bounded_run(['/usr/bin/ps', '-C', 'openvpn', '-o', 'pid='],
                                capture_output=True, text=True, timeout=5, check=False,
                                env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise ValueError('Cannot inspect existing OpenVPN processes. No connection started.')
    if result.stderr.strip() or result.returncode not in (0, 1) or (result.returncode == 0 and not result.stdout.strip()):
        raise ValueError('Process inspection was inconclusive. No connection started.')
    return bool(result.stdout.strip())


def session_lock():
    directory = Path(tempfile.gettempdir()) / ('vpn-desk-' + str(os.getuid()))
    directory.mkdir(mode=0o700,exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Unsafe lock directory. No connection started.')
    fd = os.open(str(directory / 'session.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('Unsafe lock file. No connection started.')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        os.close(fd)
        raise ValueError('Another VPN Desk launch is active, or the lock is unsafe.')
    return fd


def main():
    if os.geteuid() == 0:
        print('Launch VPN Desk as your normal desktop user, not root.')
        return 1
    try:
        action=sys.argv[1] if len(sys.argv)==2 else 'connect'
        command = argv(action)
        if action in ('disconnect','network-restore'):
            return subprocess.call(command)
        lock = session_lock()
        if existing_openvpn():
            raise ValueError('An OpenVPN process already exists. Stop it in its original terminal first.')
    except (Refused, ValueError, OSError) as error:
        print(error)
        input('Press Enter to close. ')
        return 1
    print('VPN Desk: direct OpenVPN session. Enter credentials only in this terminal.')
    print('To disconnect THIS session: press Ctrl+C here. Do not close this terminal while connected.')
    print('The helper first closes/verifies the portal and locks out new portal actions for this session.\n', flush=True)
    # Keep the unprivileged lock owner alive while sudo owns the child terminal.
    process = subprocess.Popen(command)
    try:
        while True:
            try:
                return process.wait()
            except KeyboardInterrupt:
                # Ctrl+C goes to the terminal foreground process group, including
                # sudo/OpenVPN. Keep holding the lock until the child exits.
                continue
    finally:
        os.close(lock)

if __name__ == '__main__':
    sys.exit(main())
