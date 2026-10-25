#!/usr/bin/python3
"""Explicit reviewed installation only; no firewall/profile/account mutations."""
import fcntl
import os
from pathlib import Path
import stat

DESTINATION = Path('/usr/local/libexec/vpn-desk')
FILES = ('security.py', 'safe_io.py', 'portal_helper.py',
         'vpn_session_helper.py', 'privileged.py')


def check_directory(path):
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Installation requires root-owned non-writable directories without symlinks.')


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Review this installer, then explicitly invoke with sudo /usr/bin/python3 -I -B.')
    os.umask(0o077)
    source = Path(__file__).resolve().parent
    # Read complete reviewed sources before any destination mutation.
    contents = {name: (source / name).read_bytes() for name in FILES}
    for name, data in contents.items():
        compile(data, name, 'exec')
    fd = os.open('/run/vpn-dashboard-portal.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise RuntimeError('Unsafe runtime lock.')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_directory(DESTINATION.parent.parent)
        try:
            DESTINATION.parent.mkdir(mode=0o755)
            DESTINATION.parent.chmod(0o755)
        except FileExistsError:
            pass
        check_directory(DESTINATION.parent)
        # Never merge with, follow, or overwrite a pre-existing installation.
        DESTINATION.mkdir(mode=0o755)
        try:
            DESTINATION.chmod(0o755)
            check_directory(DESTINATION)
            for name, data in contents.items():
                temporary = DESTINATION / (name + '.new')
                output = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
                with os.fdopen(output, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary.chmod(0o644)
                os.replace(temporary, DESTINATION / name)
        except BaseException:
            # Only files created by this invocation can be present here.
            for name in FILES:
                (DESTINATION / name).unlink(missing_ok=True)
                (DESTINATION / (name + '.new')).unlink(missing_ok=True)
            DESTINATION.rmdir()
            raise
    print('Installed protected helpers. No sudoers rule, profile, account or firewall was changed.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError) as error:
        raise SystemExit('Installation refused: ' + str(error))
