#!/usr/bin/python3
"""Authorize a dedicated 24-hour GitHub runner key. Never print its private key."""
import argparse
import base64
import datetime
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

LABEL = 'vpn-lab-github-actions'


def check_directory(path, owner=0):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise RuntimeError('Expected an owned directory without links or group/other write access.')


def read_owned(path, owner=0, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1
                or info.st_mode & (0o077 if private else 0o022)):
            raise RuntimeError('Existing managed file has unsafe metadata.')
        value = stream.read(65537)
        if len(value) > 65536:
            raise RuntimeError('Existing managed file is oversized.')
        return value.decode('utf-8')


def authorize(directory, public, expires, remove_blob=None, owner=0):
    check_directory(directory, owner)
    fields = public.split()
    if len(fields) < 2 or fields[0] != 'ssh-ed25519' or not re.fullmatch(r'[A-Za-z0-9+/]+=*', fields[1]):
        raise RuntimeError('Expected an ED25519 public key.')
    if not re.fullmatch(r'[0-9]{14}Z', expires):
        raise RuntimeError('Expected a UTC key expiry timestamp.')
    target = directory / 'authorized_keys'
    try:
        before = read_owned(target, owner)
    except FileNotFoundError:
        before = ''
    remove = {fields[1]}
    if remove_blob:
        if not re.fullmatch(r'[A-Za-z0-9+/]+=*', remove_blob):
            raise RuntimeError('Invalid obsolete public-key blob.')
        remove.add(remove_blob)
    lines = [line for line in before.splitlines() if not remove.intersection(line.split())]
    lines.append('restrict,expiry-time="' + expires + '" ' + ' '.join(fields[:2]) + ' ' + LABEL)
    content = '\n'.join(lines) + '\n'
    fd, temporary = tempfile.mkstemp(prefix='.vpn-lab-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--remove-key-blob', help='Remove only this obsolete public key while preserving all others.')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run in the disposable droplet root console.')
    os.umask(0o077)
    for path in (Path('/'), Path('/root')):
        check_directory(path)
    directory = Path('/root/.vpn-lab-actions')
    directory.mkdir(mode=0o700, exist_ok=True)
    check_directory(directory)
    directory.chmod(0o700)
    ssh_directory = Path('/root/.ssh')
    ssh_directory.mkdir(mode=0o700, exist_ok=True)
    check_directory(ssh_directory)
    ssh_directory.chmod(0o700)
    lock_fd = os.open(directory / 'bootstrap.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'w') as lock:
        info = os.fstat(lock.fileno())
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
            raise RuntimeError('Unsafe bootstrap lock.')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        key = directory / 'id_ed25519'
        try:
            read_owned(key, private=True)
        except FileNotFoundError:
            if key.with_suffix('.pub').exists() or key.with_suffix('.pub').is_symlink():
                raise RuntimeError('Incomplete previous key setup; inspect it before continuing.')
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                            '-C', LABEL, '-f', str(key)], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=15, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            read_owned(key, private=True)
        result = subprocess.run(['/usr/bin/ssh-keygen', '-y', '-f', str(key)], check=True,
                                capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=10,
                                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        public = result.stdout.strip()
        expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)).strftime('%Y%m%d%H%M%SZ')
        authorize(ssh_directory, public, expires, args.remove_key_blob)
        blob = public.split()[1]
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip('=')
        print('Dedicated GitHub runner key authorized; expires at ' + expires + ' (UTC).')
        print('Public key fingerprint: ' + fingerprint)
        print('Private key file: ' + str(key))
        print('Copy its contents only into the vpn-lab environment secret VPN_LAB_SSH_PRIVATE_KEY, never chat or source control.')
        print('No VPN, firewall, package or SSH daemon configuration changed.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit('Runner-key bootstrap failed; private-key contents and raw command errors withheld.')
