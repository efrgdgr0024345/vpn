#!/usr/bin/python3
"""Prepare a dedicated server-retained SSH test identity; emit public data only."""
import base64
import binascii
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import stat
import subprocess
import time

ROOT = Path('/root')
DIRECTORY_NAME = '.vpn-lab-external-test'
KEY_NAME = 'id_ed25519'
COMMENT = 'vpn-lab-external-test'
ROOT_UID = 0
KEYGEN = '/usr/bin/ssh-keygen'
ENVIRONMENT = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
REPORT_KEYS = {'ssh_public_key', 'ssh_public_key_fingerprint', 'private_key_retained_on_server'}
WIRE_PREFIX = b'\0\0\0\x0bssh-ed25519\0\0\0\x20'


class AccessError(RuntimeError):
    pass


def directory_check(path, *, private=False):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID
            or info.st_mode & 0o022 or private and stat.S_IMODE(info.st_mode) != 0o700):
        raise AccessError('Unprotected test identity directory.')


def trusted_root():
    for path in (*reversed(ROOT.parents), ROOT):
        directory_check(path)
    return ROOT


def file_check(path, *, public=False):
    info = path.lstat()
    modes = (0o600, 0o644) if public else (0o600,)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in modes or info.st_size > (4096 if public else 16384)):
        raise AccessError('Unprotected or unsupported test identity file.')
    return info


def public_read(path):
    before = file_check(path, public=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        current = os.fstat(stream.fileno())
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise AccessError('Test identity file changed during validation.')
        value = stream.read(4097)
    if len(value) > 4096:
        raise AccessError('Unsupported public key output.')
    try:
        return value.decode('ascii')
    except UnicodeError:
        raise AccessError('Unsupported public key output.') from None


def canonical_public(value, *, comment=False):
    pattern = r'ssh-ed25519 ([A-Za-z0-9+/]{68})'
    if comment:
        pattern += r'(?: '+COMMENT+r')?\n?'
    match = re.fullmatch(pattern, value) if isinstance(value, str) else None
    if match is None:
        raise ValueError('Unsupported public test identity.')
    try:
        wire = base64.b64decode(match[1], validate=True)
    except (ValueError, binascii.Error):
        raise ValueError('Unsupported public test identity.') from None
    if len(wire) != 51 or not wire.startswith(WIRE_PREFIX) or base64.b64encode(wire).decode('ascii') != match[1]:
        raise ValueError('Unsupported public test identity.')
    return 'ssh-ed25519 '+match[1], wire


def validate_report(value):
    if not isinstance(value, dict) or set(value) != REPORT_KEYS or value['private_key_retained_on_server'] is not True:
        raise ValueError('Unsupported public test identity report.')
    public, wire = canonical_public(value['ssh_public_key'])
    fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(wire).digest()).decode('ascii').rstrip('=')
    if value['ssh_public_key'] != public or value['ssh_public_key_fingerprint'] != fingerprint:
        raise ValueError('Unsupported public test identity report.')
    return value


def keygen(argv, *, limit=4096):
    """Fixed distribution binary, bounded output/deadline, no stderr retention."""
    process = None
    try:
        process = subprocess.Popen([KEYGEN, *argv], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENVIRONMENT)
        deadline = time.monotonic()+10
        result = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline-time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise AccessError('SSH identity command did not finish.')
                part = os.read(process.stdout.fileno(), min(8192, limit+1-len(result)))
                if not part:
                    break
                result.extend(part)
                if len(result) > limit:
                    raise AccessError('Unsupported public key output.')
        if process.wait(timeout=max(.001, deadline-time.monotonic())):
            raise AccessError('SSH identity command failed.')
        return result.decode('ascii')
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise AccessError('SSH identity command failed.') from None
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            process.stdout.close()


def cleanup_created(keys):
    # Only files absent at this call's preflight may be removed on failure.
    # Unexpected metadata is preserved for root review, never followed/chmodded.
    for path, public in keys:
        if not path.exists() and not path.is_symlink():
            continue
        try:
            file_check(path, public=public)
        except (OSError, AccessError):
            continue
        path.unlink()


def prepare():
    if os.geteuid() != 0:
        raise AccessError('Test identity preparation requires root.')
    root = trusted_root()
    directory = root/DIRECTORY_NAME
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    directory_check(directory, private=True)
    lock = directory/'prepare.lock'
    if lock.exists() or lock.is_symlink():
        file_check(lock)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+b') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise AccessError('Unprotected test identity lock.')
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AccessError('Another test identity setup is active.') from None
        if set(path.name for path in directory.iterdir())-{'prepare.lock', KEY_NAME, KEY_NAME+'.pub'}:
            raise AccessError('Unexpected test identity directory contents.')
        private = directory/KEY_NAME
        public = directory/(KEY_NAME+'.pub')
        present = [path.exists() or path.is_symlink() for path in (private, public)]
        if any(present) and not all(present):
            raise AccessError('Incomplete existing test identity; review it locally.')
        generated = not any(present)
        previous_umask = os.umask(0o077)
        try:
            if generated:
                keygen(['-q', '-t', 'ed25519', '-N', '', '-C', COMMENT, '-f', str(private)])
            file_check(private)
            stored, _ = canonical_public(public_read(public), comment=True)
            derived, wire = canonical_public(keygen(['-y', '-P', '', '-f', str(private)]), comment=True)
            if stored != derived:
                raise AccessError('Existing public and private test identities do not match.')
            fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(wire).digest()).decode('ascii').rstrip('=')
            return validate_report({'ssh_public_key': derived, 'ssh_public_key_fingerprint': fingerprint,
                                    'private_key_retained_on_server': True})
        except (AccessError, OSError, ValueError, subprocess.SubprocessError):
            if generated:
                cleanup_created(((private, False), (public, True)))
            raise AccessError('Dedicated test identity preparation failed; private contents withheld.') from None
        finally:
            os.umask(previous_umask)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        print(json.dumps(prepare(), sort_keys=True))
    except (AccessError, OSError, ValueError, subprocess.SubprocessError):
        import sys
        print('Dedicated test access could not be prepared; private contents withheld.', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
