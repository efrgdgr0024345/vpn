#!/usr/bin/python3
"""Explicit, hash-pinned upgrade of the owned client's transport/log bundle.

Run using system Python -I -B after independently verifying this script and the
candidate helper. No profile, credential, firewall, DNS or IPv6 setting changes.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

HELPER = Path('/usr/local/libexec/vpn-desk/vpn_session_helper.py')
MANIFEST = Path('/opt/vpn-desk/install-manifest.json')
LOCK = Path('/run/vpn-dashboard-portal.lock')
ROOTS = (Path('/opt/vpn-desk'), Path('/usr/local/libexec/vpn-desk'))
EXACT = {'/usr/local/bin/vpn-desk', '/usr/local/share/applications/vpn-desk.desktop'}
OLD_SHA256 = 'fa6137221cd9638e0e55db4356598457bfb13e2883b0544c669b47ca2ca2f96b'
LEGACY = {
    'vpn_session_helper.py': {'fa6137221cd9638e0e55db4356598457bfb13e2883b0544c669b47ca2ca2f96b',
                              'f2ca82581f2ae80900a94909f3172ae998bda0352b01fa8a62f1d44971df5044'},
    'session_channel.py': {'0f32f5050602f5a79a9f77a6837fc8f4bb9a9b8b7951b67b76bd9ceb4dd567b6'},
    'session_ui.py': {'7fa19a51db92c708a1c321370bbfc6efa0cc94615a3a87d6b07be47148a2918a'},
    'portal_helper.py': {'e401522faad3638eff1f9d6d2874e26a7c749713e34a2fb0fe3b0c78429e17ef'},
    'app.py': {'d0433e0f3f06edefb84e334183af599df79c13c17e6ab08ab025518397436b84'},
}


def targets():
    return {'vpn_session_helper.py': (HELPER,),
            'session_channel.py': (HELPER.parent/'session_channel.py', MANIFEST.parent/'session_channel.py'),
            'session_ui.py': (MANIFEST.parent/'session_ui.py',),
            'portal_helper.py': (HELPER.parent/'portal_helper.py',),
            'app.py': (MANIFEST.parent/'app.py',)}


class UpgradeError(RuntimeError):
    pass


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read_file(path, *, source=False):
    if not source:
        for parent in reversed(path.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise UpgradeError('Unprotected installed directory.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        owners = (0, int(os.environ.get('SUDO_UID', '0'))) if source else (0,)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid not in owners or info.st_mode & 0o022):
            raise UpgradeError('Unsafe source or installed file metadata.')
        value = stream.read(2_000_001)
        if len(value) > 2_000_000:
            raise UpgradeError('Public source or inventory exceeds the size limit.')
        return value


def publish(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.vpn-desk-upgrade-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def load_bundle(source, expected):
    raw = read_file(source/'client-update.json', source=True)
    if not re.fullmatch(r'[0-9a-f]{64}', expected) or digest(raw) != expected:
        raise UpgradeError('Public update manifest hash mismatch; nothing installed.')
    document = json.loads(raw)
    if (not isinstance(document, dict) or set(document) != {'version', 'files'}
            or type(document['version']) is not int or document['version'] != 1
            or not isinstance(document['files'], dict) or set(document['files']) != set(targets())):
        raise UpgradeError('Unsupported public update manifest.')
    return {name: (read_file(source/name, source=True), value) for name, value in document['files'].items()}


def upgrade(candidate, expected, *, bundle=None):
    updates = {HELPER: (candidate, expected, {OLD_SHA256})}
    if bundle is not None:
        if set(bundle) != set(targets()):
            raise UpgradeError('The complete reviewed transport/log bundle is required.')
        updates = {path: (value, checksum, LEGACY[name])
                   for name, (value, checksum) in bundle.items() for path in targets()[name]}
    for path, (value, checksum, _) in updates.items():
        if not isinstance(checksum, str) or not re.fullmatch(r'[0-9a-f]{64}', checksum) or digest(value) != checksum:
            raise UpgradeError('Candidate hash mismatch; nothing installed.')
        try:
            compile(value, path.name, 'exec')
        except SyntaxError:
            raise UpgradeError('Candidate Python syntax is invalid; nothing installed.') from None
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise UpgradeError('Unsafe action lock.')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise UpgradeError('Stop the VPN before upgrading.') from None
        processes = subprocess.run(['/usr/bin/ps', '-C', 'openvpn', '-o', 'pid='],
            capture_output=True, text=True, timeout=5,
            env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
        if processes.returncode != 1 or processes.stdout.strip() or processes.stderr.strip():
            raise UpgradeError('OpenVPN must be stopped and its process check must succeed.')
        document = json.loads(read_file(MANIFEST))
        if (not isinstance(document, dict) or set(document) != {'version', 'files'}
                or type(document['version']) is not int or document['version'] != 1 or not isinstance(document['files'], dict)
                or not 10 <= len(document['files']) <= 80
                or not (EXACT | {str(path) for path in updates}) <= set(document['files'])):
            raise UpgradeError('Unsupported installation baseline.')
        files = document['files']
        for path, (_, checksum, legacy) in updates.items():
            if files[str(path)] not in legacy | {checksum}:
                raise UpgradeError('Installed transport/log module has an unsupported baseline.')
        for name, recorded in files.items():
            path = Path(name)
            if (not path.is_absolute() or str(path) != name or '..' in path.parts
                    or not (name in EXACT or path.parent in ROOTS)
                    or re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', path.name) is None
                    or not isinstance(recorded, str) or re.fullmatch(r'[0-9a-f]{64}', recorded) is None):
                raise UpgradeError('Unsupported installation inventory entry.')
            actual = digest(read_file(path))
            # Resume safely if power failed between the two atomic file writes.
            transitional = path in updates and actual == updates[path][1] and recorded in updates[path][2]
            if actual != recorded and not transitional:
                raise UpgradeError('Installed files differ from the recorded baseline; nothing overwritten.')
        for root in ROOTS:
            if any(str(path) not in files and path != MANIFEST for path in root.iterdir()):
                raise UpgradeError('Unexpected installed file; nothing overwritten.')
        for path, (value, checksum, legacy) in updates.items():
            if digest(read_file(path)) not in legacy | {checksum}:
                raise UpgradeError('Unrecognized installed transport/log module; nothing overwritten.')
            publish(path, value)
            files[str(path)] = checksum
        publish(MANIFEST, (json.dumps(document, sort_keys=True, indent=2) + '\n').encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('sha256')
    args = parser.parse_args()
    if os.geteuid() != 0 or not sys.flags.isolated:
        raise UpgradeError('Use sudo with /usr/bin/python3 -I -B.')
    os.umask(0o077)
    bundle = load_bundle(args.source, args.sha256)
    candidate, expected = bundle['vpn_session_helper.py']
    upgrade(candidate, expected, bundle=bundle)
    print('Transport/log modules and public-code baseline updated. Private settings and networking were preserved. Reopen VPN Desk.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, UpgradeError, subprocess.SubprocessError) as error:
        print('Upgrade stopped: ' + (str(error) if isinstance(error, UpgradeError) else
              'Update incomplete; verify the installed baseline before retrying. Private details withheld.'))
        raise SystemExit(1)
