"""Trust the private panel CA in a dedicated Firefox profile and open the panel.

Run as the Kali desktop user, after verifying this public source. This helper
never reads the administrator password and never changes global certificate trust.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import ssl
import stat
import subprocess
import tempfile
from urllib.request import Request, urlopen

ROOT_UID = 0
ORIGIN = 'https://172.27.240.1:8443'
ANNOTATIONS = re.compile(r'https://api\.github\.com/repos/efrgdgr0024345/vpn/check-runs/[1-9][0-9]{0,19}/annotations\Z')
FINGERPRINT = re.compile(r'[0-9a-f]{64}\Z')
CERTIFICATE = re.compile(r'-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]{1,76}\n)+-----END CERTIFICATE-----\n?\Z')
CERTUTIL = Path('/usr/bin/certutil')
FIREFOXES = (Path('/usr/bin/firefox-esr'), Path('/usr/bin/firefox'))
NICKNAME = 'VPNLabPanelCA'
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
PREFERENCES = {
    'browser.startup.homepage': ORIGIN,
    'browser.startup.page': 0,
    'startup.homepage_welcome_url': '',
    'startup.homepage_welcome_url.additional': '',
    'browser.aboutwelcome.enabled': False,
    'browser.shell.checkDefaultBrowser': False,
    'browser.newtabpage.enabled': False,
    'browser.newtab.preload': False,
    'browser.search.suggest.enabled': False,
    'browser.urlbar.suggest.searches': False,
    'signon.rememberSignons': False,
    'browser.cache.disk.enable': False,
    'datareporting.healthreport.uploadEnabled': False,
    'datareporting.policy.dataSubmissionEnabled': False,
    'toolkit.telemetry.enabled': False,
    'toolkit.telemetry.unified': False,
    'toolkit.telemetry.archive.enabled': False,
    'browser.ping-centre.telemetry': False,
    'app.normandy.enabled': False,
    'app.shield.optoutstudies.enabled': False,
    'extensions.pocket.enabled': False,
    'network.captive-portal-service.enabled': False,
    'network.connectivity-service.enabled': False,
    'network.trr.mode': 5,
    'network.proxy.type': 0,
    'security.enterprise_roots.enabled': False,
}
USER_JS = ''.join('user_pref('+json.dumps(key)+', '+json.dumps(value)+');\n'
                  for key, value in sorted(PREFERENCES.items())).encode()


class SetupError(RuntimeError):
    pass


def certificate_bytes(pem, expected):
    # NSS can emit CRLF inside the PEM body even on Linux. Normalize only
    # standard line endings before checking the exact public-certificate shape.
    if isinstance(pem, str):
        pem = pem.replace('\r\n', '\n')
    if (not isinstance(expected, str) or not FINGERPRINT.fullmatch(expected)
            or not isinstance(pem, str) or len(pem) > 4096 or not CERTIFICATE.fullmatch(pem)):
        raise SetupError('The public panel certificate is unsupported.')
    try:
        value = ssl.PEM_cert_to_DER_cert(pem)
    except (ValueError, TypeError):
        raise SetupError('The public panel certificate is unsupported.') from None
    if hashlib.sha256(value).hexdigest() != expected:
        raise SetupError('Panel CA checksum mismatch; no certificate was trusted.')
    return pem.encode('ascii')


def annotation_certificate(document, expected):
    if not isinstance(document, list) or len(document) > 100:
        raise SetupError('Unsupported public installation report.')
    matches = [item for item in document if isinstance(item, dict)
               and item.get('title') == 'VPN lab install-admin-panel']
    if len(matches) != 1 or not isinstance(matches[0].get('message'), str):
        raise SetupError('A unique public panel installation report was not found.')
    try:
        report = json.loads(matches[0]['message'])
    except ValueError:
        raise SetupError('Unsupported public installation report.') from None
    if (not isinstance(report, dict) or type(report.get('version')) is not int
            or report['version'] != 1 or report.get('panel_url') != ORIGIN
            or report.get('credential_contents_returned') is not False
            or report.get('ca_certificate_sha256') != expected):
        raise SetupError('The public installation report does not match the expected panel.')
    return certificate_bytes(report.get('ca_certificate_pem'), expected)


def download_certificate(url, expected):
    if not isinstance(url, str) or not ANNOTATIONS.fullmatch(url):
        raise SetupError('Use the exact public installation annotations URL.')
    if not isinstance(expected, str) or not FINGERPRINT.fullmatch(expected):
        raise SetupError('Use the independently supplied SHA256 of the public CA.')
    request = Request(url, headers={'Accept': 'application/vnd.github+json',
                                   'User-Agent': 'VPN-Desk-private-panel-setup'})
    # Stock HTTPS certificate verification remains enabled. Only public CA data
    # is downloaded; no administrator credential is requested or transmitted.
    try:
        with urlopen(request, timeout=20) as response:
            if response.geturl() != url:
                raise SetupError('Unexpected public-report redirect; stopped.')
            value = response.read(1_000_001)
        if len(value) > 1_000_000:
            raise SetupError('The public installation report exceeds its limit.')
        document = json.loads(value)
    except (OSError, ValueError):
        raise SetupError('Could not read the public installation report; no certificate was trusted.') from None
    return annotation_certificate(document, expected)


def trusted_directory(path):
    uid = os.getuid()
    path = Path(path)
    for entry in (*reversed(path.parents), path):
        info = entry.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (ROOT_UID, uid)
                or info.st_mode & 0o022):
            raise SetupError('The panel profile directory has unsafe ownership, permissions or links.')


def directory(path):
    path = Path(path)
    if not path.exists():
        directory(path.parent)
        path.mkdir(mode=0o700)
    trusted_directory(path)


def read_user_file(path, limit=16384):
    path = Path(path)
    trusted_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise SetupError('An existing panel setup file has unsafe metadata.')
        value = stream.read(limit+1)
    if len(value) > limit:
        raise SetupError('An existing panel setup file exceeds its limit.')
    return value


def atomic(path, contents):
    trusted_directory(path.parent)
    if os.path.lexists(path):
        read_user_file(path)
    fd, temporary = tempfile.mkstemp(prefix='.panel-setup-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def lock(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise SetupError('The panel setup lock has unsafe metadata.')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SetupError('Another panel setup is running.') from None
        yield
    finally:
        os.close(fd)


def command(argv, *, allow_failure=False):
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, env=ENVIRONMENT, timeout=20)
        output.seek(0)
        value = output.read(65537)
    if len(value) > 65536 or result.returncode and not allow_failure:
        raise SetupError('A browser certificate setup command failed; no raw output is shown.')
    return result.returncode, value


def certificate_trust(database):
    _, listing = command([str(CERTUTIL), '-L', '-d', database])
    try:
        text = listing.decode('ascii').replace('\r\n', '\n')
    except UnicodeError:
        raise SetupError('The isolated certificate trust listing is unsupported.') from None
    matches = re.findall(r'^'+re.escape(NICKNAME)+r'[ \t]+([A-Za-z,]+)[ \t]*$', text, re.MULTILINE)
    if len(matches) != 1:
        raise SetupError('The expected isolated certificate trust entry was not found.')
    return matches[0]


def profile_setup(pem, expected, *, home=None):
    if os.geteuid() == 0 or os.getuid() == 0:
        raise SetupError('Run this as your ordinary Kali desktop user, without sudo.')
    pem = certificate_bytes(pem.decode('ascii') if isinstance(pem, bytes) else pem, expected)
    if not CERTUTIL.is_file() or not os.access(CERTUTIL, os.X_OK):
        raise SetupError('Install the standard libnss3-tools package first, then rerun this command.')
    home = Path(home) if home is not None else Path(pwd.getpwuid(os.getuid()).pw_dir)
    trusted_directory(home)
    base = home/'.local'/'share'/'vpn-lab-admin'
    directory(base)
    if base.lstat().st_uid != os.getuid() or stat.S_IMODE(base.lstat().st_mode) != 0o700:
        raise SetupError('The dedicated panel directory must be owned by you with mode 0700.')
    profile = base/'browser'
    manifest = base/'setup.json'
    ca_file = base/'ca.crt'
    wanted = {'version': 1, 'ca_sha256': expected, 'profile': 'browser', 'origin': ORIGIN}
    with lock(base/'setup.lock'):
        if os.path.lexists(manifest):
            try:
                record = json.loads(read_user_file(manifest))
            except ValueError:
                raise SetupError('The existing panel profile record is unsupported.') from None
            if (not isinstance(record, dict) or set(record) != set(wanted)|{'ready'}
                    or type(record.get('version')) is not int
                    or any(record.get(key) != value for key, value in wanted.items())
                    or type(record['ready']) is not bool):
                raise SetupError('This profile belongs to another CA or configuration; preserved without changes.')
        else:
            if any(item.name != 'setup.lock' for item in base.iterdir()):
                raise SetupError('An existing profile without our setup record was preserved.')
            record = {**wanted, 'ready': False}
            atomic(manifest, (json.dumps(record, sort_keys=True)+'\n').encode())
        directory(profile)
        if profile.lstat().st_uid != os.getuid() or stat.S_IMODE(profile.lstat().st_mode) != 0o700:
            raise SetupError('The isolated browser profile must have mode 0700 and your ownership.')
        for path, value in ((ca_file, pem), (profile/'user.js', USER_JS)):
            if os.path.lexists(path):
                if read_user_file(path) != value:
                    raise SetupError('An existing panel setup file differs; preserved without changes.')
            else:
                atomic(path, value)
        for name in ('cert9.db', 'key4.db', 'pkcs11.txt'):
            path = profile/name
            if os.path.lexists(path):
                read_user_file(path, limit=2_000_000)
        database = 'sql:'+str(profile)
        if not (profile/'cert9.db').exists():
            command([str(CERTUTIL), '-N', '--empty-password', '-d', database])
        status, existing = command([str(CERTUTIL), '-L', '-d', database, '-n', NICKNAME, '-a'], allow_failure=True)
        if status == 0:
            certificate_bytes(existing.decode('ascii'), expected)
        else:
            command([str(CERTUTIL), '-A', '-d', database, '-n', NICKNAME, '-t', 'C,,', '-i', str(ca_file)])
            _, imported = command([str(CERTUTIL), '-L', '-d', database, '-n', NICKNAME, '-a'])
            certificate_bytes(imported.decode('ascii'), expected)
        # A matching certificate can still be explicitly distrusted or have no
        # CA trust. Repair only the independently verified certificate in this
        # dedicated profile, then read back the SSL-only trust assignment.
        if certificate_trust(database) != 'C,,':
            command([str(CERTUTIL), '-M', '-d', database, '-n', NICKNAME, '-t', 'C,,'])
        if certificate_trust(database) != 'C,,':
            raise SetupError('The isolated panel certificate trust could not be verified.')
        record['ready'] = True
        atomic(manifest, (json.dumps(record, sort_keys=True)+'\n').encode())
    return profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--annotation-url', required=True)
    parser.add_argument('--ca-sha256', required=True)
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    if os.geteuid() == 0 or os.getuid() == 0:
        raise SetupError('Run this as your ordinary Kali desktop user, without sudo.')
    if not CERTUTIL.is_file():
        raise SetupError('Install the standard libnss3-tools package first, then rerun this command.')
    firefox = next((path for path in FIREFOXES if path.is_file() and os.access(path, os.X_OK)), None)
    if not args.prepare_only and firefox is None:
        raise SetupError('Firefox is required for the isolated administration profile.')
    pem = download_certificate(args.annotation_url, args.ca_sha256)
    profile = profile_setup(pem, args.ca_sha256)
    print('Private panel CA verified in its isolated Firefox profile. Global certificate trust was unchanged.', flush=True)
    if not args.prepare_only:
        subprocess.Popen([str(firefox), '--no-remote', '--new-instance', '--profile', str(profile), '--url', ORIGIN],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, start_new_session=True)
        print('Opening the VPN-only panel. Enter the separate administrator password there.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (SetupError, OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, SetupError) else 'A required local or network check failed; stop and review.'
        raise SystemExit('Panel browser setup stopped: '+detail) from None
