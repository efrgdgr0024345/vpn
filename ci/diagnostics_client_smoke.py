"""Real one-shot client diagnostics in a disposable PID/net/mount namespace.

The separate PID namespace makes the server's OpenVPN process invisible to the
client's normal unmanaged-process checks. No production check is substituted.
"""
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
PEER = 'diag-peer'
CLIENT_ADDRESS = '192.0.2.48'
GATEWAY = '192.0.2.1'
PHASE = 'namespace preparation'


def command(argv, *, timeout=15):
    try:
        return subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=timeout).stdout
    except subprocess.CalledProcessError:
        # Never expose arbitrary argv, environment, stderr or private inputs.
        raise RuntimeError('Diagnostics fixture command failed during '+PHASE+'.') from None


def disposable():
    if (not Path('/.dockerenv').exists() or os.geteuid() != 0
            or os.environ.get('VPN_LAB_DISPOSABLE_SERVER_TEST') != '1'):
        raise RuntimeError('Use only the disposable diagnostics client fixture.')


def receive(process, *, timeout=20):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise RuntimeError('The isolated diagnostics client did not respond.')
    value = process.stdout.readline(131073)
    if not value or len(value) > 131072:
        raise RuntimeError('The isolated diagnostics response was missing or oversized.')
    return value.strip()


def firewall_signature():
    document = json.loads(command(['/usr/sbin/nft', '-j', 'list', 'ruleset']))
    def structural(value):
        if isinstance(value, list):
            return [structural(item) for item in value]
        if isinstance(value, dict):
            # The real packet test legitimately increments existing counters.
            return {key: ({} if key == 'counter' and isinstance(item, dict)
                          else structural(item)) for key, item in value.items()}
        return value
    return structural(document)


def run(endpoint):
    """Run only while the disposable server and fake public peers are active."""
    global PHASE
    disposable()
    before_resolver = Path('/etc/resolv.conf').read_bytes()
    before_routes = command(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'])
    before_firewall = firewall_signature()
    process = subprocess.Popen([
        '/usr/bin/unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
        '--propagation', 'private', '--', '/usr/bin/python3', '-I', '-B',
        str(Path(__file__)), 'client', endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, start_new_session=True)
    linked = False
    try:
        if receive(process, timeout=30) != 'client namespace ready':
            raise RuntimeError('The isolated diagnostics client did not prepare.')
        # The unshare parent and its PID-namespace child share this fresh netns.
        PHASE = 'veth creation'
        command(['/usr/sbin/ip', 'link', 'add', PEER, 'type', 'veth', 'peer', 'name', 'wlan0'])
        linked = True
        PHASE = 'namespace interface transfer'
        command(['/usr/sbin/ip', 'link', 'set', 'wlan0', 'netns', str(process.pid)])
        PHASE = 'veth configuration'
        command(['/usr/sbin/ip', 'address', 'add', GATEWAY+'/24', 'dev', PEER])
        command(['/usr/sbin/ip', 'link', 'set', PEER, 'up'])
        process.stdin.write('start\n')
        process.stdin.flush()
        # Only this fixed summary crosses out of the client namespace. The
        # child asserts the detailed report and never emits private file data.
        value = receive(process, timeout=175)
        if value != 'PASS: one-shot success and authentication failure restored the client baseline.':
            if value.startswith('FAIL ') and re.fullmatch(r'[A-Za-z0-9 ,/_.()\-]{1,180}', value):
                raise RuntimeError(value)
            raise RuntimeError('The real automated diagnostics fixture failed.')
        process.wait(timeout=10)
        if process.returncode:
            raise RuntimeError('The automated diagnostics fixture did not exit cleanly.')
    finally:
        if process.poll() is None:
            # Terminate the disposable namespace's init, which also tears down
            # all of its descendants. This never targets the host VPN process.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        process.stdin.close()
        process.stdout.close()
        if linked:
            # Exiting the fresh namespace normally deletes both veth ends. Do
            # not turn successful teardown into an error or mask a prior one.
            links = json.loads(command(['/usr/sbin/ip', '-j', 'link', 'show']))
            if any(item.get('ifname') == PEER for item in links):
                command(['/usr/sbin/ip', 'link', 'delete', PEER])
    if (Path('/etc/resolv.conf').read_bytes() != before_resolver
            or command(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all']) != before_routes
            or firewall_signature() != before_firewall):
        raise RuntimeError('The isolated diagnostics fixture changed server networking.')
    print('PASS: actual automated client TLS, private/system DNS, verified HTTPS, bad-password classification and explicit restoration; server networking preserved.', flush=True)


def install_client(endpoint):
    # These paths contain only the earlier fake audit fixture in this exact
    # disposable server image. The production installer never removes them.
    for directory in ('/etc/vpn-desk', '/opt/vpn-desk', '/usr/local/libexec/vpn-desk'):
        path = Path(directory)
        if path.exists():
            shutil.rmtree(path)
    for filename in ('/usr/local/bin/vpn-desk', '/usr/local/share/applications/vpn-desk.desktop'):
        Path(filename).unlink(missing_ok=True)
    sys.path.insert(0, str(ROOT/'vpn-dashboard'))
    import install
    import security
    import firewall_policy
    policy = security.validate_policy({
        'wifi_interface': 'wlan0', 'vpn_server_ipv4': endpoint, 'vpn_port': 1194,
        'vpn_protocol': 'udp', 'dhcp_server_ipv4': GATEWAY, 'server_name': 'VPNLabServer'})
    profile = Path('/root/vpn-lab/client.ovpn').read_text()
    security.validate_profile(profile, policy)
    contents = {name: (ROOT/'vpn-dashboard'/name).read_bytes()
                for name in set(install.HELPERS + install.APPLICATION)}
    install.install(security, firewall_policy, contents, policy, profile)


def assert_clean(report):
    recovery = report.get('recovery', {})
    if not recovery.get('restored') or not recovery.get('confirmed') or not recovery.get('ownership_proven'):
        raise RuntimeError('The automated client did not verify its own restoration.')
    if Path('/etc/vpn-desk/network-state.json').exists():
        raise RuntimeError('The automated client retained active network state.')
    credentials = Path('/etc/vpn-desk/testing-login.txt').lstat()
    if (credentials.st_uid != 0 or not stat.S_ISREG(credentials.st_mode)
            or credentials.st_nlink != 1 or stat.S_IMODE(credentials.st_mode) != 0o600):
        raise RuntimeError('The automated client broadened saved credential access.')


def client(endpoint):
    global PHASE
    disposable()
    os.umask(0o077)
    # Docker normally bind mounts this file. Unmount it only inside our private
    # mount namespace, exposing a regular disposable overlay file for the app's
    # normal atomic resolver updates. The server keeps its original bind mount.
    command(['/usr/bin/umount', '/etc/resolv.conf'])
    resolver = Path('/etc/resolv.conf')
    if resolver.is_symlink():
        resolver.unlink()
    resolver.write_text('nameserver '+GATEWAY+'\n')
    resolver.chmod(0o644)
    PHASE = 'protected installation'
    install_client(endpoint)
    print('client namespace ready', flush=True)
    if sys.stdin.readline().strip() != 'start':
        raise RuntimeError('The isolated diagnostics client was not started.')
    PHASE = 'interface preparation'
    command(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
    command(['/usr/sbin/ip', 'address', 'add', CLIENT_ADDRESS+'/24', 'dev', 'wlan0'])
    command(['/usr/sbin/ip', 'link', 'set', 'wlan0', 'up'])
    command(['/usr/sbin/ip', 'route', 'add', 'default', 'via', GATEWAY, 'dev', 'wlan0'])
    env = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C', 'SUDO_UID': '1000'}
    login = Path('/root/vpn-lab/login.txt').read_bytes()

    def attempt(path):
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(ROOT/'ops/client_diagnostics.py'),
                                 '--restore-after-test', '--credentials', str(path)],
                                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=110)
        if (len(result.stdout) > 131072 or login.splitlines()[1] in result.stdout
                or any(word in result.stdout for word in (b'SESS_ID_', b'BEGIN PRIVATE', b'PUSH_REPLY'))):
            raise RuntimeError('The automated client report exposed transport or credential data.')
        try:
            report = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError('The automated client did not produce one typed report.') from None
        return result, report

    PHASE = 'successful attempt'
    result, report = attempt(Path('/root/vpn-lab/login.txt'))
    assert_clean(report)
    if result.returncode or report.get('outcome') != 'success':
        raise RuntimeError('The automated client did not pass the actual VPN session.')
    checks = report.get('checks', [])
    if not checks or not any(row.get('private_dns') == 'ok' and row.get('system_dns') == 'ok'
                             and row.get('https') == 'ok' for row in checks):
        raise RuntimeError('The automated client did not verify private DNS, system DNS and HTTPS.')
    time.sleep(6)
    wrong = Path('/run/diagnostics-wrong-login')
    wrong.write_bytes(b'vpn-lab-client\nINTENTIONALLY_WRONG_DIAGNOSTICS_PASSWORD_1234567890\n')
    wrong.chmod(0o600)
    PHASE = 'rejected password attempt'
    result, report = attempt(wrong)
    wrong.unlink()
    assert_clean(report)
    snapshot = report.get('session') or {}
    if (result.returncode == 0 or report.get('outcome') == 'success'
            or 'auth_failed' not in {row['code'] for row in snapshot.get('events', [])}):
        raise RuntimeError('The automated client did not classify a real rejected password.')
    print('PASS: one-shot success and authentication failure restored the client baseline.', flush=True)


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != 'client':
        raise SystemExit('Use the disposable server diagnostics fixture entry point.')
    try:
        client(sys.argv[2])
    except Exception as error:
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        if re.fullmatch(r'[A-Za-z0-9 ,/_.()\-]{1,120}', detail) is None:
            detail = type(error).__name__
        print('FAIL '+PHASE+' '+detail, flush=True)
        raise SystemExit(1)
