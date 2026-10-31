"""Actual unprivileged panel/TLS over a real VPN in disposable CI namespaces.

Systemd lifecycle is substituted in the container; accounts, files, credentials,
certificates, nftables, OpenVPN and the separate web UID are real.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'ops'))
import install_admin_panel as installer
import server_foundation as foundation

PEER = 'admin-peer'
CLIENT_IF = 'testwan0'
OUTER_CLIENT = '192.0.2.50'
GATEWAY = '192.0.2.1'
HANDSHAKE_RULE = 'vpn-lab-admin-test-outer'


def command(argv, *, data=None, timeout=20):
    try:
        return subprocess.run(argv, input=data, check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=timeout,
            env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}).stdout
    except subprocess.CalledProcessError:
        raise RuntimeError('An isolated panel fixture command failed.') from None


def disposable():
    if (os.geteuid() != 0 or not Path('/.dockerenv').exists()
            or os.environ.get('VPN_LAB_DISPOSABLE_SERVER_TEST') != '1'):
        raise RuntimeError('Use only the disposable panel integration fixture.')


def receive(process, timeout=30):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise RuntimeError('The isolated panel client did not respond.')
    line = process.stdout.readline(1025).strip()
    if not line or len(line) > 1024:
        raise RuntimeError('The isolated panel client response was invalid.')
    return line


def counter():
    objects = json.loads(command(['/usr/sbin/nft', '-j', 'list', 'chain', 'inet', 'vpn_lab', 'input']))['nftables']
    rules = [o['rule'] for o in objects if o.get('rule', {}).get('comment') == installer.COMMENT]
    if len(rules) != 1:
        raise RuntimeError('The panel firewall counter is missing.')
    return sum(item['counter']['packets'] for item in rules[0]['expr'] if 'counter' in item)


def https(method, route, body=None, headers=None):
    context = ssl.create_default_context(cafile='/etc/vpn-lab-admin/ca.crt')
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    connection = http.client.HTTPSConnection('172.27.240.1', 8443, context=context, timeout=8)
    try:
        connection.request(method, route, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read(262145)
        if len(data) > 262144:
            raise RuntimeError('Panel test response exceeded its limit.')
        return response.status, dict(response.getheaders()), data
    finally:
        connection.close()


def client():
    disposable()
    print('namespace ready', flush=True)
    if sys.stdin.readline().strip() != 'start':
        raise RuntimeError('Panel namespace did not receive its start signal.')
    for argv in (['/usr/sbin/ip', 'link', 'set', 'lo', 'up'],
                 ['/usr/sbin/ip', 'address', 'add', OUTER_CLIENT+'/24', 'dev', CLIENT_IF],
                 ['/usr/sbin/ip', 'link', 'set', CLIENT_IF, 'up'],
                 ['/usr/sbin/ip', 'route', 'add', 'default', 'via', GATEWAY, 'dev', CLIENT_IF]):
        command(argv)
    with tempfile.TemporaryDirectory(prefix='vpn-panel-client-', dir='/run') as directory, tempfile.TemporaryFile() as log:
        root = Path(directory)
        profile = Path('/root/vpn-lab/client.ovpn').read_text()
        profile = re.sub(r'^remote [^\r\n]+$', 'remote '+GATEWAY+' 1194', profile, flags=re.M)
        config = root/'client.ovpn'
        config.write_text(profile)
        config.chmod(0o600)
        vpn = subprocess.Popen(['/usr/sbin/openvpn', '--config', str(config),
            '--auth-user-pass', '/root/vpn-lab/login.txt', '--auth-nocache',
            '--proto', 'udp4', '--disable-dco', '--pull-filter', 'ignore', 'redirect-gateway',
            '--explicit-exit-notify', '1', '--script-security', '1'],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic()+20
            while True:
                log.seek(0)
                data = log.read(131073)
                if len(data) > 131072 or vpn.poll() is not None:
                    raise RuntimeError('The private panel VPN client did not initialize.')
                if b'Initialization Sequence Completed' in data:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('The private panel VPN client timed out.')
                time.sleep(.1)
            print('vpn ready', flush=True)
            if sys.stdin.readline().strip() != 'probe':
                raise RuntimeError('Panel namespace did not receive its probe signal.')
            headers = {'Origin': installer.URL, 'Content-Type': 'application/json'}
            status, _, _ = https('GET', '/api/status')
            if status != 401:
                raise RuntimeError('The private panel did not require a separate login.')
            status, _, _ = https('POST', '/api/login', json.dumps({'password': 'intentionally-invalid-panel-password'}), headers)
            if status != 401:
                raise RuntimeError('An incorrect panel password was not rejected.')
            password = Path('/root/vpn-lab/admin/login.txt').read_text().strip()
            status, response_headers, body = https('POST', '/api/login', json.dumps({'password': password}), headers)
            cookie = response_headers.get('Set-Cookie', '')
            if status != 200 or not all(flag in cookie for flag in ('Secure', 'HttpOnly', 'SameSite=Strict')):
                raise RuntimeError('The private panel login or secure cookie failed.')
            value = json.loads(body)
            if password.encode() in body or set(value) != {'authenticated', 'csrf_token'}:
                raise RuntimeError('The panel login response exposed unexpected data.')
            authenticated = {**headers, 'Cookie': cookie.split(';', 1)[0]}
            status, _, body = https('GET', '/api/status', headers=authenticated)
            report = json.loads(body)
            if (status != 200 or not report.get('available') or report.get('stale')
                    or report['snapshot']['authorization']['element_count'] != 1
                    or report['snapshot']['authorization']['addresses'][0]['ipv4'] != '172.27.240.10'):
                raise RuntimeError('The panel did not display the real authorized VPN session.')
            if password.encode() in body or b'BEGIN PRIVATE' in body or b'SESS_ID_' in body:
                raise RuntimeError('The public panel snapshot exposed credential material.')
            status, _, ca = https('GET', '/ca.crt')
            if status != 200 or ca != Path('/etc/vpn-lab-admin/ca.crt').read_bytes():
                raise RuntimeError('The public panel CA did not match the checked trust anchor.')
            status, _, _ = https('POST', '/api/logout', '{}', authenticated)
            if status != 403:
                raise RuntimeError('Panel logout did not enforce CSRF protection.')
            status, _, _ = https('POST', '/api/logout', '{}', {**authenticated, 'X-CSRF-Token': value['csrf_token']})
            if status != 200 or https('GET', '/api/status', headers=authenticated)[0] != 401:
                raise RuntimeError('Panel logout did not invalidate the browser session.')
        finally:
            if vpn.poll() is None:
                os.killpg(vpn.pid, signal.SIGTERM)
                vpn.wait(timeout=8)
            # Keep the outer namespace/device alive while the server processes
            # UDP explicit exit notification. Destroying the veth immediately
            # can discard a queued EXIT and strand the global session slot.
            print('vpn stopped', flush=True)
            if sys.stdin.readline().strip() != 'finish':
                raise RuntimeError('The panel client cleanup was not confirmed.')
    print('PASS private panel HTTPS and authentication', flush=True)


def run(daemons):
    disposable()
    sources = {name: ((ROOT/'ops/server_diagnostics.py') if name == 'server_diagnostics.py'
                       else ROOT/'vpn-admin'/name).read_text() for name in installer.SOURCE_FILES}
    preserved_paths = [Path('/root/vpn-lab/login.txt'), Path('/root/vpn-lab/client.ovpn'),
                       Path('/etc/openvpn/lab/devices.json'), *Path('/etc/openvpn/lab/pki').rglob('*')]
    identities = {str(path): hashlib.sha256(path.read_bytes()).digest() for path in preserved_paths if path.is_file()}
    before_pids = {name: process.pid for name, process in daemons.items()}
    panel_processes = {}
    with tempfile.TemporaryFile() as output:
        real_run = foundation.run
        def lifecycle(argv, **kwargs):
            if argv[:2] == ['/usr/bin/systemctl', 'show']:
                unit = argv[-1]
                if unit in daemons:
                    process = daemons[unit]
                    return ('MainPID='+str(process.pid)+'\nActiveState='+('active' if process.poll() is None else 'inactive')
                            +'\nActiveEnterTimestampMonotonic=fixture-'+str(process.pid)+'\n')
            if argv[:2] in (['/usr/bin/systemctl', 'daemon-reload'], ['/usr/bin/systemctl', 'enable']):
                return ''
            if argv[:2] == ['/usr/bin/systemctl', 'restart'] and tuple(argv[2:]) == installer.PANEL_UNITS:
                for process in panel_processes.values():
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        process.wait(timeout=5)
                account = pwd.getpwnam(installer.USER)
                for name, filename in zip(installer.PANEL_UNITS, ('collector.py', 'server.py')):
                    extra = {} if filename == 'collector.py' else {'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': []}
                    panel_processes[name] = subprocess.Popen(['/usr/bin/python3', '-I', '-B', str(installer.CODE/filename)],
                        stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, start_new_session=True, **extra)
                return ''
            if argv[:2] == ['/usr/bin/systemctl', 'is-active'] and argv[-1] in panel_processes:
                return 'active\n' if panel_processes[argv[-1]].poll() is None else 'inactive\n'
            return real_run(argv, **kwargs)
        child = None
        handle = None
        linked = False
        try:
            try:
                with patch.object(foundation, 'run', side_effect=lifecycle):
                    result = installer.install(sources, 'a'*40)
            except foundation.SetupError:
                raise RuntimeError('Private panel installation failed during '+installer.STAGE+'.') from None
            if not result['vpn_runtime_preserved']:
                raise RuntimeError('Panel installation changed the active VPN services.')
            panel_private = [installer.EXPORT/'login.txt', installer.CONFIG/'auth.json',
                             installer.CONFIG/'server.key', installer.CONFIG/'ca-private'/'ca.key']
            private_before = [path.read_bytes() for path in panel_private]
            with patch.object(foundation, 'run', side_effect=lifecycle):
                repeated = installer.install(sources, 'a'*40)
            if ([path.read_bytes() for path in panel_private] != private_before
                    or repeated['ca_certificate_sha256'] != result['ca_certificate_sha256']):
                raise RuntimeError('A panel installer retry changed its private identity.')
            process = panel_processes['vpn-lab-admin.service']
            fields = dict(line.split(':', 1) for line in Path('/proc', str(process.pid), 'status').read_text().splitlines() if ':' in line)
            if int(fields['Uid'].split()[0]) == 0 or int(fields['CapEff'].strip(), 16) != 0:
                raise RuntimeError('The panel web process retained root or effective capabilities.')
            if https('GET', '/api/status')[0] != 403:
                raise RuntimeError('The panel accepted a host-local request outside its VPN peer policy.')
            before_counter = counter()
            child = subprocess.Popen(['/usr/bin/unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                '--propagation', 'private', '--', '/usr/bin/python3', '-I', '-B',
                str(Path(__file__)), 'client'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, start_new_session=True)
            if receive(child) != 'namespace ready':
                raise RuntimeError('The private panel test namespace did not prepare.')
            command(['/usr/sbin/ip', 'link', 'add', PEER, 'type', 'veth', 'peer', 'name', CLIENT_IF])
            linked = True
            command(['/usr/sbin/ip', 'link', 'set', CLIENT_IF, 'netns', str(child.pid)])
            command(['/usr/sbin/ip', 'address', 'add', GATEWAY+'/24', 'dev', PEER])
            command(['/usr/sbin/ip', 'link', 'set', PEER, 'up'])
            expression = [
                {'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': PEER}},
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': OUTER_CLIENT}},
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}}, 'right': GATEWAY}},
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'udp', 'field': 'dport'}}, 'right': 1194}},
                {'accept': None}]
            command(['/usr/sbin/nft', '-j', '-f', '-'], data=json.dumps({'nftables': [{'add': {'rule': {
                'family': 'inet', 'table': 'vpn_lab', 'chain': 'input', 'expr': expression, 'comment': HANDSHAKE_RULE}}}]}))
            rules = json.loads(command(['/usr/sbin/nft', '-j', 'list', 'chain', 'inet', 'vpn_lab', 'input']))['nftables']
            matched = [item['rule'] for item in rules if item.get('rule', {}).get('comment') == HANDSHAKE_RULE]
            if len(matched) != 1:
                raise RuntimeError('The isolated outer handshake rule did not verify.')
            handle = matched[0]['handle']
            child.stdin.write('start\n')
            child.stdin.flush()
            if receive(child) != 'vpn ready':
                raise RuntimeError('The panel client did not establish its actual VPN.')
            deadline = time.monotonic()+20
            while True:
                try:
                    snapshot = json.loads(Path('/run/vpn-lab-admin/status.json').read_text())
                    ready = snapshot['authorization']['element_count'] == 1
                except (OSError, ValueError, KeyError, TypeError):
                    ready = False
                if ready:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('The root collector did not observe the real VPN grant.')
                time.sleep(.2)
            child.stdin.write('probe\n')
            child.stdin.flush()
            if receive(child, timeout=45) != 'vpn stopped':
                raise RuntimeError('The private panel HTTPS or authentication test failed.')
            deadline = time.monotonic()+25
            while True:
                objects = json.loads(command(['/usr/sbin/nft', '-j', 'list', 'set', 'inet', 'vpn_lab', 'authorized']))['nftables']
                sets = [item['set'] for item in objects if item.get('set', {}).get('name') == 'authorized']
                if len(sets) == 1 and not sets[0].get('elem'):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('The panel test VPN forwarding lease was not released.')
                time.sleep(.2)
            child.stdin.write('finish\n')
            child.stdin.flush()
            if receive(child) != 'PASS private panel HTTPS and authentication':
                raise RuntimeError('The private panel test did not finish cleanly.')
            child.wait(timeout=10)
            if child.returncode or counter() <= before_counter:
                raise RuntimeError('Panel HTTPS did not traverse the private authorization firewall rule.')
            if (any(process.pid != before_pids[name] or process.poll() is not None for name, process in daemons.items())
                    or any(hashlib.sha256(Path(path).read_bytes()).digest() != digest for path, digest in identities.items())):
                raise RuntimeError('Panel installation or tests changed VPN identities or existing daemons.')
            print('PASS: actual private panel installation, unprivileged web UID, separate TLS/admin login, CSRF/logout, real VPN-only firewall path and unchanged VPN identities/daemons.', flush=True)
        finally:
            if child is not None:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
                child.stdin.close()
                child.stdout.close()
            if handle is not None:
                command(['/usr/sbin/nft', 'delete', 'rule', 'inet', 'vpn_lab', 'input', 'handle', str(handle)])
            if linked and any(row.get('ifname') == PEER for row in json.loads(command(['/usr/sbin/ip', '-j', 'link', 'show']))):
                command(['/usr/sbin/ip', 'link', 'delete', PEER])
            for process in panel_processes.values():
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2 or sys.argv[1] != 'client':
            raise RuntimeError('Use the disposable panel client entry point.')
        client()
    except Exception as error:
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        if not re.fullmatch(r'[A-Za-z0-9 ,/_.()\-]{1,150}', detail):
            detail = 'Private panel fixture failed.'
        print('FAIL '+detail, flush=True)
        raise SystemExit(1)
