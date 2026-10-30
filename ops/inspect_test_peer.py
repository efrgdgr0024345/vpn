#!/usr/bin/python3
"""Inspect one explicitly pinned test peer through a fixed read-only SSH program."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import tempfile
import time

KEY = Path('/root/.vpn-lab-external-test/id_ed25519')
RUNTIME = Path('/run')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
CLIENTS = ('/usr/sbin/openvpn', '/usr/bin/openvpn', '/usr/local/openvpn_as/sbin/openvpn')
TOOLS = ('ip', 'python3', 'curl', 'nft')
WIRE_PREFIX = b'\0\0\0\x0bssh-ed25519\0\0\0\x20'


class PeerError(RuntimeError):
    pass


def run(argv, *, input=None, timeout=15, limit=32768):
    """Bound both pipes and kill only this owned command group on failure."""
    pending = memoryview(input.encode() if input else b'')
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if pending else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, start_new_session=True)
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic()+timeout
    try:
        with selectors.DefaultSelector() as poller:
            for label in output:
                stream = getattr(process, label)
                os.set_blocking(stream.fileno(), False)
                poller.register(stream, selectors.EVENT_READ, label)
            if pending:
                os.set_blocking(process.stdin.fileno(), False)
                poller.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
            while poller.get_map():
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise PeerError('command_failed')
                for item, _ in poller.select(remaining):
                    if item.data == 'stdin':
                        try:
                            count = os.write(item.fileobj.fileno(), pending[:4096])
                            pending = pending[count:]
                        except BrokenPipeError:
                            pending = memoryview(b'')
                        if not pending:
                            poller.unregister(item.fileobj)
                            item.fileobj.close()
                    else:
                        part = os.read(item.fileobj.fileno(), 4096)
                        if not part:
                            poller.unregister(item.fileobj)
                        else:
                            if sum(map(len, output.values()))+len(part) > limit:
                                raise PeerError('command_failed')
                            output[item.data].extend(part)
        return subprocess.CompletedProcess(argv,
            process.wait(timeout=max(.001, deadline-time.monotonic())),
            output['stdout'].decode('utf-8'), output['stderr'].decode('utf-8'))
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        raise PeerError('command_failed') from None
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def settings(host, port, fingerprint):
    try:
        address = ipaddress.IPv4Address(host)
        if (not isinstance(host, str) or str(address) != host or address.is_loopback
                or address.is_unspecified or address.is_multicast or address.is_link_local
                or host == '255.255.255.255'):
            raise ValueError()
        port = str(port)
        if not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
            raise ValueError()
        if not isinstance(fingerprint, str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint):
            raise ValueError()
    except (TypeError, ValueError):
        raise PeerError('invalid_settings') from None
    return host, str(int(port)), fingerprint


def check_key():
    try:
        for path in reversed(KEY.parents):
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise PeerError('unsafe_key')
        if stat.S_IMODE(KEY.parent.lstat().st_mode) != 0o700:
            raise PeerError('unsafe_key')
        with os.fdopen(os.open(KEY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 16384):
                raise PeerError('unsafe_key')
    except OSError:
        raise PeerError('unsafe_key') from None


def pin_host(host, port, fingerprint, execute):
    scan = execute(['/usr/bin/ssh-keyscan', '-T', '8', '-p', port, '-t', 'ed25519', host],
                   timeout=12, limit=16384)
    if scan.returncode:
        raise PeerError('host_pin_failed')
    identity = host if port == '22' else '['+host+']:'+port
    found = set()
    for line in scan.stdout.splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) != 3 or fields[:2] != [identity, 'ssh-ed25519']:
            raise PeerError('host_pin_failed')
        try:
            wire = base64.b64decode(fields[2], validate=True)
        except ValueError:
            raise PeerError('host_pin_failed') from None
        actual = 'SHA256:'+base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip('=')
        if len(wire) != 51 or not wire.startswith(WIRE_PREFIX) or actual != fingerprint:
            raise PeerError('host_pin_failed')
        found.add(' '.join(fields))
    if len(found) != 1:
        raise PeerError('host_pin_failed')
    return next(iter(found))+'\n'


REMOTE = r'''
import json, os, platform, re, selectors, shutil, signal, stat, subprocess, time
from pathlib import Path
if os.geteuid() != 0:
    raise SystemExit(1)
def read(argv):
    try:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}, start_new_session=True)
    except OSError:
        return None
    data, deadline = bytearray(), time.monotonic()+5
    try:
        with selectors.DefaultSelector() as poller:
            poller.register(p.stdout, selectors.EVENT_READ)
            while True:
                left = deadline-time.monotonic()
                if left <= 0 or not poller.select(left):
                    return None
                part = os.read(p.stdout.fileno(), 4096)
                if not part:
                    break
                data.extend(part)
                if len(data)>16384:
                    return None
        code = p.wait(timeout=max(.001,deadline-time.monotonic()))
        return code, data.decode('utf-8')
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return None
    finally:
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait(timeout=2)
        p.stdout.close()
release = {'ID':None,'VERSION_ID':None}
try:
    with open('/etc/os-release') as f:
        text = f.read(65537)
    if len(text)<=65536:
        for line in text.splitlines():
            key, sep, value = line.partition('=')
            value = value.strip('"')
            if sep and key=='ID' and value in ('debian','ubuntu','kali'):
                release[key]=value
            if sep and key=='VERSION_ID' and re.fullmatch(r'[0-9]{1,2}(?:\.[0-9]{1,2}){0,2}',value):
                release[key]=value
except OSError:
    pass
kernel = platform.release()
if not re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}[-A-Za-z0-9.+_]{0,80}',kernel):
    kernel = None
active = read(['/usr/bin/systemctl','is-active','openvpnas.service'])
active = None if active is None or active[1].strip() not in ('active','inactive','failed','activating','deactivating','unknown') else active[1].strip()=='active'
client = {'path':None,'version':None}
for name in ('/usr/sbin/openvpn','/usr/bin/openvpn','/usr/local/openvpn_as/sbin/openvpn'):
    try:
        target=Path(name)
        for path in (*reversed(target.parents),target):
            info=path.lstat()
            if info.st_uid!=0 or info.st_mode&0o022 or not (stat.S_ISREG(info.st_mode) if path==target else stat.S_ISDIR(info.st_mode)):
                raise ValueError()
        response=read([name,'--version'])
        client['path']=name
        match=re.match(r'^OpenVPN ([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,4})?)\b',response[1]) if response is not None and response[0]==0 else None
        client['version']=match[1] if match else None
        break
    except (OSError,ValueError):
        continue
print(json.dumps({'version':1,'root_confirmed':True,'os':release,'kernel':kernel,
    'access_server_active':active,'openvpn_client':client,
    'tools':{name:shutil.which(name) is not None for name in ('ip','python3','curl','nft')}},sort_keys=True))
'''


def validate_report(value):
    try:
        def exact(item, keys):
            if not isinstance(item, dict) or set(item) != set(keys):
                raise ValueError()
        exact(value, {'version','root_confirmed','os','kernel','access_server_active','openvpn_client','tools'})
        if type(value['version']) is not int or value['version'] != 1 or value['root_confirmed'] is not True:
            raise ValueError()
        exact(value['os'], {'ID','VERSION_ID'})
        if value['os']['ID'] not in (None,'debian','ubuntu','kali'):
            raise ValueError()
        version = value['os']['VERSION_ID']
        if version is not None and (not isinstance(version,str) or not re.fullmatch(r'[0-9]{1,2}(?:\.[0-9]{1,2}){0,2}',version)):
            raise ValueError()
        kernel = value['kernel']
        if kernel is not None and (not isinstance(kernel,str) or not re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}[-A-Za-z0-9.+_]{0,80}',kernel)):
            raise ValueError()
        if value['access_server_active'] is not None and type(value['access_server_active']) is not bool:
            raise ValueError()
        exact(value['openvpn_client'], {'path','version'})
        if value['openvpn_client']['path'] not in (None,*CLIENTS):
            raise ValueError()
        version = value['openvpn_client']['version']
        if version is not None and (not isinstance(version,str) or not re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,4})?',version)):
            raise ValueError()
        exact(value['tools'], TOOLS)
        if any(type(item) is not bool for item in value['tools'].values()):
            raise ValueError()
        return value
    except (ValueError,TypeError,KeyError,AttributeError):
        raise ValueError('Unsupported peer inspection report.') from None


def inspect(host, port, fingerprint, execute=run):
    if os.geteuid() != 0:
        raise PeerError('root_required')
    host, port, fingerprint = settings(host, port, fingerprint)
    check_key()
    known = pin_host(host, port, fingerprint, execute)
    with tempfile.TemporaryDirectory(prefix='vpn-test-peer-', dir=RUNTIME) as directory:
        target = Path(directory)/'known_hosts'
        with os.fdopen(os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600),'w') as f:
            f.write(known)
        result = execute(['/usr/bin/ssh','-F','/dev/null','-T','-p',port,'-i',str(KEY),
            '-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','UserKnownHostsFile='+str(target),'-o','GlobalKnownHostsFile=/dev/null',
            '-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','ConnectTimeout=10',
            '-o','IdentityAgent=none','-o','PreferredAuthentications=publickey',
            '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
            '-o','HostKeyAlgorithms=ssh-ed25519',
            '-o','ConnectionAttempts=1','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=3',
            '-o','LogLevel=ERROR','root@'+host,'/usr/bin/python3 -I -B -'],
            input=REMOTE, timeout=35, limit=32768)
        if result.returncode:
            raise PeerError('ssh_failed')
        try:
            return validate_report(json.loads(result.stdout))
        except ValueError:
            raise PeerError('invalid_peer_report') from None


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    try:
        value=inspect(globals().get('TEST_PEER_HOST'), globals().get('TEST_PEER_PORT','22'),
                      globals().get('TEST_PEER_HOST_FINGERPRINT'))
        print(json.dumps(value,sort_keys=True))
    except (PeerError,OSError,ValueError,subprocess.SubprocessError):
        print(json.dumps({'error':'peer_inspection_failed','detail':'Read-only peer inspection failed.'}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
