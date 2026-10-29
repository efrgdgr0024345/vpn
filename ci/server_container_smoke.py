import hashlib
import json
import os
import re
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ops'))
import server_foundation as foundation
import server_selftest
import device_admin
sys.path.insert(0,str(ROOT/'ci'))
import client_control_smoke
PHASE='preflight'


def old_password_rejected(login):
    with tempfile.TemporaryDirectory(prefix='vpn-old-credential-',dir='/run') as directory:
        path=Path(directory)/'auth'
        path.write_bytes(login)
        path.chmod(0o600)
        with tempfile.TemporaryFile() as output:
            process=subprocess.Popen(['/usr/sbin/openvpn','--config','/root/vpn-lab/client.ovpn',
                '--auth-user-pass',str(path),'--auth-nocache','--dev','tun-old-secret',
                '--dev-type','tun','--ifconfig-noexec','--route-noexec','--connect-retry','1',
                '--connect-timeout','5','--connect-retry-max','2','--script-security','1'],
                stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            try:
                end=time.monotonic()+15
                while time.monotonic()<end:
                    output.seek(0)
                    text=output.read(131073).decode(errors='replace')
                    if len(text)>131072 or 'Initialization Sequence Completed' in text:
                        raise RuntimeError('Old credential test overflowed or unexpectedly connected.')
                    if 'AUTH_FAILED' in text:
                        return
                    if process.poll() is not None:
                        break
                    time.sleep(.1)
                raise RuntimeError('The previous password was not observed being rejected.')
            finally:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGTERM)
                    process.wait(timeout=5)


def main():
    global PHASE
    if (not Path('/.dockerenv').is_file() or os.geteuid()!=0
            or os.environ.get('VPN_LAB_DISPOSABLE_SERVER_TEST')!='1'):
        raise SystemExit('Use only the disposable server test harness.')
    Path('/dev/net').mkdir(exist_ok=True)
    if not Path('/dev/net/tun').exists():
        os.mknod('/dev/net/tun',stat.S_IFCHR|0o600,os.makedev(10,200))
    endpoint=socket.gethostbyname(socket.gethostname())
    PHASE='foundation installation'
    report=foundation.install(endpoint,22,True)
    print(json.dumps(report,sort_keys=True),flush=True)
    profile=Path('/root/vpn-lab/client.ovpn')
    login=Path('/root/vpn-lab/login.txt')
    before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in (profile,login)]
    PHASE='idempotent installation'
    foundation.install(endpoint,22,True)
    if before!=[hashlib.sha256(p.read_bytes()).hexdigest() for p in (profile,login)]:
        raise SystemExit('Installer rerun changed existing client credentials.')
    foundation.run(['/usr/sbin/ip','route','replace','198.41.0.4/32','via',sys.argv[1]])
    log=Path('/run/vpn-server-test.log')
    Path('/run/openvpn-server').mkdir(mode=0o700,exist_ok=True)
    with open(log,'wb') as output:
        PHASE='daemon startup'
        os.chmod(log,0o600)
        server=subprocess.Popen(['/usr/sbin/openvpn','--config','/etc/openvpn/server/vpn-lab.conf'],
                                stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
        broker=subprocess.Popen(['/usr/bin/python3','-I','-B','/test/ops/session_broker.py'],
                                stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
        resolver=subprocess.Popen(['/usr/sbin/unbound','-d'],stdout=output,stderr=subprocess.STDOUT,
                                  start_new_session=True)
        try:
            end=time.monotonic()+15
            while time.monotonic()<end:
                if 'Initialization Sequence Completed' in log.read_text(errors='replace'):
                    break
                if server.poll() is not None:
                    raise RuntimeError('Distribution OpenVPN server exited before initialization.')
                time.sleep(.1)
            else:
                raise RuntimeError('OpenVPN server initialization timed out.')
            PHASE='live VPN packet and token tests'
            print(json.dumps(server_selftest.test(broker.pid),sort_keys=True),flush=True)
            PHASE='owned app supervisor'
            client_control_smoke.supervisor_with_real_openvpn()
            PHASE='real password recovery'
            old_login=login.read_bytes()
            real_run=foundation.run
            def lifecycle(argv,**kwargs):
                nonlocal server,broker
                if argv==['/usr/bin/systemctl','stop','openvpn-server@vpn-lab.service']:
                    for process in (broker,server):
                        if process.poll() is None:
                            try:
                                os.killpg(process.pid,signal.SIGTERM)
                            except ProcessLookupError:
                                process.poll()  # Reap a daemon already stopped by its broker.
                            process.wait(timeout=10)
                    return ''
                if argv==['/usr/bin/systemctl','start','openvpn-server@vpn-lab.service']:
                    server=subprocess.Popen(['/usr/sbin/openvpn','--config','/etc/openvpn/server/vpn-lab.conf'],
                        stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
                    broker=subprocess.Popen(['/usr/bin/python3','-I','-B','/test/ops/session_broker.py'],
                        stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
                    return ''
                return real_run(argv,**kwargs)
            # Only systemd lifecycle is substituted in the container. PAM,
            # chpasswd, private writes, nft revocation and daemon restart are real.
            with patch.object(foundation,'run',side_effect=lifecycle):
                recovery=device_admin.administer('rotate-password')
            if login.read_bytes()==old_login or recovery.get('credential_contents_returned') is not False:
                raise RuntimeError('Private password recovery did not replace the known credential.')
            old_password_rejected(old_login)
            client_control_smoke.supervisor_with_real_openvpn()
            print('PASS: real PAM password replacement, old-password rejection, fresh-password login and daemon/token reset.',flush=True)
        except Exception:
            print('::notice title=VPN lab daemon state::'+json.dumps({
                'server_exit':server.poll(),'broker_exit':broker.poll(),
                'resolver_exit':resolver.poll()},sort_keys=True),flush=True)
            raise
        finally:
            PHASE='daemon cleanup after '+PHASE
            if resolver.poll() is None:
                os.killpg(resolver.pid,signal.SIGTERM)
                resolver.wait(timeout=5)
            if broker.poll() is None:
                os.killpg(broker.pid,signal.SIGTERM)
                broker.wait(timeout=5)
            if server.poll() is None:
                os.killpg(server.pid,signal.SIGTERM)
                server.wait(timeout=10)
    print('PASS: real TLS/PAM login, bad-password rejection, NAT/DNS packets, private/IPv6 containment, exclusive session and repeat installation.')


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        # Keep a useful, secret-free diagnostic readable through the Checks API
        # when the runner's signed log-download host is unavailable. Never dump
        # subprocess arguments, raw VPN logs or exception locals.
        detail='Integration failed during '+PHASE+' ('+type(exc).__name__+').'
        if isinstance(exc,(server_selftest.TestFailure,foundation.SetupError,RuntimeError)):
            candidate=str(exc)
            if re.fullmatch(r'[A-Za-z0-9 ,/_.()\-]{1,180}',candidate):
                detail=candidate
        print('::error title=VPN lab integration::'+detail,flush=True)
        raise SystemExit(1)
