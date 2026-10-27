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
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ops'))
import server_foundation as foundation
import server_selftest


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid()!=0
            or os.environ.get('VPN_LAB_DISPOSABLE_SERVER_TEST')!='1'):
        raise SystemExit('Use only the disposable server test harness.')
    Path('/dev/net').mkdir(exist_ok=True)
    if not Path('/dev/net/tun').exists():
        os.mknod('/dev/net/tun',stat.S_IFCHR|0o600,os.makedev(10,200))
    endpoint=socket.gethostbyname(socket.gethostname())
    report=foundation.install(endpoint,22,True)
    print(json.dumps(report,sort_keys=True),flush=True)
    profile=Path('/root/vpn-lab/client.ovpn')
    login=Path('/root/vpn-lab/login.txt')
    before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in (profile,login)]
    foundation.install(endpoint,22,True)
    if before!=[hashlib.sha256(p.read_bytes()).hexdigest() for p in (profile,login)]:
        raise SystemExit('Installer rerun changed existing client credentials.')
    foundation.run(['/usr/sbin/ip','route','replace','9.9.9.9/32','via',sys.argv[1]])
    log=Path('/run/vpn-server-test.log')
    Path('/run/openvpn-server').mkdir(mode=0o700,exist_ok=True)
    with open(log,'wb') as output:
        os.chmod(log,0o600)
        server=subprocess.Popen(['/usr/sbin/openvpn','--config','/etc/openvpn/server/vpn-lab.conf'],
                                stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
        broker=subprocess.Popen(['/usr/bin/python3','-I','-B','/test/ops/session_broker.py'],
                                stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
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
            print(json.dumps(server_selftest.test(broker.pid),sort_keys=True),flush=True)
        finally:
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
        detail='Integration infrastructure or cleanup failed.'
        if isinstance(exc,(server_selftest.TestFailure,foundation.SetupError,RuntimeError)):
            candidate=str(exc)
            if re.fullmatch(r'[A-Za-z0-9 ,/_.()\-]{1,180}',candidate):
                detail=candidate
        print('::error title=VPN lab integration::'+detail,flush=True)
        raise SystemExit(1)
