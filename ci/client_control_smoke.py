"""Real Unix credentials/process descriptors in the disposable Debian container."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'vpn-dashboard'))
import session_channel as channel
import install_audit as audit


def supervisor_with_real_openvpn():
    """Exercise the actual app supervisor against the isolated server.

    The client TUN stays unconfigured. The separate kernel namespace check
    validates client firewall/DNS ownership; this fixture substitutes that check
    only to avoid replacing the server container's firewall with a client one.
    """
    command=['/usr/sbin/openvpn','--config','/root/vpn-lab/client.ovpn',
             '--auth-user-pass','/root/vpn-lab/login.txt','--auth-nocache',
             '--dev','tun-app-test','--dev-type','tun','--ifconfig-noexec','--route-noexec',
             '--user','vpn-lab-transport','--group','vpn-lab-transport','--script-security','1',
             '--connect-retry','1','--connect-timeout','10','--connect-retry-max','3']
    program=('import sys;sys.path.insert(0,'+repr(str(ROOT/'vpn-dashboard'))+');'
             'import vpn_session_helper as s;'
             's.network_setup.verify_during_session=lambda:True;'
             'raise SystemExit(s.controlled_session('+repr(command)+',1000))')
    with tempfile.TemporaryFile() as log:
        process=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',program],
                                 stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            deadline=time.monotonic()+45
            while time.monotonic()<deadline:
                try:
                    snapshot=channel.request()
                except (OSError,channel.ChannelError):
                    snapshot=None
                if snapshot and snapshot['state']=='tunnel_ready':
                    break
                if process.poll() is not None:
                    raise RuntimeError('The app supervisor exited before real TLS initialization.')
                time.sleep(.1)
            else:
                raise RuntimeError('The app supervisor did not report real tunnel initialization.')
            channel.request('stop')
            process.wait(timeout=15)
            if process.returncode:
                raise RuntimeError('The controlled OpenVPN session did not exit cleanly.')
            log.seek(0)
            text=log.read(131073).decode('utf-8',errors='replace')
            if len(text)>131072 or any(word in text for word in ('SESS_ID_','BEGIN PRIVATE','PUSH_REPLY')):
                raise RuntimeError('Raw credential-bearing transport output reached the session console.')
            if 'OpenVPN initialized the tunnel' not in text:
                raise RuntimeError('The session console did not contain controlled transport events.')
        finally:
            if process.poll() is None:
                try:
                    channel.request('stop')
                except (OSError,channel.ChannelError):
                    process.poll()  # It may already have exited and removed its socket.
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL)
                    process.wait(timeout=5)
    print('PASS: actual app supervisor over real TLS/PAM transport, private local status, filtered events and scoped Disconnect.',flush=True)


def main():
    if os.geteuid()!=0 or not Path('/.dockerenv').exists() or os.environ.get('VPN_LAB_DISPOSABLE_SERVER_TEST')!='1':
        raise RuntimeError('Use only the disposable Debian app-control harness.')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='vpn-app-test-',dir='/run') as temporary:
        base=Path(temporary)
        base.chmod(0o755)
        endpoint=base/'runtime/session.sock'
        events=channel.Events()
        events.add('starting')
        owned=subprocess.Popen(['/usr/bin/sleep','30'],user=1000,group=1000,extra_groups=[])
        other=subprocess.Popen(['/usr/bin/sleep','30'],user=1000,group=1000,extra_groups=[])
        pidfd=os.pidfd_open(owned.pid)
        def stop():
            events.add('stopping')
            signal.pidfd_send_signal(pidfd,signal.SIGTERM)
        try:
            with channel.Server(1000,events,stop,endpoint):
                script=('import sys;sys.path.insert(0,'+repr(str(ROOT/'vpn-dashboard'))+');'
                        'import session_channel as c;print(c.request(path='+repr(str(endpoint))+'))')
                result=subprocess.run(['/usr/bin/python3','-I','-B','-c',script],user=1000,group=1000,
                                      extra_groups=[],capture_output=True,text=True,timeout=5)
                if result.returncode or 'starting' not in result.stdout:
                    raise RuntimeError('The desktop owner could not read the root helper status.')
                endpoint.chmod(0o666)
                for uid,request in ((1002,b'status\n'),(1000,b'stop\n'),(1000,b'run arbitrary-command\n')):
                    script=('import socket; s=socket.socket(socket.AF_UNIX);s.settimeout(1);'
                            's.connect('+repr(str(endpoint))+');s.sendall('+repr(request)+');'
                            'print(len(s.recv(1024)))')
                    result=subprocess.run(['/usr/bin/python3','-I','-B','-c',script],user=uid,group=uid,
                                          extra_groups=[],capture_output=True,text=True,timeout=5)
                    if result.returncode==0 and result.stdout.strip()!='0':
                        raise RuntimeError('An unauthorized local control request was accepted.')
                if owned.poll() is not None:
                    raise RuntimeError('An unprivileged stop request affected the session.')
                endpoint.chmod(0o600)
                if channel.request('stop',endpoint)!={'stop_requested':True}:
                    raise RuntimeError('Root session stop was not acknowledged.')
                owned.wait(timeout=5)
                if other.poll() is not None:
                    raise RuntimeError('Session stop affected an unrelated process.')
        finally:
            os.close(pidfd)
            for process in (owned,other):
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
    # Exact filesystem ownership/hashes, rather than mocked metadata. These
    # directories belong only to this disposable container, never the host.
    files={Path(name):('fixture '+Path(name).name+'\n').encode() for name in audit.REQUIRED}
    for path,value in files.items():
        path.parent.mkdir(parents=True,exist_ok=True)
        path.parent.chmod(0o755)
        path.write_bytes(value)
        path.chmod(0o644)
    audit.MANIFEST.write_text(json.dumps(audit.make_manifest(files)))
    audit.MANIFEST.chmod(0o644)
    if audit.check()['state']!='matches_baseline':
        raise RuntimeError('The installed code baseline did not verify.')
    Path('/opt/vpn-desk/app.py').write_text('altered fixture\n')
    Path('/opt/vpn-desk/json.py').write_text('unexpected shadow module\n')
    report=audit.check()
    if report['state']!='mismatch' or 'app.py' not in report['changed'] or report['unexpected_files']!=1:
        raise RuntimeError('Code alteration or an unexpected module was not detected.')
    print('PASS: root-peer status, owner-only read access, privileged stop, PID-descriptor targeting and code-baseline mismatch detection.',flush=True)


if __name__=='__main__':
    main()
