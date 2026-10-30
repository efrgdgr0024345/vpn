"""Real Unix credentials/process descriptors in the disposable Debian container."""
import json
import os
import re
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
import vpn_session_helper as transport


def supervisor_with_real_openvpn():
    """Exercise the actual app supervisor against the isolated server.

    IPv6 automatic address generation is disabled on the pre-created client TUN;
    the real engine must configure IPv4 and ignore the server's IPv6 pushes.
    Routes stay unmodified. Host-wide IPv6 disablement needs physical acceptance.
    The separate namespace check validates client firewall/DNS ownership; this
    fixture substitutes that check to preserve the server container's firewall.
    """
    command=['/usr/sbin/openvpn','--config','/root/vpn-lab/client.ovpn',
             '--auth-user-pass','/root/vpn-lab/login.txt','--auth-nocache',
             '--dev','tun-app-test','--dev-type','tun','--route-noexec',
             '--user','vpn-lab-transport','--group','vpn-lab-transport','--script-security','1',
             '--connect-retry','1','--connect-timeout','10','--connect-retry-max','3']
    command += transport.ipv4_options('udp')
    command += transport.userspace_options(command[0])
    subprocess.run(['/usr/sbin/ip','tuntap','add','dev','tun-app-test','mode','tun'],check=True,timeout=5)
    subprocess.run(['/usr/sbin/ip','link','set','dev','tun-app-test','addrgenmode','none'],check=True,timeout=5)
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
            addresses=json.loads(subprocess.check_output(
                ['/usr/sbin/ip','-j','address','show','dev','tun-app-test'],text=True,timeout=5))
            families={item['family'] for link in addresses for item in link.get('addr_info',[])}
            if 'inet' not in families or 'inet6' in families:
                raise RuntimeError('The real client did not configure IPv4 while ignoring IPv6 server pushes.')
            if (snapshot['details'].get('server_port')!=1194 or snapshot['details'].get('protocol')!='udp4'
                    or not snapshot['details'].get('tunnel_ipv4')
                    or snapshot['details'].get('tls_version')!='TLSv1.3'):
                raise RuntimeError('The live client log omitted its verified endpoint, tunnel or TLS details.')
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
            subprocess.run(['/usr/sbin/ip','tuntap','del','dev','tun-app-test','mode','tun'],check=True,timeout=5)
    print('PASS: app supervisor over real TLS/PAM, IPv4-only tunnel addressing despite IPv6 server pushes, private status and scoped Disconnect.',flush=True)


def timeout_without_server():
    with tempfile.TemporaryDirectory(prefix='vpn-no-reply-',dir='/run') as directory:
        profile=Path(directory)/'client.ovpn'
        original=Path('/root/vpn-lab/client.ovpn').read_text()
        profile.write_text(re.sub(r'^remote .*$', 'remote 127.0.0.1 61194', original, flags=re.M))
        profile.chmod(0o600)
        command=['/usr/sbin/openvpn','--config',str(profile),
                 '--auth-user-pass','/root/vpn-lab/login.txt','--auth-nocache','--dev','tun-no-reply',
                 '--dev-type','tun','--ifconfig-noexec','--route-noexec','--script-security','1']
        command+=transport.ipv4_options('udp')
        program=('import sys;sys.path.insert(0,'+repr(str(ROOT/'vpn-dashboard'))+');'
                 'import vpn_session_helper as s;w=s.StartupWatch;'
                 's.StartupWatch=lambda now:w(now,network_seconds=2,overall_seconds=4);'
                 's.network_setup.verify_during_session=lambda:True;'
                 'raise SystemExit(s.controlled_session('+repr(command)+',1000))')
        result=subprocess.run(['/usr/bin/python3','-I','-B','-c',program],
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20)
        record=json.loads((channel.HISTORY/'1000.json').read_text())
        snapshot=channel.validate_snapshot(record['snapshot'])
        if (result.returncode==0 or snapshot['state']!='error'
                or 'server_timeout' not in {row['code'] for row in snapshot['events']}
                or snapshot['details'].get('server_ipv4')!='127.0.0.1'
                or snapshot['details'].get('server_port')!=61194
                or any(word in result.stdout for word in (b'SESS_ID_',b'BEGIN PRIVATE',b'PUSH_REPLY'))):
            raise RuntimeError('No-reply timeout or private last-attempt diagnostics did not match policy.')
    print('PASS: real OpenVPN no-reply timeout stops the owned child and retains endpoint/stage diagnostics without secrets.',flush=True)


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
                channel.save_last(1000,events.snapshot(),0)
                for uid in (1000,1002):
                    script=(('import sys;sys.path.insert(0,'+repr(str(ROOT/'vpn-dashboard'))+');'
                             'import session_channel as c;c.read_last();print("readable")') if uid==1000 else
                            'from pathlib import Path;Path("/var/lib/vpn-desk-history/1000.json").read_bytes();print("readable")')
                    result=subprocess.run(['/usr/bin/python3','-I','-B','-c',script],
                        user=uid,group=uid,extra_groups=[],capture_output=True,text=True,timeout=5)
                    if (uid==1000)!=(result.returncode==0):
                        raise RuntimeError('Private last-attempt history was not scoped to its desktop owner.')
                script='from pathlib import Path;Path("/var/lib/vpn-desk-history/1000.json").write_text("tamper")'
                result=subprocess.run(['/usr/bin/python3','-I','-B','-c',script],user=1000,group=1000,
                                      extra_groups=[],capture_output=True,text=True,timeout=5)
                if result.returncode==0:
                    raise RuntimeError('The desktop owner could modify privileged saved session history.')
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
