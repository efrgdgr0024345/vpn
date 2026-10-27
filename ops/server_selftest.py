"""Read local protected credentials to test the VPN; never export their contents."""
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time


class TestFailure(RuntimeError):
    pass


def command(argv):
    result=subprocess.run(argv,capture_output=True,text=True,timeout=10,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if result.returncode:
        raise TestFailure('Required local test command failed.')
    return result.stdout


def checksum(data):
    if len(data)%2:
        data+=b'\0'
    value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while value>>16:
        value=(value&65535)+(value>>16)
    return (~value)&65535


def dns_packet(source,destination,port,identifier,ipv6=False,root_query=False):
    question=b'\0'+struct.pack('!HH',2,1) if root_query else b'\x07example\x03com\0'+struct.pack('!HH',1,1)
    dns=struct.pack('!6H',identifier,0 if root_query else 0x0100,1,0,0,0)+question
    udp=struct.pack('!HHHH',port,53,8+len(dns),0)+dns
    if ipv6:
        src,dst=socket.inet_pton(socket.AF_INET6,source),socket.inet_pton(socket.AF_INET6,destination)
        pseudo=src+dst+struct.pack('!I3xB',len(udp),17)
        value=checksum(pseudo+udp) or 65535
        udp=udp[:6]+struct.pack('!H',value)+udp[8:]
        return struct.pack('!IHBB',6<<28,len(udp),17,64)+src+dst+udp
    src,dst=socket.inet_aton(source),socket.inet_aton(destination)
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),identifier,0,64,17,0,src,dst)
    return header[:10]+struct.pack('!H',checksum(header))+header[12:]+udp


def private_counter():
    objects=json.loads(command(['/usr/sbin/nft','-j','list','ruleset']))['nftables']
    for item in objects:
        rule=item.get('rule',{})
        if rule.get('comment')=='vpn-lab-block-private':
            return sum(e['counter']['packets'] for e in rule['expr'] if 'counter' in e)
    raise TestFailure('Private-network firewall rule is missing.')


def read_private(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'r') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:
            raise TestFailure('Unsafe protected test file.')
        value=stream.read(2_000_001)
        if len(value)>2_000_000:
            raise TestFailure('Oversized protected test file.')
        return value


def update_registry(value):
    target=Path('/etc/openvpn/lab/devices.json')
    read_private(target)
    fd,name=tempfile.mkstemp(prefix='.test-policy-',dir=target.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name,target)
    finally:
        Path(name).unlink(missing_ok=True)


def test(broker_pid=None):
    if os.geteuid()!=0:
        raise TestFailure('Self-test requires local root on the lab server.')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.umask(0o077)
    profile=read_private('/root/vpn-lab/client.ovpn')
    login=read_private('/root/vpn-lab/login.txt')
    policy_before=read_private('/etc/openvpn/lab/devices.json')
    if not all(json.loads(policy_before).get(name,{}).get('enabled') for name in ('kali','iphone','android')):
        raise TestFailure('All three lab test identities must be enabled before this disruptive self-test.')
    if broker_pid is None:
        value=command(['/usr/bin/systemctl','show','vpn-lab-broker.service','--property=MainPID','--value']).strip()
        if not value.isdigit() or int(value)<=1:
            raise TestFailure('Authorization broker is not running.')
        broker_pid=int(value)
    values=login.splitlines()
    if len(values)!=2 or values[0]!='vpn-lab-client':
        raise TestFailure('Protected local test credentials are invalid.')
    # The client tunnel stays unconfigured: no host address, route, resolver or
    # default gateway is changed. AF_PACKET sends/receives only on this test TUN.
    profile=re.sub(r'^remote .*$', 'remote 127.0.0.1 1194', profile, flags=re.M)
    processes=[]
    managers=[]
    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL)
                process.wait()
    with tempfile.TemporaryDirectory(prefix='vpn-lab-test-',dir='/run') as directory, \
            os.fdopen(os.pidfd_open(broker_pid),'rb') as broker_handle:
        root=Path(directory)
        def start(name,password,device='kali'):
            selected=profile if device=='kali' else read_private('/root/vpn-lab/devices/'+device+'/client.ovpn')
            selected=re.sub(r'^remote .*$', 'remote 127.0.0.1 1194', selected, flags=re.M)
            config,auth,log=root/(name+'.ovpn'),root/(name+'.auth'),root/(name+'.log')
            for path,value in ((config,selected),(auth,values[0]+'\n'+password+'\n')):
                fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                with os.fdopen(fd,'w') as stream:
                    stream.write(value)
            # Popen duplicates stdout into the child; close the parent's copy
            # immediately after spawn rather than retaining it for the whole test.
            with open(log,'wb') as output:
                os.chmod(log,0o600)
                extra=[]
                if name=='lab-check':
                    extra=['--management',str(root/'token-observer'),'unix','--management-client-user','root']
                process=subprocess.Popen(['/usr/sbin/openvpn','--config',str(config),
                     '--auth-user-pass',str(auth),'--auth-nocache','--dev','tun-'+name,
                     '--dev-type','tun','--ifconfig-noexec','--route-noexec',
                     '--connect-retry','1','--connect-timeout','5','--connect-retry-max','1',
                     '--user','vpn-lab-transport','--group','vpn-lab-transport',
                     '--reneg-sec','5',
                     '--script-security','1']+extra,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,
                     start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            processes.append(process)
            if extra:
                observer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                observer.settimeout(.2)
                end=time.monotonic()+3
                while True:
                    try:
                        observer.connect(str(root/'token-observer'))
                        break
                    except (FileNotFoundError,ConnectionRefusedError):
                        if time.monotonic()>=end:
                            observer.close()
                            raise TestFailure('Local token observer did not start.')
                        time.sleep(.05)
                managers.append(observer)
            return process,log
        def initialized(process,log,seconds):
            end=time.monotonic()+seconds
            while time.monotonic()<end:
                if 'Initialization Sequence Completed' in log.read_text(errors='replace'):
                    return True
                if process.poll() is not None:
                    return False
                time.sleep(0.1)
            return False
        try:
            bad,badlog=start('lab-bad',secrets.token_urlsafe(32))
            if initialized(bad,badlog,12):
                raise TestFailure('An incorrect password was accepted.')
            stop(bad)
            if 'AUTH_FAILED' not in badlog.read_text(errors='replace'):
                raise TestFailure('Wrong-password rejection was not observed.')
            changed=json.loads(policy_before)
            changed['android']['sha256']='0'*64
            update_registry(json.dumps(changed)+'\n')
            try:
                time.sleep(1.2)
                denied,deniedlog=start('lab-unapproved',values[1],'android')
                if initialized(denied,deniedlog,12):
                    raise TestFailure('An unapproved certificate pin obtained access.')
                stop(denied)
                if 'AUTH_FAILED' not in deniedlog.read_text(errors='replace'):
                    raise TestFailure('Unapproved-device denial was not observed.')
            finally:
                update_registry(policy_before)
            time.sleep(1.2)
            good,goodlog=start('lab-check',values[1])
            if not initialized(good,goodlog,20):
                raise TestFailure('The local valid-credential VPN handshake failed.')
            observed=b''
            token=None
            end=time.monotonic()+3
            while time.monotonic()<end:
                try:
                    observed+=managers[0].recv(4096)
                except socket.timeout:
                    continue
                if len(observed)>32768:
                    raise TestFailure('Local token observer overflowed.')
                lines=observed.split(b'\n')[:-1]
                candidates=[line.split(b':',2)[-1].strip() for line in lines
                            if line.startswith(b'>PASSWORD:Auth-Token:')]
                if candidates:
                    token=candidates[-1].decode('ascii')
                    break
            if not token or not re.fullmatch(r'SESS_ID_AT_[A-Za-z0-9+/=]{40,256}',token):
                raise TestFailure('A server-issued session token was not observed privately.')
            text=goodlog.read_text(errors='replace')
            match=re.search(r'ifconfig (172\.27\.240\.\d+) 255\.255\.255\.0',text)
            if not match:
                raise TestFailure('Could not establish the assigned VPN client address.')
            source=match.group(1)
            if ipaddress.ip_address(source) not in ipaddress.ip_network('172.27.240.0/24'):
                raise TestFailure('Unexpected test client address.')
            command(['/usr/sbin/ip','link','set','dev','tun-lab-check','up'])
            channel=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
            try:
                channel.bind(('tun-lab-check',0))
                channel.settimeout(0.25)
                def public_dns():
                    identifier=secrets.randbelow(65536)
                    port=35000+secrets.randbelow(20000)
                    # Ask a root authoritative nameserver about the root zone.
                    # This tests Internet NAT, not a third-party recursive VPN
                    # DNS provider. In CI this address is a local simulator.
                    packet=dns_packet(source,'198.41.0.4',port,identifier,root_query=True)
                    end=time.monotonic()+8
                    retry=0.0
                    while time.monotonic()<end:
                        if time.monotonic()>=retry:
                            try:
                                channel.send(packet)
                            except OSError:
                                return False
                            retry=time.monotonic()+1
                        try:
                            reply,address=channel.recvfrom(4096)
                        except socket.timeout:
                            continue
                        except OSError:
                            return False
                        if address[2]==socket.PACKET_OUTGOING or not reply or reply[0]>>4!=4:
                            continue
                        offset=(reply[0]&15)*4
                        if len(reply)<offset+20 or reply[9]!=17:
                            continue
                        sport,dport=struct.unpack('!HH',reply[offset:offset+4])
                        transaction,flags=struct.unpack('!HH',reply[offset+8:offset+12])
                        if sport==53 and dport==port and transaction==identifier and flags&0x8000:
                            return True
                    return False
                if not public_dns():
                    raise TestFailure('DNS roundtrip through VPN forwarding/NAT failed.')
                # Query the VPS-owned resolver, not a client-side public DNS
                # service. The existing public fixture also tests IPv4 NAT.
                identifier=secrets.randbelow(65536)
                channel.send(dns_packet(source,'172.27.240.1',35005,identifier))
                private_dns=False
                end=time.monotonic()+8
                while time.monotonic()<end:
                    try:
                        reply,address=channel.recvfrom(4096)
                    except socket.timeout:
                        continue
                    if address[2]==socket.PACKET_OUTGOING or not reply or reply[0]>>4!=4:
                        continue
                    offset=(reply[0]&15)*4
                    if (len(reply)>=offset+20 and reply[9]==17
                            and reply[12:16]==socket.inet_aton('172.27.240.1')
                            and struct.unpack('!HH',reply[offset:offset+4])==(53,35005)):
                        transaction,flags=struct.unpack('!HH',reply[offset+8:offset+12])
                        if transaction==identifier and flags&0x8000 and flags&15==0:
                            private_dns=True
                            break
                if not private_dns:
                    raise TestFailure('The private VPN resolver did not answer an authorized query.')
                # Remove the initial password file and force a real TLS rekey.
                # Reauthentication must use the server-issued token, not reread
                # the known password from disk after dropping privileges.
                (root/'lab-check.auth').unlink()
                end=time.monotonic()+16
                while time.monotonic()<end:
                    text=goodlog.read_text(errors='replace')
                    if ('TLS: soft reset' in text and text.count('Control Channel:')>=2):
                        break
                    if good.poll() is not None:
                        raise TestFailure('Token-based TLS reauthentication failed.')
                    time.sleep(.2)
                else:
                    raise TestFailure('Token-based TLS reauthentication was not observed.')
                if not public_dns():
                    raise TestFailure('Token renewal interrupted authorized packet forwarding.')
                before=private_counter()
                channel.send(dns_packet(source,'169.254.169.254',35001,1234))
                end=time.monotonic()+3
                while time.monotonic()<end and private_counter()<=before:
                    time.sleep(0.1)
                if private_counter()<=before:
                    raise TestFailure('Metadata/private-network packet filtering was not observed.')
                ipv6=re.search(r'ifconfig-ipv6 ([0-9a-f:]+)/64',text,re.I)
                if not ipv6:
                    raise TestFailure('IPv6 confinement options were not received.')
                channel.send(dns_packet(ipv6.group(1),'2001:db8::53',35002,2345,True))
                blocked=False
                end=time.monotonic()+3
                while time.monotonic()<end:
                    try:
                        reply,address=channel.recvfrom(4096)
                    except socket.timeout:
                        continue
                    if (address[2]!=socket.PACKET_OUTGOING and len(reply)>=41
                            and reply[0]>>4==6 and reply[6]==58 and reply[40]==1):
                        blocked=True
                        break
                if not blocked:
                    raise TestFailure('Client IPv6 block response was not observed.')
                second,secondlog=start('lab-second',values[1],'iphone')
                if initialized(second,secondlog,6):
                    raise TestFailure('A second simultaneous client was accepted.')
                stop(second)
                if good.poll() is not None or not public_dns():
                    raise TestFailure('A second connection attempt displaced the active session.')
                # The broker is frozen rather than cleanly stopped: no cleanup
                # handler can hide a missing kernel timeout. Established flows
                # must lose access in both directions once the set expires.
                signal.pidfd_send_signal(broker_handle.fileno(),signal.SIGSTOP)
                try:
                    time.sleep(22)
                    if public_dns():
                        raise TestFailure('Forwarding survived an expired kernel lease.')
                finally:
                    signal.pidfd_send_signal(broker_handle.fileno(),signal.SIGCONT)
                # A resumed broker must reject stale queued liveness events.
                end=time.monotonic()+5
                while time.monotonic()<end and good.poll() is None:
                    time.sleep(.1)
                stop(good)
            finally:
                channel.close()
            # OpenVPN schedules peer retirement five seconds after HALT/EXIT.
            # Let the old transport actually retire before testing another one;
            # killing a half-open replay would otherwise occupy max-clients.
            time.sleep(6)
            # Force the disconnect-before-kill ordering rather than relying on
            # runner scheduling to expose it. A valid old token can establish
            # transport internally, but the stopped broker cannot grant packets.
            signal.pidfd_send_signal(broker_handle.fileno(),signal.SIGSTOP)
            try:
                replay,replaylog=start('lab-replay',token)
                if not initialized(replay,replaylog,20):
                    raise TestFailure('The replay transport did not reach the stale-command test.')
                elements=json.loads(command(['/usr/sbin/nft','-j','list','set','inet','vpn_lab','authorized']))
                if any(item.get('set',{}).get('elem') for item in elements['nftables']):
                    raise TestFailure('A replayed session token obtained a forwarding grant.')
                stop(replay)
                time.sleep(6)
            finally:
                signal.pidfd_send_signal(broker_handle.fileno(),signal.SIGCONT)
            time.sleep(.5)
            if select.select([broker_handle],[],[],0)[0]:
                raise TestFailure('The broker exited during a disconnected replay rejection.')
            phone,phonelog=start('lab-phone',values[1],'iphone')
            if not initialized(phone,phonelog,20):
                raise TestFailure('Ownership could not transfer to the next enrolled device.')
            text=phonelog.read_text(errors='replace')
            if 'ifconfig 172.27.240.11 255.255.255.0' not in text:
                raise TestFailure('The next enrolled device received an unexpected address.')
            source='172.27.240.11'
            command(['/usr/sbin/ip','link','set','dev','tun-lab-phone','up'])
            channel=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
            try:
                channel.bind(('tun-lab-phone',0))
                channel.settimeout(.25)
                if not public_dns():
                    raise TestFailure('The new session owner could not forward packets.')
            finally:
                channel.close()
            # A normal user disconnect must release the global slot promptly,
            # rather than waiting for the server's 60-second dead-peer timer.
            stop(phone)
            time.sleep(1)
            android,androidlog=start('lab-release',values[1],'android')
            if not initialized(android,androidlog,12):
                raise TestFailure('A normal disconnect did not promptly release the session slot.')
            if 'ifconfig 172.27.240.12 255.255.255.0' not in androidlog.read_text(errors='replace'):
                raise TestFailure('Android identity did not receive its distinct address.')
            source='172.27.240.12'
            command(['/usr/sbin/ip','link','set','dev','tun-lab-release','up'])
            channel=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
            try:
                channel.bind(('tun-lab-release',0))
                channel.settimeout(.25)
                if not public_dns():
                    raise TestFailure('Packet forwarding failed after a normal ownership release.')
                changed=json.loads(policy_before)
                changed['android']['enabled']=False
                update_registry(json.dumps(changed)+'\n')
                time.sleep(2)
                if public_dns():
                    raise TestFailure('A revoked device retained packet forwarding.')
            finally:
                channel.close()
                update_registry(policy_before)
            if select.select([broker_handle],[],[],0)[0]:
                raise TestFailure('The original broker did not survive the complete acceptance test.')
            return {'correct_credentials_connect':True,'wrong_password_rejected':True,
                    'ipv4_dns_roundtrip_through_vpn_and_nat':True,
                    'metadata_private_network_packet_dropped':True,
                    'client_ipv6_block_response_observed':True,
                    'second_connection_rejected_without_displacing_first':True,
                    'unapproved_device_rejected':True,'session_token_reauthentication':True,
                    'kernel_lease_expires_when_broker_frozen':True,
                    'ownership_transfers_between_devices':True,'device_revocation_denies_forwarding':True,
                    'replayed_session_token_denied':True,
                    'disconnected_replay_preserves_broker':True,
                    'normal_disconnect_releases_slot':True,
                    'private_vpn_resolver_answers':True,
                    'host_routes_and_resolver_modified':False,
                    'credentials_exported':False}
        finally:
            update_registry(policy_before)
            for process in reversed(processes):
                stop(process)
            for manager in managers:
                manager.close()


if __name__=='__main__':
    try:
        print(json.dumps(test(),sort_keys=True))
    except (TestFailure,OSError,ValueError,subprocess.SubprocessError) as exc:
        detail=str(exc) if isinstance(exc,TestFailure) else 'Protected local test command failed.'
        print(json.dumps({'error':'selftest_failed','detail':detail}))
        raise SystemExit(1)
