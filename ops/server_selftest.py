"""Read local protected credentials to test the VPN; never export their contents."""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
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


def dns_packet(source,destination,port,identifier,ipv6=False):
    dns=struct.pack('!6H',identifier,0x0100,1,0,0,0)+b'\x07example\x03com\0'+struct.pack('!HH',1,1)
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


def test():
    if os.geteuid()!=0:
        raise TestFailure('Self-test requires local root on the lab server.')
    profile=Path('/root/vpn-lab/client.ovpn').read_text()
    login=Path('/root/vpn-lab/login.txt').read_text()
    values=login.splitlines()
    if len(values)!=2 or values[0]!='vpn-lab-client':
        raise TestFailure('Protected local test credentials are invalid.')
    # The client tunnel stays unconfigured: no host address, route, resolver or
    # default gateway is changed. AF_PACKET sends/receives only on this test TUN.
    profile=re.sub(r'^remote .*$', 'remote 127.0.0.1 1194', profile, flags=re.M)
    processes=[]
    files=[]
    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL)
                process.wait()
    with tempfile.TemporaryDirectory(prefix='vpn-lab-test-',dir='/run') as directory:
        root=Path(directory)
        def start(name,password):
            config,auth,log=root/(name+'.ovpn'),root/(name+'.auth'),root/(name+'.log')
            for path,value in ((config,profile),(auth,values[0]+'\n'+password+'\n')):
                fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                with os.fdopen(fd,'w') as stream:
                    stream.write(value)
            output=open(log,'wb')
            os.chmod(log,0o600)
            files.append(output)
            process=subprocess.Popen(['/usr/sbin/openvpn','--config',str(config),
                 '--auth-user-pass',str(auth),'--auth-nocache','--dev','tun-'+name,
                 '--dev-type','tun','--ifconfig-noexec','--route-noexec',
                 '--connect-retry','1','--connect-timeout','5','--connect-retry-max','1',
                 '--user','vpn-lab-transport','--group','vpn-lab-transport',
                 '--script-security','1'],stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,
                 start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            processes.append(process)
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
            good,goodlog=start('lab-check',values[1])
            if not initialized(good,goodlog,20):
                raise TestFailure('The local valid-credential VPN handshake failed.')
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
                    packet=dns_packet(source,'9.9.9.9',port,identifier)
                    end=time.monotonic()+8
                    retry=0.0
                    while time.monotonic()<end:
                        if time.monotonic()>=retry:
                            channel.send(packet)
                            retry=time.monotonic()+1
                        try:
                            reply,address=channel.recvfrom(4096)
                        except socket.timeout:
                            continue
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
                channel.send(dns_packet(ipv6.group(1),'2001:4860:4860::8888',35002,2345,True))
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
                second,secondlog=start('lab-second',values[1])
                if initialized(second,secondlog,6):
                    raise TestFailure('A second simultaneous client was accepted.')
                stop(second)
                if good.poll() is not None or not public_dns():
                    raise TestFailure('A second connection attempt displaced the active session.')
            finally:
                channel.close()
            return {'correct_credentials_connect':True,'wrong_password_rejected':True,
                    'ipv4_dns_roundtrip_through_vpn_and_nat':True,
                    'metadata_private_network_packet_dropped':True,
                    'client_ipv6_block_response_observed':True,
                    'second_connection_rejected_without_displacing_first':True,
                    'host_routes_and_resolver_modified':False,
                    'credentials_exported':False}
        finally:
            for process in reversed(processes):
                stop(process)
            for output in files:
                output.close()


if __name__=='__main__':
    try:
        print(json.dumps(test(),sort_keys=True))
    except (TestFailure,OSError,ValueError,subprocess.SubprocessError) as exc:
        detail=str(exc) if isinstance(exc,TestFailure) else 'Protected local test command failed.'
        print(json.dumps({'error':'selftest_failed','detail':detail}))
        raise SystemExit(1)
