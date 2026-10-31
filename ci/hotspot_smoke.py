"""Real DHCP, DNS redirection, NAT and no-uplink-fallback in fresh namespaces."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'vpn-dashboard'),str(ROOT/'ops')]
import firewall_policy
import portal_helper
import vpn_hotspot

POLICY={'wifi_interface':'wlan0','vpn_server_ipv4':'170.64.224.131','vpn_port':1194,
        'vpn_protocol':'udp','dhcp_server_ipv4':'192.0.2.1','server_name':'VPNLabServer'}
PEER=r'''
import json,select,socket,struct,sys
print('ready',flush=True)
if sys.stdin.readline().strip()!='start':raise SystemExit(1)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('172.27.240.1',53))
e=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);e.bind(('203.0.113.7',9000))
t=socket.socket();t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);t.bind(('172.27.240.1',53));t.listen()
sources=[]
def answer(query):return query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('203.0.113.7')
while True:
    ready,_,_=select.select([sys.stdin,u,e,t],[],[],1)
    for item in ready:
        if item==sys.stdin:
            text=sys.stdin.readline().strip()
            if text=='stats':print(json.dumps(sources),flush=True)
            else:raise SystemExit()
        elif item==t:
            c,a=t.accept();c.settimeout(2)
            try:
                prefix=c.recv(2);length=int.from_bytes(prefix,'big');query=b''
                while len(query)<length:query+=c.recv(length-len(query))
                response=answer(query);c.sendall(len(response).to_bytes(2,'big')+response);sources.append(a[0])
            finally:c.close()
        else:
            query,a=item.recvfrom(4096);sources.append(a[0]);item.sendto(answer(query) if item==u else b'echo-ok',a)
'''
PROBE=r'''
import socket,struct,sys
mode=sys.argv[1]
query=struct.pack('!6H',1234,256,1,0,0,0)+b'\x07example\x03com\x00\x00\x01\x00\x01'
if mode=='dhcp':
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'phone0\0');s.bind(('',68));s.settimeout(4)
    packet=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,0,777,0,0x8000,b'\0'*4,b'\0'*4,b'\0'*4,b'\0'*4,b'\x02\x00\x00\x00\x00\x02'+b'\0'*10,b'\0'*64,b'\0'*128)+b'\x63\x82\x53\x63\x35\x01\x01\x37\x02\x03\x06\xff'
    s.sendto(packet,('255.255.255.255',67));data=s.recv(4096)
    assert data[0]==2 and int.from_bytes(data[4:8],'big')==777
    opts={};at=240
    while at<len(data) and data[at]!=255:
        if data[at]==0:at+=1;continue
        code,length=data[at:at+2];opts[code]=data[at+2:at+2+length];at+=2+length
    assert opts[6]==socket.inet_aton('172.27.240.1') and opts[3]==socket.inet_aton('10.77.0.1')
else:
    tcp=mode=='tcp';s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM);s.settimeout(1)
    dns=mode in ('dns','tcp','blocked-dns');target=('8.8.8.8',53) if dns else ('203.0.113.7',9000)
    try:
        s.connect(target)
        s.sendall(len(query).to_bytes(2,'big')+query if tcp else query if dns else b'fixture')
        data=s.recv(4096)
        if mode.startswith('blocked'):raise AssertionError('Traffic escaped without VPN route')
        if tcp:data=data[2:]
        assert data[:2]==query[:2] if dns else data==b'echo-ok'
    except socket.timeout:
        if not mode.startswith('blocked'):raise
print('pass')
'''

def command(argv,data=None):
    return subprocess.run(argv,input=data,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          check=True,timeout=10).stdout


def child():
    if os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):
        raise RuntimeError('Refusing the host network namespace.')
    peer=phone=dhcp=None
    with tempfile.TemporaryDirectory(prefix='hotspot-fixture-',dir='/run') as directory:
        try:
            command(['/usr/sbin/ip','link','set','lo','up'])
            peer=subprocess.Popen(['/usr/bin/unshare','--net','--','/usr/bin/python3','-I','-B','-c',PEER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
            if not select.select([peer.stdout],[],[],5)[0] or peer.stdout.readline().strip()!='ready':raise RuntimeError('Peer did not prepare.')
            phone=subprocess.Popen(['/usr/bin/unshare','--net','--','sleep','infinity'])
            deadline=time.monotonic()+3
            while os.readlink('/proc/'+str(phone.pid)+'/ns/net')==os.readlink('/proc/self/ns/net'):
                if time.monotonic()>deadline:raise RuntimeError('Phone namespace did not prepare.')
                time.sleep(.01)
            for local,remote,pid,local_ip,remote_ip in (
                ('vpn-ap0','phone0',phone.pid,'10.77.0.1/24','10.77.0.2/24'),
                ('tun0','vpn-peer',peer.pid,'172.27.240.10/24','172.27.240.1/24'),
                ('wlan0','wan-peer',peer.pid,'192.0.2.2/24','192.0.2.1/24')):
                command(['/usr/sbin/ip','link','add',local,'type','veth','peer','name',remote])
                command(['/usr/sbin/ip','link','set',remote,'netns',str(pid)])
                command(['/usr/sbin/ip','address','add',local_ip,'dev',local]);command(['/usr/sbin/ip','link','set',local,'up'])
                enter=['/usr/bin/nsenter','-t',str(pid),'-n','--','/usr/sbin/ip']
                command(enter+['link','set','lo','up']);command(enter+['address','add',remote_ip,'dev',remote]);command(enter+['link','set',remote,'up'])
            command(['/usr/sbin/ip','route','add','default','via','192.0.2.1','dev','wlan0'])
            command(['/usr/sbin/ip','route','add','203.0.113.7/32','via','172.27.240.1','dev','tun0'])
            command(['/usr/bin/nsenter','-t',str(peer.pid),'-n','--','/usr/sbin/ip','address','add','203.0.113.7/32','dev','lo'])
            command(['/usr/bin/nsenter','-t',str(phone.pid),'-n','--','/usr/sbin/ip','route','add','default','via','10.77.0.1'])
            if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()!='1':
                Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
            batch=firewall_policy.render_batch(POLICY,995,hotspot=True)
            command(['/usr/sbin/nft','-j','-f','-'],json.dumps(batch))
            with patch.object(portal_helper,'load_policy',return_value=POLICY),patch.object(portal_helper,'service_account',return_value=SimpleNamespace(pw_uid=995)):
                portal_helper.inspect_guard(json.loads(command(['/usr/sbin/nft','-j','list','ruleset'])))
            peer.stdin.write('start\n');peer.stdin.flush()
            command(['/usr/sbin/useradd','--system','--user-group','--home-dir','/nonexistent','--no-create-home','--shell','/usr/sbin/nologin','vpn-hotspot'])
            config=Path(directory)/'dhcp.conf';config.write_text(vpn_hotspot.dhcp_configuration());config.chmod(0o600)
            dhcp=subprocess.Popen(['/usr/sbin/dnsmasq','--no-daemon','--conf-file='+str(config)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            time.sleep(.5)
            if dhcp.poll() is not None:raise RuntimeError('Fixture DHCP service failed.')
            def probe(mode):
                value=command(['/usr/bin/nsenter','-t',str(phone.pid),'-n','--','/usr/bin/python3','-I','-B','-c',PROBE,mode])
                if value.strip()!='pass':raise RuntimeError('Phone probe failed.')
            for mode in ('dhcp','dns','tcp','echo'):probe(mode)
            def stats():
                peer.stdin.write('stats\n');peer.stdin.flush()
                if not select.select([peer.stdout],[],[],4)[0]:raise RuntimeError('Peer counter unavailable.')
                return json.loads(peer.stdout.readline())
            before=stats()
            if len(before)<3 or set(before)!={'172.27.240.10'}:raise RuntimeError('NAT source did not use Kali tunnel address.')
            command(['/usr/sbin/ip','route','delete','203.0.113.7/32'])
            probe('blocked-echo')
            command(['/usr/sbin/ip','link','set','tun0','down'])
            probe('blocked-dns')
            if stats()!=before:raise RuntimeError('Phone packets escaped over physical uplink.')
            # Restoring normal host networking must refuse while AP exists.
            with patch.object(portal_helper,'load_policy',return_value=POLICY),patch.object(portal_helper,'service_account',return_value=SimpleNamespace(pw_uid=995)):
                portal_helper.inspect_guard(json.loads(command(['/usr/sbin/nft','-j','list','ruleset'])))
            print('PASS: real phone DHCP private-DNS options, UDP/TCP DNS redirection, tunnel NAT and no physical fallback after route/tunnel loss.',flush=True)
        finally:
            for process in (dhcp,peer,phone):
                if process is not None and process.poll() is None:
                    process.terminate();process.wait(timeout=5)


if __name__=='__main__':
    if os.geteuid()!=0 or not Path('/.dockerenv').exists() or os.environ.get('VPN_LAB_DISPOSABLE_SERVER_TEST')!='1':
        raise SystemExit('Use only the disposable hotspot test container.')
    try:
        if sys.argv[1:]==['child']:child()
        else:subprocess.run(['/usr/bin/unshare','--net','--','/usr/bin/python3','-I','-B',__file__,'child'],check=True,timeout=45)
    except Exception as error:
        print('FAIL: isolated hotspot fixture '+type(error).__name__+'.',flush=True)
        raise SystemExit(1)
