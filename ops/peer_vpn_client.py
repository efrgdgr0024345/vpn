#!/usr/bin/python3
"""Temporary external VPN client in a private network namespace. JSON only."""
import ctypes
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import resource
import select
import selectors
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C',
       'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'l'}
STAGES = {'prepare','namespace','handshake','private_dns','public_dns','https','cleanup','complete'}
ERRORS = {'prepare_failed','invalid_request','namespace_failed','vpn_failed','dns_failed',
          'host_state_changed','cleanup_failed'}
VPN_FAILURES = {'auth_failed','tls_failed','startup_timeout','process_failed','configuration_failed','route_failed'}
DNS_STATUS = {'unchecked','ok','timeout','rcode_error','invalid','transport_error'}
TEST_ADDRESS = '172.27.240.249'
PRIVATE_DNS = '172.27.240.1'
PUBLIC_DNS = '198.41.0.4'
RUNTIME = Path('/run')
STOCK_CONFIG_DIRS = (Path('/etc/openvpn'),Path('/etc/openvpn/client'),Path('/etc/openvpn/server'))
QUESTION = b'\x07example\x03com\0'+struct.pack('!HH',1,1)
ROOT_QUESTION = b'\0'+struct.pack('!HH',2,1)


class ClientError(RuntimeError):
    pass


def empty_report(mode='test'):
    return {'version':1,'mode':mode,'passed':False,'tools_ready':False,
        'packages_installed':False,'client_version':None,'slirp_version':None,
        'namespace_isolated':False,'handshake':False,
        'private_dns':{'status':'unchecked','rcode':None,'answers':None},
        'public_dns':{'status':'unchecked','rcode':None,'answers':None},
        'https_status':'not_attempted','host_routes_unchanged':False,
        'host_dns_unchanged':False,'cleanup_confirmed':False,
        'stage':'prepare' if mode=='prepare' else 'namespace','vpn_failure':None,'error':None}


def validate_report(value):
    try:
        if not isinstance(value,dict) or set(value)!=set(empty_report()):
            raise ValueError()
        if type(value['version']) is not int or value['version']!=1 or value['mode'] not in ('prepare','test'):
            raise ValueError()
        for name in ('passed','tools_ready','packages_installed','namespace_isolated','handshake',
                     'host_routes_unchanged','host_dns_unchanged','cleanup_confirmed'):
            if type(value[name]) is not bool:
                raise ValueError()
        for name in ('client_version','slirp_version'):
            if value[name] is not None and (not isinstance(value[name],str) or
                    not re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,4})?',value[name])):
                raise ValueError()
        for name in ('private_dns','public_dns'):
            row=value[name]
            if not isinstance(row,dict) or set(row)!={'status','rcode','answers'} or row['status'] not in DNS_STATUS:
                raise ValueError()
            for field,maximum in (('rcode',15),('answers',128)):
                if row[field] is not None and (type(row[field]) is not int or not 0<=row[field]<=maximum):
                    raise ValueError()
            if row['status']=='ok' and (row['rcode']!=0 or type(row['answers']) is not int or row['answers']<1):
                raise ValueError()
        if (value['https_status'] not in ('not_attempted','ok','failed') or value['stage'] not in STAGES
                or value['vpn_failure'] is not None and value['vpn_failure'] not in VPN_FAILURES
                or value['error'] is not None and value['error'] not in ERRORS):
            raise ValueError()
        if value['passed']:
            required=('tools_ready','host_routes_unchanged','host_dns_unchanged','cleanup_confirmed')
            if not all(value[name] for name in required) or value['error'] is not None:
                raise ValueError()
            if value['mode']=='test' and (not value['namespace_isolated'] or not value['handshake']
                    or value['private_dns']['status']!='ok' or value['public_dns']['status']!='ok'
                    or value['https_status']!='ok' or value['stage']!='complete'):
                raise ValueError()
        return value
    except (ValueError,TypeError,KeyError,AttributeError):
        raise ValueError('Unsupported external VPN client report.') from None


def command(argv, *, timeout=8, limit=65536):
    """Keep command output private and bounded; never include it in failures."""
    process=None
    try:
        process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,env=ENV,cwd='/',start_new_session=True)
        output=bytearray()
        deadline=time.monotonic()+timeout
        with selectors.DefaultSelector() as poller:
            poller.register(process.stdout,selectors.EVENT_READ)
            while True:
                left=deadline-time.monotonic()
                if left<=0 or not poller.select(left):
                    raise ClientError('prepare_failed')
                data=os.read(process.stdout.fileno(),min(4096,limit+1-len(output)))
                if not data:
                    break
                output.extend(data)
                if len(output)>limit:
                    raise ClientError('prepare_failed')
        code=process.wait(timeout=max(.001,deadline-time.monotonic()))
        return code,output.decode('utf-8',errors='replace')
    except (OSError,ValueError,subprocess.SubprocessError):
        raise ClientError('prepare_failed') from None
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
            process.stdout.close()


def versions():
    values={}
    for name,path,pattern in (
            ('client_version','/usr/sbin/openvpn',r'^OpenVPN ([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'),
            ('slirp_version','/usr/bin/slirp4netns',r'^slirp4netns version ([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b')):
        values[name]=None
        if not Path(path).is_file():
            continue
        try:
            code,text=command([path,'--version'],timeout=3)
            match=re.search(pattern,text,re.M) if code==0 else None
            if match:
                values[name]=match[1]
        except ClientError:
            pass
    return values


def state_fingerprint():
    """Observe host state; no route, resolver or service is modified."""
    try:
        routes=[]
        for family in ('-4','-6'):
            code,text=command(['/usr/sbin/ip','-j',family,'route','show','table','all'],timeout=3)
            if code:
                return None,None
            rows=json.loads(text)
            if not isinstance(rows,list) or not all(isinstance(row,dict) for row in rows):
                return None,None
            # Expiry and cache timestamps change without a configuration write.
            routes.extend([{key:value for key,value in row.items() if key not in ('expires','cache','used')}
                           for row in rows])
        with open('/etc/resolv.conf','rb') as stream:
            dns=stream.read(65537)
        if len(dns)>65536:
            return None,None
        route_hash=hashlib.sha256(json.dumps(routes,sort_keys=True).encode()).hexdigest()
        return route_hash,hashlib.sha256(dns).hexdigest()
    except (OSError,ValueError,ClientError):
        return None,None


def stock_configs_present():
    # A package maintainer may start its stock service. Refuse installation if
    # any existing stock configuration could make that service change routing.
    # Only existence is checked; contents and names never enter the report.
    try:
        return any(any(directory.glob('*.conf')) for directory in STOCK_CONFIG_DIRS)
    except OSError:
        return True


def prepare():
    report=empty_report('prepare')
    before=state_fingerprint()
    try:
        packages=[]
        if not Path('/usr/sbin/openvpn').is_file():
            if stock_configs_present():
                raise ClientError('prepare_failed')
            packages.append('openvpn')
        if not Path('/usr/bin/slirp4netns').is_file():
            packages.append('slirp4netns')
        trust=ssl.get_default_verify_paths().cafile
        if trust is None or not Path(trust).is_file():
            packages.append('ca-certificates')
        if packages:
            code,_=command(['/usr/bin/apt-get','update','-qq'],timeout=60,limit=2_000_000)
            if code:
                raise ClientError('prepare_failed')
            code,_=command(['/usr/bin/apt-get','install','-y','--no-install-recommends',
                           '--no-upgrade','--no-remove',*packages],timeout=240,limit=2_000_000)
            if code:
                raise ClientError('prepare_failed')
            report['packages_installed']=True
        report.update(versions())
        report['tools_ready']=all(report[name] is not None for name in ('client_version','slirp_version')) and Path('/usr/sbin/ip').is_file()
        if not report['tools_ready']:
            raise ClientError('prepare_failed')
    except ClientError:
        report['error']='prepare_failed'
    after=state_fingerprint()
    report['host_routes_unchanged']=before[0] is not None and before[0]==after[0]
    report['host_dns_unchanged']=before[1] is not None and before[1]==after[1]
    report['cleanup_confirmed']=True
    report['passed']=report['tools_ready'] and report['host_routes_unchanged'] and report['host_dns_unchanged'] and report['error'] is None
    report['stage']='complete' if report['passed'] else 'prepare'
    return report


def validate_request(request):
    if not isinstance(request,dict) or request.get('mode') not in ('prepare','test'):
        raise ClientError('invalid_request')
    if request['mode']=='prepare':
        if set(request)!={'mode'}:
            raise ClientError('invalid_request')
        return request
    if set(request)!={'mode','profile','login','server_ipv4','expected_ipv4'} or request['expected_ipv4']!=TEST_ADDRESS:
        raise ClientError('invalid_request')
    try:
        server=ipaddress.IPv4Address(request['server_ipv4'])
        if str(server)!=request['server_ipv4'] or server.is_loopback or server.is_unspecified or server.is_multicast or server.is_link_local or str(server)=='255.255.255.255':
            raise ValueError()
    except (TypeError,ValueError):
        raise ClientError('invalid_request') from None
    profile=request['profile']
    login=request['login']
    if (not isinstance(profile,str) or not 1<=len(profile)<=131072 or '\x00' in profile
            or not isinstance(login,str) or len(login)>256):
        raise ClientError('invalid_request')
    values=login.splitlines()
    if len(values)!=2 or values[0]!='vpn-lab-client' or not re.fullmatch(r'[A-Za-z0-9_-]{40,128}',values[1]):
        raise ClientError('invalid_request')
    required={'client','remote '+str(server)+' 1194','remote-cert-tls server',
              'verify-x509-name VPNLabServer name','tls-version-min 1.3','auth-user-pass'}
    allowed=required|{'dev tun','dev tun0','proto udp','proto udp4','nobind','persist-key','persist-tun',
        'data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305','auth SHA256','auth-nocache','mssfix 1300','verb 3'}
    seen=set()
    blocks=set()
    active=None
    for raw in profile.splitlines():
        line=raw.strip()
        if not line or line.startswith('#'):
            continue
        if active is not None:
            if line=='</'+active+'>':
                active=None
            elif not re.fullmatch(r'[A-Za-z0-9+/= -]{1,160}',line):
                raise ClientError('invalid_request')
            continue
        if line in ('<ca>','<cert>','<key>','<tls-crypt>'):
            name=line[1:-1]
            if name in blocks:
                raise ClientError('invalid_request')
            active=name
            blocks.add(name)
        elif line not in allowed or line in seen:
            raise ClientError('invalid_request')
        else:
            seen.add(line)
    if active is not None or blocks!={'ca','cert','key','tls-crypt'} or not required<=seen:
        raise ClientError('invalid_request')
    if len(seen&{'dev tun','dev tun0'})!=1 or len(seen&{'proto udp','proto udp4'})!=1:
        raise ClientError('invalid_request')
    return request


def dns_name(data,offset):
    labels=[]
    seen=set()
    end=None
    size=1
    while True:
        if offset>=len(data) or offset in seen or len(seen)>=128:
            raise ValueError()
        seen.add(offset)
        length=data[offset]
        if length&0xc0==0xc0:
            if offset+1>=len(data):
                raise ValueError()
            pointer=((length&63)<<8)|data[offset+1]
            if not 12<=pointer<offset:
                raise ValueError()
            end=offset+2 if end is None else end
            offset=pointer
            continue
        if length&0xc0 or offset+1+length>len(data):
            raise ValueError()
        offset+=1
        if not length:
            return tuple(labels),end if end is not None else offset
        labels.append(data[offset:offset+length].lower())
        size+=length+1
        if size>255:
            raise ValueError()
        offset+=length


def parse_dns(data,identifier,*,root=False):
    invalid=({'status':'invalid','rcode':None,'answers':None},[])
    try:
        if not 12<=len(data)<=4096:
            return invalid
        ident,flags,questions,answers,authority,additional=struct.unpack('!6H',data[:12])
        if ident!=identifier or flags&0xf800!=0x8000 or questions!=1 or answers+authority+additional>128:
            return invalid
        name,offset=dns_name(data,12)
        expected=() if root else (b'example',b'com')
        kind=2 if root else 1
        if name!=expected or data[offset:offset+4]!=struct.pack('!HH',kind,1):
            return invalid
        offset+=4
        rcode=flags&15
        if rcode:
            return {'status':'rcode_error','rcode':rcode,'answers':None},[]
        if flags&0x0200:
            # A matching root reply still proves UDP forwarding/NAT even when
            # glue records were truncated. It is not a fallback resolver.
            return ({'status':'ok','rcode':0,'answers':answers},[]) if root and answers else invalid
        addresses=[]
        usable=0
        for index in range(answers+authority+additional):
            owner,offset=dns_name(data,offset)
            if offset+10>len(data):
                return invalid
            rrtype,family,_,length=struct.unpack('!HHIH',data[offset:offset+10])
            offset+=10
            if offset+length>len(data) or rrtype==1 and length!=4:
                return invalid
            if index<answers and owner==expected and family==1 and rrtype==kind:
                usable+=1
                if kind==1:
                    addresses.append(socket.inet_ntoa(data[offset:offset+4]))
            offset+=length
        if offset!=len(data) or usable<1:
            return invalid
        return {'status':'ok','rcode':0,'answers':usable},addresses
    except (ValueError,struct.error):
        return invalid


def tunnel_socket(kind):
    channel=socket.socket(socket.AF_INET,kind)
    try:
        channel.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'tun-test\0')
        channel.bind((TEST_ADDRESS,0))
        channel.settimeout(3)
        return channel
    except BaseException:
        channel.close()
        raise


def query_dns(address,*,root=False):
    try:
        code,text=command(['/usr/sbin/ip','-j','-4','route','get',address])
        routes=json.loads(text) if code==0 else None
        if not isinstance(routes,list) or len(routes)!=1 or routes[0].get('dev')!='tun-test':
            raise OSError()
        with tunnel_socket(socket.SOCK_DGRAM) as channel:
            identifier=int.from_bytes(os.urandom(2),'big')
            question=ROOT_QUESTION if root else QUESTION
            channel.connect((address,53))
            channel.send(struct.pack('!6H',identifier,0 if root else 0x0100,1,0,0,0)+question)
            data,peer=channel.recvfrom(4097)
        if peer!=(address,53):
            return {'status':'invalid','rcode':None,'answers':None},[]
        return parse_dns(data,identifier,root=root)
    except socket.timeout:
        return {'status':'timeout','rcode':None,'answers':None},[]
    except (OSError,ValueError,ClientError):
        return {'status':'transport_error','rcode':None,'answers':None},[]


def https_test(addresses):
    for address in addresses[:2]:
        if not ipaddress.IPv4Address(address).is_global:
            continue
        try:
            with tunnel_socket(socket.SOCK_STREAM) as raw:
                raw.settimeout(5)
                raw.connect((address,443))
                with ssl.create_default_context().wrap_socket(raw,server_hostname='example.com') as channel:
                    channel.sendall(b'HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
                    data=bytearray()
                    deadline=time.monotonic()+5
                    while b'\r\n' not in data and len(data)<4096:
                        left=deadline-time.monotonic()
                        if left<=0:
                            break
                        channel.settimeout(left)
                        part=channel.recv(min(1024,4096-len(data)))
                        if not part:
                            break
                        data.extend(part)
                    match=re.match(rb'^HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]{0,128})?\r\n',bytes(data))
                    if match and 200<=int(match[1])<400:
                        return 'ok'
        except (OSError,ValueError,ssl.SSLError):
            continue
    return 'failed'


def openvpn_command(profile,login,version):
    argv=['/usr/sbin/openvpn','--config',str(profile),'--auth-user-pass',str(login),
        '--auth-nocache','--dev','tun-test','--dev-type','tun','--proto','udp4',
        '--pull-filter','ignore','ifconfig-ipv6','--pull-filter','ignore','route-ipv6',
        '--pull-filter','ignore','redirect-gateway','--pull-filter','ignore','block-ipv6',
        '--redirect-gateway','def1','--script-security','1','--allow-compression','no',
        '--connect-retry','1','--connect-timeout','10','--connect-retry-max','3',
        '--mssfix','1300','--verb','3','--persist-key','--persist-tun',
        '--explicit-exit-notify','1']
    if tuple(map(int,version.split('.')[:2]))>=(2,6):
        argv.append('--disable-dco')
    try:
        user=pwd.getpwnam('nobody')
        group=grp.getgrnam('nogroup')
        if user.pw_uid>0 and user.pw_gid==group.gr_gid and group.gr_gid>0:
            argv.extend(['--user','nobody','--group','nogroup'])
    except KeyError:
        pass
    return argv


def classify_line(line):
    if any(word in line.lower() for word in ('push_reply','auth-token','password=','private key')):
        return None
    message=re.sub(r'^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)? ','',line)
    for prefix,result in (('Initialization Sequence Completed','ready'),
            ('AUTH: Received control message: AUTH_FAILED','auth_failed'),
            ('VERIFY ERROR','tls_failed'),('TLS Error:','tls_failed'),
            ('Options error:','configuration_failed'),
            ('ERROR: Linux route','route_failed'),('ERROR: Linux IPv4','route_failed')):
        if message.startswith(prefix):
            return result
    return None


def worker(profile,login,report):
    report['namespace_isolated']=True
    report['stage']='handshake'
    process=None
    try:
        process=subprocess.Popen(openvpn_command(profile,login,report['client_version']),
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
            env=ENV,cwd='/',extra_groups=[])
        deadline=time.monotonic()+35
        buffer=b''
        ready=False
        while time.monotonic()<deadline and process.poll() is None and not ready:
            if not select.select([process.stdout],[],[],.2)[0]:
                continue
            part=os.read(process.stdout.fileno(),4096)
            if not part:
                break
            buffer+=part
            if len(buffer)>65536:
                raise ClientError('vpn_failed')
            while b'\n' in buffer:
                line,buffer=buffer.split(b'\n',1)
                stage=classify_line(line.decode('utf-8',errors='replace'))
                if stage=='ready':
                    ready=True
                    break
                if stage in VPN_FAILURES:
                    report['vpn_failure']=stage
                    raise ClientError('vpn_failed')
        if not ready:
            report['vpn_failure']='startup_timeout' if process.poll() is None else 'process_failed'
            raise ClientError('vpn_failed')
        code,text=command(['/usr/sbin/ip','-j','-4','address','show','dev','tun-test'])
        links=json.loads(text) if code==0 else []
        if not any(item.get('local')==TEST_ADDRESS for row in links for item in row.get('addr_info',[])):
            report['vpn_failure']='route_failed'
            raise ClientError('vpn_failed')
        report['handshake']=True
        report['stage']='private_dns'
        report['private_dns'],addresses=query_dns(PRIVATE_DNS)
        if report['private_dns']['status']!='ok':
            raise ClientError('dns_failed')
        report['stage']='public_dns'
        report['public_dns'],_=query_dns(PUBLIC_DNS,root=True)
        if report['public_dns']['status']!='ok':
            raise ClientError('dns_failed')
        report['stage']='https'
        report['https_status']=https_test(addresses)
        if report['https_status']!='ok':
            raise ClientError('vpn_failed')
        report['stage']='complete'
    except (OSError,ValueError,ClientError,subprocess.SubprocessError) as error:
        report['error']=str(error) if isinstance(error,ClientError) and str(error) in ERRORS else 'vpn_failed'
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            process.stdout.close()
    return report


def private_file(path,text):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        stream.write(text)


def unshare_network():
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.unshare(0x40000000)!=0:  # Linux CLONE_NEWNET; no mount/PID/host changes.
        raise ClientError('namespace_failed')


def group_active(pid):
    """Inspect only group/state fields, never command arguments or process logs."""
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            with (path/'stat').open() as stream:
                text=stream.read(4097)
            fields=text.rsplit(')',1)[1].split()
            if len(text)>4096 or len(fields)<3:
                return None
            if int(fields[2])==pid and fields[0]!='Z':
                return True
        except FileNotFoundError:
            continue
        except (OSError,ValueError,IndexError):
            return None
    return False


def stop_child(pid):
    if pid is None:
        return True
    try:
        os.killpg(pid,signal.SIGTERM)
    except ProcessLookupError:
        pass
    # Keep the leader unreaped until the whole owned group has stopped, so its
    # PID cannot be reused while a remaining OpenVPN child is being signaled.
    deadline=time.monotonic()+12
    while group_active(pid) is True and time.monotonic()<deadline:
        time.sleep(.05)
    if group_active(pid) is not False:
        try:
            os.killpg(pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline=time.monotonic()+3
        while group_active(pid) is True and time.monotonic()<deadline:
            time.sleep(.05)
    stopped=group_active(pid) is False
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        try:
            done,_=os.waitpid(pid,os.WNOHANG)
        except ChildProcessError:
            return stopped
        if done:
            return stopped
        time.sleep(.05)
    return False


def test(request):
    report=empty_report()
    report.update(versions())
    report['tools_ready']=all(report[name] is not None for name in ('client_version','slirp_version'))
    before=state_fingerprint()
    host_namespace=os.stat('/proc/self/ns/net').st_ino
    child=None
    slirp=None
    directory_name=None
    temporary=None
    descriptors=[]
    try:
        if not report['tools_ready']:
            report['error']='prepare_failed'
            return report
        temporary=tempfile.TemporaryDirectory(prefix='vpn-peer-test-',dir=RUNTIME)
        directory=temporary.name
        directory_name=directory
        profile=Path(directory)/'client.ovpn'
        login=Path(directory)/'login.txt'
        private_file(profile,request['profile'])
        private_file(login,request['login'])
        ready_r,ready_w=os.pipe()
        go_r,go_w=os.pipe()
        result_r,result_w=os.pipe()
        descriptors.extend((ready_r,ready_w,go_r,go_w,result_r,result_w))
        child=os.fork()
        if child==0:
            for fd in (ready_r,go_w,result_r):
                os.close(fd)
            def interrupted(number,frame):
                signal.signal(signal.SIGTERM,signal.SIG_IGN)
                signal.signal(signal.SIGHUP,signal.SIG_IGN)
                raise ClientError('namespace_failed')
            try:
                os.setsid()
                signal.signal(signal.SIGTERM,interrupted)
                signal.signal(signal.SIGHUP,interrupted)
                unshare_network()
                if os.stat('/proc/self/ns/net').st_ino==host_namespace:
                    raise ClientError('namespace_failed')
                os.write(ready_w,b'R')
                os.close(ready_w)
                if os.read(go_r,1)!=b'G':
                    raise ClientError('namespace_failed')
                os.close(go_r)
                report=worker(profile,login,report)
            except (OSError,ValueError,ClientError):
                report['error']='namespace_failed'
            finally:
                try:
                    os.write(result_w,json.dumps(report,sort_keys=True).encode())
                    os.close(result_w)
                except OSError:
                    pass
                os._exit(0)
        for fd in (ready_w,go_r,result_w):
            os.close(fd)
            descriptors.remove(fd)
        if not select.select([ready_r],[],[],5)[0] or os.read(ready_r,1)!=b'R':
            raise ClientError('namespace_failed')
        if os.stat('/proc/'+str(child)+'/ns/net').st_ino==host_namespace:
            raise ClientError('namespace_failed')
        slirp_r,slirp_w=os.pipe()
        descriptors.extend((slirp_r,slirp_w))
        slirp=subprocess.Popen(['/usr/bin/slirp4netns','--configure','--mtu=1500',
            '--disable-host-loopback','--ready-fd',str(slirp_w),str(child),'tap0'],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            pass_fds=(slirp_w,),env=ENV,cwd='/',start_new_session=True)
        os.close(slirp_w)
        descriptors.remove(slirp_w)
        if not select.select([slirp_r],[],[],8)[0] or len(os.read(slirp_r,1))!=1 or slirp.poll() is not None:
            raise ClientError('namespace_failed')
        os.write(go_w,b'G')
        os.close(go_w)
        descriptors.remove(go_w)
        data=bytearray()
        deadline=time.monotonic()+110
        while True:
            left=deadline-time.monotonic()
            if left<=0 or not select.select([result_r],[],[],left)[0]:
                raise ClientError('namespace_failed')
            part=os.read(result_r,4096)
            if not part:
                break
            data.extend(part)
            if len(data)>16384:
                raise ClientError('namespace_failed')
        report=validate_report(json.loads(data))
    except (OSError,ValueError,ClientError,subprocess.SubprocessError):
        report['error']='namespace_failed'
    finally:
        cleanup=stop_child(child)
        if slirp is not None:
            if slirp.poll() is None:
                slirp.terminate()
                try:
                    slirp.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    slirp.kill()
                    slirp.wait(timeout=3)
            cleanup=cleanup and slirp.poll() is not None
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                pass
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError:
                cleanup=False
        report['cleanup_confirmed']=cleanup and (directory_name is None or not Path(directory_name).exists())
        after=state_fingerprint()
        report['host_routes_unchanged']=before[0] is not None and before[0]==after[0]
        report['host_dns_unchanged']=before[1] is not None and before[1]==after[1]
        if os.stat('/proc/self/ns/net').st_ino!=host_namespace:
            report['error']='host_state_changed'
        if not report['host_routes_unchanged'] or not report['host_dns_unchanged']:
            report['error']='host_state_changed'
        if not report['cleanup_confirmed']:
            report['error']='cleanup_failed'
        report['passed']=(report['error'] is None and report['tools_ready'] and report['namespace_isolated']
            and report['handshake'] and report['private_dns']['status']=='ok'
            and report['public_dns']['status']=='ok' and report['https_status']=='ok'
            and report['host_routes_unchanged'] and report['host_dns_unchanged'] and report['cleanup_confirmed'])
    return report


def handle(request):
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if os.geteuid()!=0:
        raise ClientError('invalid_request')
    request=validate_request(request)
    return validate_report(prepare() if request['mode']=='prepare' else test(request))


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.umask(0o077)
    handlers={}
    def interrupted(number,frame):
        # Ignore repeated termination while the owned processes are reaped.
        signal.signal(signal.SIGTERM,signal.SIG_IGN)
        signal.signal(signal.SIGHUP,signal.SIG_IGN)
        raise ClientError('namespace_failed')
    try:
        for number in (signal.SIGTERM,signal.SIGHUP):
            handlers[number]=signal.getsignal(number)
            signal.signal(number,interrupted)
        raw=sys.stdin.buffer.read(262145)
        if len(raw)>262144:
            raise ClientError('invalid_request')
        report=handle(json.loads(raw))
    except (OSError,ValueError,ClientError,subprocess.SubprocessError):
        report=empty_report()
        report['error']='invalid_request'
    finally:
        for number,handler in handlers.items():
            signal.signal(number,handler)
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':
    main()
