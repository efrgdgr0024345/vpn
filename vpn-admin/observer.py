"""Passive IPv4/DNS metadata capture on the VPN interface; no packet-body storage."""
from collections import OrderedDict
import grp
import ipaddress
import json
import os
from pathlib import Path
import resource
import secrets
import socket
import stat
import sqlite3
import struct
import sys
import time

CODE=Path('/opt/vpn-lab-admin')
REGISTRY=Path('/etc/openvpn/lab/devices.json')
STATE=Path('/var/lib/vpn-lab-admin')
ROOT_UID=0
MAX_FLOWS=4096
MAX_STREAMS=128


def protected(path,limit=32768):
    for parent in reversed(path.parents):
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=ROOT_UID or info.st_mode&0o022:
            raise ValueError('Unprotected observer directory.')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=ROOT_UID or info.st_nlink!=1 or info.st_mode&0o022:
            raise ValueError('Unprotected observer input.')
        value=stream.read(limit+1)
    if len(value)>limit: raise ValueError('Oversized observer input.')
    return value


def devices():
    value=json.loads(protected(REGISTRY))
    if not isinstance(value,dict) or set(value)!={'kali','iphone','android'}:
        raise ValueError('Unrecognized device registry.')
    result={}
    for name,record in value.items():
        address=str(ipaddress.IPv4Address(record['address']))
        if address in result or ipaddress.IPv4Address(address) not in ipaddress.IPv4Network('172.27.240.0/24'):
            raise ValueError('Unrecognized device address.')
        result[address]=name
    return result


def packet(data):
    """Read only bounded IPv4 transport headers. Truncated payloads remain opaque."""
    if len(data)<20 or data[0]>>4!=4: return None
    ihl=(data[0]&15)*4
    total=struct.unpack_from('!H',data,2)[0]
    fragments=struct.unpack_from('!H',data,6)[0]
    if ihl<20 or ihl>60 or len(data)<ihl or total<ihl or fragments&8191:
        return None
    protocol={6:'tcp',17:'udp',1:'icmp'}.get(data[9])
    if protocol is None: return None
    source=socket.inet_ntoa(data[12:16]);destination=socket.inet_ntoa(data[16:20])
    result={'source':source,'destination':destination,'protocol':protocol,'source_port':None,
            'destination_port':None,'length':total,'payload':b'','sequence':0,'flags':0,'complete':len(data)>=total and not fragments&8192}
    if protocol=='tcp':
        if len(data)<ihl+20 or total<ihl+20: return None
        length=(data[ihl+12]>>4)*4
        if length<20 or length>60 or total<ihl+length or len(data)<ihl+length: return None
        result.update(source_port=struct.unpack_from('!H',data,ihl)[0],
            destination_port=struct.unpack_from('!H',data,ihl+2)[0],
            sequence=struct.unpack_from('!I',data,ihl+4)[0],flags=data[ihl+13],
            payload=data[ihl+length:min(len(data),total)])
    elif protocol=='udp':
        if len(data)<ihl+8 or total<ihl+8: return None
        length=struct.unpack_from('!H',data,ihl+4)[0]
        if length<8 or length>total-ihl: return None
        result.update(source_port=struct.unpack_from('!H',data,ihl)[0],
            destination_port=struct.unpack_from('!H',data,ihl+2)[0],
            payload=data[ihl+8:min(len(data),ihl+length)])
    return result


def questions(data):
    """Strict DNS question parsing; no responses, HTTP, TLS or page contents."""
    if len(data)<12: return []
    _,flags,count,_,_,_=struct.unpack_from('!6H',data)
    if flags&0xf800 or not 1<=count<=4: return []
    offset=12;result=[]
    for _ in range(count):
        labels=[];cursor=offset;end=None;visited=set()
        while True:
            if cursor>=len(data) or cursor in visited or len(visited)>=128: return []
            visited.add(cursor);length=data[cursor];cursor+=1
            if length&0xc0==0xc0:
                if cursor>=len(data): return []
                if end is None: end=cursor+1
                cursor=((length&63)<<8)|data[cursor]
                continue
            if length&0xc0 or length>63 or cursor+length>len(data): return []
            if not length:
                offset=end if end is not None else cursor
                break
            try: label=data[cursor:cursor+length].decode('ascii').lower()
            except UnicodeError: return []
            if not label or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789_-' for c in label): return []
            labels.append(label);cursor+=length
        if offset+4>len(data): return []
        kind,scope=struct.unpack_from('!HH',data,offset);offset+=4
        name='.'.join(labels)
        if scope==1 and kind and 1<=len(name)<=253: result.append((name,kind))
    return result


class Tracker:
    def __init__(self,mapping):
        self.mapping=mapping
        self.flows=OrderedDict();self.streams=OrderedDict();self.syns={}
        self.pending={};self.counters={'socket_drops':0,'dns_gaps':0,'queue_drops':0}

    def queue(self,value):
        if value['key'] not in self.pending and len(self.pending)>=512:
            self.counters['queue_drops']+=1;return
        self.pending[value['key']]=dict(value)

    def dns(self,value):
        if value['protocol']=='udp':
            if not value['complete']:
                self.counters['dns_gaps']+=1;return []
            return questions(value['payload'])
        key=(value['source'],value['source_port'],value['destination'],value['destination_port'])
        if value['flags']&2:
            self.streams[key]={'next':(value['sequence']+1)&0xffffffff,'data':bytearray()}
        if key not in self.streams:
            if value['payload']: self.counters['dns_gaps']+=1
            return []
        stream=self.streams[key];result=[]
        payload=value['payload'];sequence=(value['sequence']+(1 if value['flags']&2 else 0))&0xffffffff
        if payload:
            # A gap, reordering, truncation or sequence wrap makes parsing unknown.
            # Do not guess where a new DNS frame begins in an incomplete stream.
            if sequence!=stream['next'] or not value['complete'] or len(stream['data'])+len(payload)>65537:
                self.streams.pop(key);self.counters['dns_gaps']+=1;return []
            stream['next']=(sequence+len(payload))&0xffffffff;stream['data'].extend(payload)
            while len(stream['data'])>=2:
                length=int.from_bytes(stream['data'][:2],'big')
                if length<12:
                    self.streams.pop(key);self.counters['dns_gaps']+=1;return []
                if len(stream['data'])<length+2: break
                result.extend(questions(bytes(stream['data'][2:length+2])))
                del stream['data'][:length+2]
        self.streams.move_to_end(key)
        if value['flags']&5: self.streams.pop(key,None)
        while len(self.streams)>MAX_STREAMS:
            self.streams.popitem(last=False);self.counters['dns_gaps']+=1
        return result

    def observe(self,data,now):
        value=packet(data)
        if value is None: return
        outbound=value['source'] in self.mapping
        if not outbound and value['destination'] not in self.mapping: return
        client=value['source'] if outbound else value['destination']
        remote=value['destination'] if outbound else value['source']
        sport=value['source_port'] if outbound else value['destination_port']
        dport=value['destination_port'] if outbound else value['source_port']
        # Exclude this panel's own polling to avoid an observation feedback loop.
        if remote=='172.27.240.1' and dport in (8080,8443): return
        if dport==53 and value['protocol'] in ('tcp','udp'):
            if outbound:
                for domain,kind in self.dns(value):
                    self.queue(self.record(value,now,'dns',domain,kind))
            return
        key=(client,sport,remote,dport,value['protocol'])
        record=self.flows.get(key)
        new_syn=outbound and value['protocol']=='tcp' and value['flags']&2 and not value['flags']&16
        new_syn = new_syn and self.syns.get(key) != value['sequence']
        if record is None or now-record['last_seen']>300000 or now-record['first_seen']>29*86400000 or new_syn:
            if not outbound: return
            record=self.record(value,now,'flow',None,None)
            self.flows[key]=record
            self.syns[key]=value['sequence'] if new_syn else None
        self.flows.move_to_end(key)
        record['last_seen']=max(now,record['last_seen'])
        field='outbound_bytes' if outbound else 'reply_bytes'
        record[field]=min(2**63-1,record[field]+value['length'])
        if not outbound: record['reply_observed']=True
        self.queue(record)
        while len(self.flows)>MAX_FLOWS:
            expired,_=self.flows.popitem(last=False);self.syns.pop(expired,None)
        if value['protocol']=='tcp' and value['flags']&5:
            self.flows.pop(key,None);self.syns.pop(key,None)

    def record(self,value,now,kind,domain,query_type):
        return {'key':secrets.token_hex(16),'kind':kind,'device':self.mapping[value['source']],
                'source_ip':value['source'],'destination_ip':value['destination'],
                'source_port':value['source_port'],'destination_port':value['destination_port'],
                'protocol':value['protocol'],'domain':domain,'query_type':query_type,
                'first_seen':now,'last_seen':now,'outbound_bytes':0,'reply_bytes':0,'reply_observed':False}


def main():
    if os.geteuid()!=ROOT_UID or not sys.flags.isolated or Path(__file__)!=CODE/'observer.py':
        raise ValueError('Use the installed observer service.')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    for name in ('observer.py','history.py'): protected(CODE/name,2_000_000)
    sys.path.insert(0,str(CODE))
    import history
    gid=grp.getgrnam('vpn-lab-admin').gr_gid
    STATE.mkdir(mode=0o750,exist_ok=True)
    history.trusted(STATE);os.chown(STATE,ROOT_UID,gid);os.chmod(STATE,0o750)
    store=history.Store(gid)
    tracker=Tracker(devices())
    tracker.counters.update(store.counters)
    channel=None;interface_index=None;last_write=0;last_devices=0
    try:
        while True:
            if channel is None:
                store.write(list(tracker.pending.values()),tracker.counters,active=False)
                tracker.pending.clear()
                try:
                    channel=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0800))
                    channel.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,524288)
                    channel.bind(('tun-lab',0));channel.settimeout(.5)
                    interface_index=socket.if_nametoindex('tun-lab')
                except OSError:
                    if channel is not None: channel.close()
                    channel=None;time.sleep(1)
                    continue
            try:
                data,_=channel.recvfrom(4096)
                tracker.observe(data,int(time.time()*1000))
            except socket.timeout: pass
            except OSError:
                channel.close();channel=None;continue
            tick=time.monotonic()
            if tick-last_devices>=10:
                tracker.mapping=devices();last_devices=tick
                try: current_index=socket.if_nametoindex('tun-lab')
                except OSError: current_index=None
                if current_index!=interface_index:
                    channel.close();channel=None;continue
            if tick-last_write>=1:
                try:
                    statistics=channel.getsockopt(263,6,12)  # Linux PACKET_STATISTICS resets its counters.
                    tracker.counters['socket_drops']+=struct.unpack_from('=II',statistics)[1]
                except OSError: pass
                try:
                    store.write(list(tracker.pending.values()),tracker.counters)
                    tracker.pending.clear()
                except Exception:
                    tracker.counters['queue_drops']+=len(tracker.pending);tracker.pending.clear()
                    raise
                last_write=tick
    finally:
        if channel is not None: channel.close()
        store.close()


if __name__=='__main__':
    try: main()
    except (OSError,ValueError,KeyError,sqlite3.Error):
        raise SystemExit('Private network observer unavailable; packet contents withheld.') from None
