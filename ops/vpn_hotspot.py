#!/usr/bin/python3
"""Temporary WPA2 hotspot routed only through the owned Kali VPN session."""
import fcntl
from contextlib import contextmanager
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types

AP='vpn-ap0'
NETWORK='10.77.0.0/24'
GATEWAY='10.77.0.1'
SSID='VPNDesk-iPhone'
RUN=Path('/run/vpn-desk-hotspot')
NM=Path('/run/NetworkManager/conf.d/90-vpn-desk-hotspot.conf')
NM_TEXT='[device-vpn-desk-hotspot]\nmatch-device=interface-name:vpn-ap0\nmanaged=0\n'
ENV={'PATH':'/usr/sbin:/usr/bin','LC_ALL':'C'}
ROOTS=Path('/usr/local/libexec/vpn-desk')
FORWARD=Path('/proc/sys/net/ipv4/ip_forward')
LEGACY={'portal_helper.py':'96da266dc8f906aad8d5a3bfe2302156c5e855067f61917d4845b7209c9095be',
        'firewall_policy.py':'d24662b4c8f241f5597efcfeb48e1025ef0984b9f6fa3ddd62defee62607629b',
        'network_setup.py':'a626cd149eaa70d45e8f255a6e9273c0d40222f7a1f77f8244e821ca52e3427d'}
HELPER_SHA='8a168e37acd56d7ca4cfd51a553cab8bda4d5152707a250ffd180f5b24362052'
# Source digests are generated from the reviewed fixed bundle before publishing.
SOURCE_SHA256={'portal_helper.py': 'cb683c45da35c797905415c6db36eb02e48ac8c0bdf7f23fe177ad8eef06cf9f', 'firewall_policy.py': 'd4a039649fcc3937ece9d35728ad0d4dc87a51f4a6d29ea9c50ba7107cc201d2', 'network_setup.py': 'b0d061e4beccfb869623161ad72c2f0d5b563cc317ff179fd0651dd9bc93030c', 'client_diagnostics.py': '2fd2c9bbec1aaed5f422d86c1ab4769fa0a795cc919b596906220e0e28104dbf', 'upgrade_client_transport.py': '43f8cc12cc575eb62d12a8210e76070b8ea231cd968532a9b1585d2d88e46760'}

class HotspotError(RuntimeError): pass


def command(argv, *, data=None, timeout=8):
    result=subprocess.run(argv,input=data,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          timeout=timeout,check=False,env=ENV,**({'stdin':subprocess.DEVNULL} if data is None else {}))
    if result.returncode or len(result.stdout)>262144:
        raise HotspotError('A required local command failed; existing uplink configuration was preserved.')
    return result.stdout


def checked_module(name,source):
    if not isinstance(source,str) or hashlib.sha256(source.encode()).hexdigest()!=SOURCE_SHA256.get(name):
        raise HotspotError('Public hotspot bundle checksum mismatch; stopped.')
    module=types.ModuleType('hotspot_'+name.replace('.','_'))
    exec(compile(source,'checked-'+name,'exec'),module.__dict__)
    return module


def channel(info,phy):
    found=re.search(r'^\s*channel ([0-9]+) \(([0-9]+) MHz\)',info,re.M)
    if found is None: raise HotspotError('Current Wi-Fi channel could not be verified.')
    number,frequency=map(int,found.groups())
    if not (1<=number<=165 and (2412<=frequency<=2484 or 5000<=frequency<5925)):
        raise HotspotError('This hotspot supports existing 2.4/5 GHz channels only.')
    combinations=phy.partition('valid interface combinations:')[2].partition('HT Capability')[0]
    entries=re.split(r'\n\s*\*',combinations)
    if not any(re.search(r'#\{\s*managed\s*\}',entry) and re.search(r'#\{[^}]*\bAP\b[^}]*\}',entry)
               and re.search(r'#channels\s*<=\s*1\b',entry) for entry in entries):
        raise HotspotError('Concurrent station/AP operation on one channel was not verified.')
    row=re.search(r'\*\s*'+str(frequency)+r' MHz\s+\['+str(number)+r'\]([^\n]*)',phy)
    if row is None or any(flag in row.group(1).lower() for flag in ('disabled','no ir','radar')):
        raise HotspotError('The current channel is not verified for immediate AP use; no regulatory settings changed.')
    return number,frequency


def hostapd_configuration(number,frequency,password):
    if not re.fullmatch(r'[A-Za-z0-9_-]{32}',password): raise HotspotError('Invalid generated hotspot secret.')
    if not 1<=number<=165 or not 2412<=frequency<5925: raise HotspotError('Invalid hotspot channel.')
    return (f'interface={AP}\ndriver=nl80211\nssid={SSID}\nhw_mode={"g" if frequency<2500 else "a"}\n'
            f'channel={number}\nctrl_interface={RUN}/control\nauth_algs=1\nwpa=2\nwpa_key_mgmt=WPA-PSK\n'
            f'rsn_pairwise=CCMP\nwpa_passphrase={password}\nap_isolate=1\nmax_num_sta=1\nwps_state=0\n')


def dhcp_configuration():
    return (f'interface={AP}\nbind-interfaces\nexcept-interface=lo\nport=0\nno-hosts\nno-resolv\n'
            'user=vpn-hotspot\ngroup=vpn-hotspot\nleasefile-ro\ndhcp-authoritative\n'
            'dhcp-range=10.77.0.2,10.77.0.30,255.255.255.0,1h\n'
            f'dhcp-option=3,{GATEWAY}\ndhcp-option=6,172.27.240.1\nlog-facility=-\n')


def guard_batch(modules,hotspot):
    portal=modules['portal_helper']
    _,active=portal.inspect_guard(portal.js([portal.NFT,'-j','list','ruleset']))
    if active: raise HotspotError('A direct-network bypass is active; hotspot refused.')
    policy=modules['security'].load_policy()
    batch=modules['firewall_policy'].render_batch(policy,modules['security'].service_account().pw_uid,hotspot=hotspot)
    batch['nftables'].insert(0,{'delete':{'table':{'family':'inet','name':'vpn_guard'}}})
    value=json.dumps(batch)
    portal.run([portal.NFT,'--check','-j','-f','-'],value)
    portal.run([portal.NFT,'-j','-f','-'],value)
    portal.inspect_guard(portal.js([portal.NFT,'-j','list','ruleset']))


def private_file(path,value):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream: stream.write(value)


def stop_child(process):
    if process is None or process.poll() is not None: return
    process.terminate()
    try: process.wait(timeout=12)
    except subprocess.TimeoutExpired:
        process.kill();process.wait(timeout=3)


def account():
    try: user=pwd.getpwnam('vpn-hotspot')
    except KeyError:
        command(['/usr/sbin/useradd','--system','--user-group','--home-dir','/nonexistent','--no-create-home','--shell','/usr/sbin/nologin','vpn-hotspot'])
        user=pwd.getpwnam('vpn-hotspot')
    group=grp.getgrnam('vpn-hotspot')
    if (user.pw_uid<=0 or user.pw_gid!=group.gr_gid or user.pw_shell!='/usr/sbin/nologin'
            or user.pw_dir!='/nonexistent' or group.gr_mem
            or set(os.getgrouplist(user.pw_name,user.pw_gid))!={user.pw_gid}
            or any(p.pw_name!=user.pw_name and (p.pw_uid==user.pw_uid or p.pw_gid==user.pw_gid) for p in pwd.getpwall())):
        raise HotspotError('Existing hotspot account differs; preserved.')


@contextmanager
def owned_lock(path):
    path=Path(path)
    for parent in reversed(path.parents):
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise HotspotError('Unsafe runtime lock directory.')
    fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:
            raise HotspotError('Unsafe runtime lock.')
        try: fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise HotspotError('Another VPN action is running; protection was preserved.') from None
        yield


def restore_network(modules):
    with owned_lock('/run/vpn-dashboard-portal.lock'):
        if modules['portal_helper'].active_openvpn(): raise HotspotError('Another VPN is active; guard retained.')
        return modules['network_setup'].restore()


def run(owner,sources,diagnostics,updater):
    modules=diagnostics.load_modules()
    policy=modules['security'].load_policy()
    if policy['server_name']!='VPNLabServer' or not modules['session_channel'].kernel_ipv6_disabled():
        raise HotspotError('The verified lab profile and kernel IPv6 disablement are required.')
    for name in ('/usr/sbin/iw','/usr/sbin/hostapd','/usr/sbin/hostapd_cli','/usr/sbin/dnsmasq','/usr/bin/nmcli'):
        if not os.access(name,os.X_OK): raise HotspotError('Install hostapd, dnsmasq-base and iw before starting.')
    if RUN.exists() or RUN.is_symlink() or NM.exists() or NM.is_symlink():
        raise HotspotError('Existing hotspot state requires review; nothing overwritten.')
    present=(modules['portal_helper'].hotspot_present() if hasattr(modules['portal_helper'],'hotspot_present') else
             any(row.get('ifname')==AP for row in diagnostics.ip_json(['link','show'])))
    if present:
        raise HotspotError('A hotspot interface already exists; preserved.')
    info=command(['/usr/sbin/iw','dev',policy['wifi_interface'],'info'])
    phy_id=re.search(r'^\s*wiphy ([0-9]+)\s*$',info,re.M)
    if phy_id is None: raise HotspotError('Wi-Fi radio could not be verified.')
    phy=command(['/usr/sbin/iw','phy','phy'+phy_id.group(1),'info'])
    number,frequency=channel(info,phy)
    for row in diagnostics.ip_json(['route','show']):
        if row.get('dst') not in ('default','0.0.0.0/1','128.0.0.0/1') and row.get('dev')!='tun0':
            if ipaddress.IPv4Network(row['dst'],strict=False).overlaps(ipaddress.IPv4Network(NETWORK)):
                raise HotspotError('Hotspot subnet overlaps an existing route; nothing changed.')
    helper=updater.read_file(ROOTS/'vpn_session_helper.py')
    if hashlib.sha256(helper).hexdigest()!=HELPER_SHA:
        raise HotspotError('A different VPN helper requires review before hotspot setup.')
    bundle={}
    for name in LEGACY:
        value=sources[name].encode();digest=hashlib.sha256(value).hexdigest()
        current=hashlib.sha256(updater.read_file(ROOTS/name)).hexdigest()
        if current not in (LEGACY[name],digest): raise HotspotError('Installed guard has an unsupported baseline; preserved.')
        bundle[name]=(value,digest)
    modules['vpn_session_helper'].validate_testing_login()
    # Finish all read-only compatibility checks before asking the current
    # app-owned session to stop. Never kill an unrelated OpenVPN process.
    print('Preparing the temporary VPN hotspot. The current app-owned VPN will reconnect once.',flush=True)
    replaced_session=False
    previous_modules=modules
    try:
        if modules['portal_helper'].active_openvpn():
            endpoint=Path('/run/vpn-desk/session.sock')
            if endpoint.lstat().st_uid!=owner: raise HotspotError('The existing VPN belongs to another desktop owner.')
            replaced_session=True
            modules['session_channel'].request('stop')
            deadline=time.monotonic()+20
            while modules['portal_helper'].active_openvpn() or endpoint.exists():
                if time.monotonic()>=deadline: raise HotspotError('The existing VPN did not stop; no process was forcibly killed.')
                time.sleep(.25)
        if replaced_session: time.sleep(3)  # Allow the existing server lease to release.
        updater.upgrade(helper,HELPER_SHA,hotspot_bundle=bundle)
        modules=diagnostics.load_modules()
        account()
        forwarding=FORWARD
        original_forward=forwarding.read_text().strip()
        if original_forward not in ('0','1'): raise HotspotError('IPv4 forwarding state is unsupported.')
        RUN.mkdir(mode=0o700)
    except BaseException:
        if replaced_session:
            try:
                deadline=time.monotonic()+20
                while previous_modules['portal_helper'].active_openvpn() and time.monotonic()<deadline: time.sleep(.25)
                restore_network(previous_modules)
            except Exception:
                print('Startup could not restore ordinary networking. Use the saved network-restore command after stopping the VPN.',flush=True)
        raise
    vpn=ap=dhcp=None
    interface_created=False;nm_created=False;gateway_applied=False;forward_changed=False
    stopped=False
    def halt(number,frame):
        nonlocal stopped
        stopped=True
    previous={number:signal.signal(number,halt) for number in (signal.SIGINT,signal.SIGTERM)}
    try:
        launch="""import os,sys
os.environ.clear();os.environ.update(PATH='/usr/sbin:/usr/bin',LC_ALL='C')
sys.path.insert(0,'/usr/local/libexec/vpn-desk')
import vpn_session_helper
raise SystemExit(vpn_session_helper.main(int(sys.argv[1]),test_credentials=True))
"""
        vpn=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',launch,str(owner)],stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=ENV,start_new_session=True)
        deadline=time.monotonic()+95
        while True:
            if stopped: return
            if vpn.poll() is not None or time.monotonic()>=deadline: raise HotspotError('VPN did not become ready; inspect VPN Desk Session log.')
            try:
                snapshot=modules['session_channel'].request()
                ready=snapshot['state']=='tunnel_ready' and diagnostics.public_tunnel()
            except Exception: ready=False
            if ready and modules['vpn_session_helper'].private_dns_probe()[0]=='ok': break
            time.sleep(.5)
        guard_batch(modules,True);gateway_applied=True
        if original_forward=='0':
            forward_changed=True;forwarding.write_text('1\n')
        NM.parent.mkdir(mode=0o755,exist_ok=True)
        for parent in (*reversed(NM.parent.parents),NM.parent):
            info=parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
                raise HotspotError('NetworkManager runtime configuration is unprotected.')
        private_file(NM,NM_TEXT);nm_created=True
        command(['/usr/bin/nmcli','general','reload','conf'])
        command(['/usr/sbin/iw','dev',policy['wifi_interface'],'interface','add',AP,'type','__ap']);interface_created=True
        command(['/usr/sbin/ip','address','add',GATEWAY+'/24','dev',AP])
        command(['/usr/sbin/ip','link','set',AP,'up'])
        password=secrets.token_urlsafe(24)
        private_file(RUN/'hostapd.conf',hostapd_configuration(number,frequency,password))
        private_file(RUN/'dnsmasq.conf',dhcp_configuration())
        ap=subprocess.Popen(['/usr/sbin/hostapd',str(RUN/'hostapd.conf')],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=ENV)
        deadline=time.monotonic()+15
        while True:
            if stopped: return
            if ap.poll() is not None: raise HotspotError('The Wi-Fi driver refused the hotspot; original uplink was not reconfigured.')
            try: state=command(['/usr/sbin/hostapd_cli','-p',str(RUN/'control'),'-i',AP,'status'],timeout=2)
            except Exception: state=''
            if 'state=ENABLED\n' in state and 'freq='+str(frequency)+'\n' in state: break
            if time.monotonic()>=deadline: raise HotspotError('Hotspot did not become ready on the existing Wi-Fi channel.')
            time.sleep(.25)
        dhcp=subprocess.Popen(['/usr/sbin/dnsmasq','--no-daemon','--conf-file='+str(RUN/'dnsmasq.conf')],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=ENV)
        time.sleep(.5)
        if dhcp.poll() is not None: raise HotspotError('The isolated hotspot DHCP service could not start.')
        print('Hotspot ready. On iPhone, turn OFF mobile data for this VPN-only test.',flush=True)
        print('Wi-Fi name: '+SSID+'\nWi-Fi password: '+password+'\nKeep this terminal open. Ctrl+C stops hotspot and restores normal laptop networking.',flush=True)
        if os.access('/usr/bin/qrencode',os.X_OK):
            subprocess.run(['/usr/bin/qrencode','-t','UTF8'],input=f'WIFI:T:WPA;S:{SSID};P:{password};;\n',text=True,check=True,timeout=3,env=ENV)
        while not stopped:
            if any(child.poll() is not None for child in (vpn,ap,dhcp)):
                raise HotspotError('A VPN or hotspot service stopped; shutting down hotspot.')
            if not diagnostics.public_tunnel(): raise HotspotError('The VPN route changed; hotspot stopped.')
            modules['network_setup'].verify_during_session()
            current=command(['/usr/sbin/iw','dev',policy['wifi_interface'],'info'])
            if not re.search(r'channel '+str(number)+r' \('+str(frequency)+r' MHz\)',current):
                raise HotspotError('Upstream Wi-Fi changed channel; hotspot stopped without retuning it.')
            time.sleep(1)
    finally:
        cleanup_ok=True;interface_removed=not interface_created
        stop_child(ap);stop_child(dhcp)
        if interface_created:
            try:
                command(['/usr/sbin/iw','dev',AP,'del']);interface_removed=True
            except Exception: cleanup_ok=False
        stop_child(vpn)
        if forward_changed:
            try:
                current_forward=forwarding.read_text().strip()
                if current_forward=='1': forwarding.write_text(original_forward+'\n')
                elif current_forward!=original_forward: cleanup_ok=False
            except OSError: cleanup_ok=False
        if gateway_applied and cleanup_ok:
            try: guard_batch(modules,False)
            except Exception: cleanup_ok=False
        if nm_created and interface_removed:
            try:
                if NM.read_text()!=NM_TEXT: raise HotspotError('Runtime NM file changed.')
                NM.unlink();command(['/usr/bin/nmcli','general','reload','conf'])
            except Exception: cleanup_ok=False
        if cleanup_ok:
            try:
                if not modules['portal_helper'].active_openvpn(): restore_network(modules)
                else: cleanup_ok=False
            except Exception: cleanup_ok=False
        for number,handler in previous.items(): signal.signal(number,handler)
        if cleanup_ok:
            for name in ('hostapd.conf','dnsmasq.conf'): (RUN/name).unlink(missing_ok=True)
            # hostapd removes its own control socket; preserve unexpected files.
            control=RUN/'control'
            if control.exists() and not any(control.iterdir()): control.rmdir()
            if not any(RUN.iterdir()): RUN.rmdir()
            print('Hotspot stopped; normal laptop networking restored.',flush=True)
        else:
            print('Cleanup could not be fully verified. Do not assume firewall protection. Keep this terminal output for review.',flush=True)


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    if os.geteuid()!=0 or not sys.flags.isolated: raise HotspotError('Use sudo with the verified Python -I -B runner.')
    owner=int(os.environ.get('SUDO_UID','0'))
    if owner<=0: raise HotspotError('Start from your ordinary Kali desktop account.')
    os.chdir('/');os.environ.clear();os.environ.update(ENV)
    sources=globals().get('HOTSPOT_SOURCES')
    if not isinstance(sources,dict) or set(sources)!=set(SOURCE_SHA256): raise HotspotError('A complete verified hotspot bundle is required.')
    for name,source in sources.items():
        if hashlib.sha256(source.encode()).hexdigest()!=SOURCE_SHA256[name]: raise HotspotError('Hotspot source checksum mismatch.')
        compile(source,'checked-'+name,'exec')
    diagnostics=checked_module('client_diagnostics.py',sources['client_diagnostics.py'])
    updater=checked_module('upgrade_client_transport.py',sources['upgrade_client_transport.py'])
    with owned_lock('/run/vpn-desk-hotspot.lock'):
        run(owner,sources,diagnostics,updater)


if __name__=='__main__':
    try: main()
    except KeyboardInterrupt:
        print('Hotspot startup cancelled.',flush=True)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        detail=str(error) if isinstance(error,HotspotError) else 'A required verification or local operation failed.'
        raise SystemExit('VPN hotspot stopped or refused: '+detail) from None
