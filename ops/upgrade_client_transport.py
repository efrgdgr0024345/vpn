#!/usr/bin/python3
"""Explicit, hash-pinned upgrade of the owned client's transport/log bundle.

Run using system Python -I -B after independently verifying this script and the
candidate helper. Optional DHCP-only policy refresh requires a verified current
lease and an inactive network guard. No profile, credential or network changes.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace

HELPER = Path('/usr/local/libexec/vpn-desk/vpn_session_helper.py')
MANIFEST = Path('/opt/vpn-desk/install-manifest.json')
LOCK = Path('/run/vpn-dashboard-portal.lock')
CONFIG = Path('/etc/vpn-desk')
ROOTS = (Path('/opt/vpn-desk'), Path('/usr/local/libexec/vpn-desk'))
EXACT = {'/usr/local/bin/vpn-desk', '/usr/local/share/applications/vpn-desk.desktop'}
OLD_SHA256 = 'fa6137221cd9638e0e55db4356598457bfb13e2883b0544c669b47ca2ca2f96b'
LEGACY = {
    'vpn_session_helper.py': {'fa6137221cd9638e0e55db4356598457bfb13e2883b0544c669b47ca2ca2f96b',
                              'f2ca82581f2ae80900a94909f3172ae998bda0352b01fa8a62f1d44971df5044',
                              '0ab9f832632d035a5f6d393458931c8741c0e6b833ad27daba74a1b7199b0fad',
                              '66e6cd175989f8ca408c18ce791577947c3db15bd093a81e436132b1f64240b5'},
    'session_channel.py': {'0f32f5050602f5a79a9f77a6837fc8f4bb9a9b8b7951b67b76bd9ceb4dd567b6',
                           'd3981174df69eb01f1bc96606aa8eac0faa3a014340fc1c8123f0df58f3f8cb6'},
    'session_ui.py': {'7fa19a51db92c708a1c321370bbfc6efa0cc94615a3a87d6b07be47148a2918a'},
    'portal_helper.py': {'e401522faad3638eff1f9d6d2874e26a7c749713e34a2fb0fe3b0c78429e17ef'},
    'app.py': {'d0433e0f3f06edefb84e334183af599df79c13c17e6ab08ab025518397436b84'},
}


def targets():
    return {'vpn_session_helper.py': (HELPER,),
            'session_channel.py': (HELPER.parent/'session_channel.py', MANIFEST.parent/'session_channel.py'),
            'session_ui.py': (MANIFEST.parent/'session_ui.py',),
            'portal_helper.py': (HELPER.parent/'portal_helper.py',),
            'app.py': (MANIFEST.parent/'app.py',)}


class UpgradeError(RuntimeError):
    pass


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read_file(path, *, source=False, private=False):
    if not source:
        for parent in reversed(path.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise UpgradeError('Unprotected installed directory.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        owners = (0, int(os.environ.get('SUDO_UID', '0'))) if source else (0,)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid not in owners or info.st_mode & 0o022
                or private and stat.S_IMODE(info.st_mode) != 0o600):
            raise UpgradeError('Unsafe source or installed file metadata.')
        value = stream.read(2_000_001)
        if len(value) > 2_000_000:
            raise UpgradeError('Public source or inventory exceeds the size limit.')
        return value


def dhcp_address(value):
    try:
        address=ipaddress.IPv4Address(value)
        if (not isinstance(value,str) or str(address)!=value or address.is_loopback
                or address.is_unspecified or address.is_multicast or int(address)==0xffffffff):
            raise ValueError()
        return value
    except (ValueError,TypeError):
        raise UpgradeError('DHCP server must be one canonical unicast IPv4 address.') from None


@contextmanager
def installed_helpers(files):
    """Load only helper files already checked against the protected baseline."""
    names=('security','safe_io','session_channel','portal_helper','firewall_policy')
    if any(str(HELPER.parent/(name+'.py')) not in files for name in names):
        raise UpgradeError('Installed helper baseline is incomplete; DHCP settings preserved.')
    saved={name:sys.modules.pop(name,None) for name in names}
    previous=list(sys.path)
    try:
        sys.path.insert(0,str(HELPER.parent))
        importlib.invalidate_caches()
        modules={name:importlib.import_module(name) for name in names}
        if any(Path(module.__file__)!=HELPER.parent/(name+'.py') for name,module in modules.items()):
            raise UpgradeError('Installed helper import failed verification; DHCP settings preserved.')
        yield SimpleNamespace(**modules)
    finally:
        sys.path[:]=previous
        for name in names:
            sys.modules.pop(name,None)
            if saved[name] is not None:
                sys.modules[name]=saved[name]


def network_read(modules,argv,*,as_json=True):
    try:
        result=modules.safe_io.bounded_run(argv,timeout=5,limit=65536,
            env={'PATH':'/usr/sbin:/usr/bin','LC_ALL':'C'})
        if result.returncode:
            raise UpgradeError('Current network checks failed; DHCP settings preserved.')
        return json.loads(result.stdout) if as_json else result.stdout
    except (OSError,ValueError,subprocess.SubprocessError):
        raise UpgradeError('Current network checks failed; DHCP settings preserved.') from None


def inactive_lease(modules,policy,requested):
    """Inspect only; never release a guard or infer DHCP from the gateway."""
    try:
        active=modules.portal_helper.active_openvpn()
    except (OSError,RuntimeError):
        raise UpgradeError('Running VPN processes could not be verified; DHCP settings preserved.') from None
    if active:
        raise UpgradeError('Stop all VPN processes before refreshing DHCP settings.')
    if os.path.lexists(CONFIG/'network-state.json'):
        raise UpgradeError('Restore normal networking before refreshing DHCP settings.')
    document=network_read(modules,['/usr/sbin/nft','-j','list','ruleset'])
    if not isinstance(document,dict) or not isinstance(document.get('nftables'),list):
        raise UpgradeError('Firewall state is unverified; DHCP settings preserved.')
    for entry in document['nftables']:
        if not isinstance(entry,dict) or len(entry)!=1:
            raise UpgradeError('Firewall state is unverified; DHCP settings preserved.')
        kind,obj=next(iter(entry.items()))
        if not isinstance(obj,dict):
            raise UpgradeError('Firewall state is unverified; DHCP settings preserved.')
        if obj.get('table')=='vpn_guard' or kind=='table' and obj.get('name')=='vpn_guard':
            raise UpgradeError('Restore normal networking before refreshing DHCP settings.')
    links=network_read(modules,['/usr/sbin/ip','-j','-d','link','show'])
    if not isinstance(links,list) or not all(isinstance(row,dict) for row in links):
        raise UpgradeError('Network interfaces are unverified; DHCP settings preserved.')
    interface=policy['wifi_interface']
    if not any(row.get('ifname')==interface and isinstance(row.get('flags'),list) and 'UP' in row['flags'] for row in links):
        raise UpgradeError('Configured Wi-Fi interface must be up before refreshing DHCP settings.')
    kinds={'tun','wireguard','gre','gretap','ip6gre','ip6gretap','ipip','sit','vti','vti6',
           'xfrm','ovpn','ovpn-dco','ovpn-dco-v2','vxlan','geneve'}
    for row in links:
        info=row.get('linkinfo',{})
        if (not isinstance(info,dict) or not isinstance(row.get('ifname'),str)
                or row['ifname'].startswith(('tun','tap','wg','ovpn')) or info.get('info_kind') in kinds):
            raise UpgradeError('Stop all tunnels before refreshing DHCP settings.')
    routes=network_read(modules,['/usr/sbin/ip','-j','-4','route','show','table','all'])
    if not isinstance(routes,list) or not all(isinstance(row,dict) for row in routes):
        raise UpgradeError('IPv4 routes are unverified; DHCP settings preserved.')
    defaults=[row for row in routes if row.get('dst')=='default']
    if (len(defaults)!=1 or defaults[0].get('dev')!=interface or not defaults[0].get('gateway')
            or defaults[0].get('multipath') or defaults[0].get('nexthops')
            or any(str(row.get('dev','')).startswith(('tun','tap','wg','ovpn')) or 'encap' in row for row in routes)):
        raise UpgradeError('One ordinary IPv4 Wi-Fi default route is required for DHCP refresh.')
    route=network_read(modules,['/usr/sbin/ip','-j','-4','route','get',policy['vpn_server_ipv4']])
    if (not isinstance(route,list) or len(route)!=1 or not isinstance(route[0],dict)
            or route[0].get('dev')!=interface or route[0].get('multipath') or route[0].get('nexthops') or 'encap' in route[0]):
        raise UpgradeError('VPN endpoint route must use the installed Wi-Fi interface for DHCP refresh.')
    lease=network_read(modules,['/usr/bin/nmcli','-g','DHCP4.OPTION','device','show',interface],as_json=False)
    values=re.findall(r'^\s*dhcp_server_identifier[ \t]*=[ \t]*([^\s|]+)[ \t]*$',lease.replace('|','\n'),re.M)
    if not values or len(set(values))!=1 or dhcp_address(values[0])!=requested:
        raise UpgradeError('Requested DHCP server does not match the current explicit Wi-Fi lease.')


def prepare_dhcp_refresh(requested,files):
    requested=dhcp_address(requested)
    if stat.S_IMODE(CONFIG.lstat().st_mode)!=0o700:
        raise UpgradeError('Private configuration directory must retain mode 0700.')
    originals={name:read_file(CONFIG/name,private=True) for name in
               ('policy.json','client.ovpn','vpn-guard.candidate.json')}
    if len(originals['policy.json'])>8192 or len(originals['vpn-guard.candidate.json'])>65536:
        raise UpgradeError('Private configuration exceeds the supported size limit.')
    try:
        with installed_helpers(files) as modules:
            policy=modules.security.validate_policy(json.loads(originals['policy.json']))
            target=modules.security.validate_policy({**policy,'dhcp_server_ipv4':requested})
            modules.security.validate_profile(originals['client.ovpn'].decode('utf-8'),policy)
            uid=modules.security.service_account().pw_uid
            old=modules.firewall_policy.render_batch(policy,uid)
            new=modules.firewall_policy.render_batch(target,uid)
            candidate=json.loads(originals['vpn-guard.candidate.json'])
            canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'))
            if canonical(candidate) not in (canonical(old),canonical(new)):
                raise UpgradeError('Private firewall candidate differs from its supported baseline.')
            inactive_lease(modules,policy,requested)
            return {'originals':originals,'policy':policy,'requested':requested,'modules':modules,
                'target':target,'candidate':(json.dumps(new,indent=2)+'\n').encode()}
    except (ValueError,TypeError,KeyError,AttributeError,RuntimeError) as error:
        if isinstance(error,UpgradeError):
            raise
        raise UpgradeError('Private configuration could not be verified; DHCP settings preserved.') from None


def publish_private(path,value):
    fd,temporary=tempfile.mkstemp(prefix='.vpn-desk-dhcp-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,path)
        directory_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def commit_dhcp_refresh(plan):
    inactive_lease(plan['modules'],plan['policy'],plan['requested'])
    if any(read_file(CONFIG/name,private=True)!=value for name,value in plan['originals'].items()):
        raise UpgradeError('Private settings changed during upgrade; DHCP settings preserved.')
    if plan['target']==plan['policy']:
        return
    # Candidate is an inert review artifact. Publish it first; policy's atomic
    # replacement is the logical commit. A rerun recognizes only this exact pair.
    publish_private(CONFIG/'vpn-guard.candidate.json',plan['candidate'])
    publish_private(CONFIG/'policy.json',(json.dumps(plan['target'],indent=2)+'\n').encode())


def publish(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.vpn-desk-upgrade-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def load_bundle(source, expected):
    raw = read_file(source/'client-update.json', source=True)
    if not re.fullmatch(r'[0-9a-f]{64}', expected) or digest(raw) != expected:
        raise UpgradeError('Public update manifest hash mismatch; nothing installed.')
    document = json.loads(raw)
    if (not isinstance(document, dict) or set(document) != {'version', 'files'}
            or type(document['version']) is not int or document['version'] != 1
            or not isinstance(document['files'], dict) or set(document['files']) != set(targets())):
        raise UpgradeError('Unsupported public update manifest.')
    return {name: (read_file(source/name, source=True), value) for name, value in document['files'].items()}


def upgrade(candidate, expected, *, bundle=None, dhcp_server=None):
    if dhcp_server is not None:
        dhcp_server=dhcp_address(dhcp_server)
    updates = {HELPER: (candidate, expected, {OLD_SHA256})}
    if bundle is not None:
        if set(bundle) != set(targets()):
            raise UpgradeError('The complete reviewed transport/log bundle is required.')
        updates = {path: (value, checksum, LEGACY[name])
                   for name, (value, checksum) in bundle.items() for path in targets()[name]}
    for path, (value, checksum, _) in updates.items():
        if not isinstance(checksum, str) or not re.fullmatch(r'[0-9a-f]{64}', checksum) or digest(value) != checksum:
            raise UpgradeError('Candidate hash mismatch; nothing installed.')
        try:
            compile(value, path.name, 'exec')
        except SyntaxError:
            raise UpgradeError('Candidate Python syntax is invalid; nothing installed.') from None
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise UpgradeError('Unsafe action lock.')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise UpgradeError('Stop the VPN before upgrading.') from None
        processes = subprocess.run(['/usr/bin/ps', '-C', 'openvpn', '-o', 'pid='],
            capture_output=True, text=True, timeout=5,
            env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
        if processes.returncode != 1 or processes.stdout.strip() or processes.stderr.strip():
            raise UpgradeError('OpenVPN must be stopped and its process check must succeed.')
        document = json.loads(read_file(MANIFEST))
        if (not isinstance(document, dict) or set(document) != {'version', 'files'}
                or type(document['version']) is not int or document['version'] != 1 or not isinstance(document['files'], dict)
                or not 10 <= len(document['files']) <= 80
                or not (EXACT | {str(path) for path in updates}) <= set(document['files'])):
            raise UpgradeError('Unsupported installation baseline.')
        files = document['files']
        for path, (_, checksum, legacy) in updates.items():
            if files[str(path)] not in legacy | {checksum}:
                raise UpgradeError('Installed transport/log module has an unsupported baseline.')
        for name, recorded in files.items():
            path = Path(name)
            if (not path.is_absolute() or str(path) != name or '..' in path.parts
                    or not (name in EXACT or path.parent in ROOTS)
                    or re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', path.name) is None
                    or not isinstance(recorded, str) or re.fullmatch(r'[0-9a-f]{64}', recorded) is None):
                raise UpgradeError('Unsupported installation inventory entry.')
            actual = digest(read_file(path))
            # Resume safely if power failed between the two atomic file writes.
            transitional = path in updates and actual == updates[path][1] and recorded in updates[path][2]
            if actual != recorded and not transitional:
                raise UpgradeError('Installed files differ from the recorded baseline; nothing overwritten.')
        for root in ROOTS:
            if any(str(path) not in files and path != MANIFEST for path in root.iterdir()):
                raise UpgradeError('Unexpected installed file; nothing overwritten.')
        refresh=prepare_dhcp_refresh(dhcp_server,files) if dhcp_server is not None else None
        for path, (value, checksum, legacy) in updates.items():
            if digest(read_file(path)) not in legacy | {checksum}:
                raise UpgradeError('Unrecognized installed transport/log module; nothing overwritten.')
            publish(path, value)
            files[str(path)] = checksum
        publish(MANIFEST, (json.dumps(document, sort_keys=True, indent=2) + '\n').encode())
        if refresh is not None:
            commit_dhcp_refresh(refresh)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('sha256')
    parser.add_argument('--dhcp-server',type=dhcp_address,
                        help='Refresh only the DHCP server from the confirmed current Wi-Fi lease.')
    args = parser.parse_args()
    if os.geteuid() != 0 or not sys.flags.isolated:
        raise UpgradeError('Use sudo with /usr/bin/python3 -I -B.')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    bundle = load_bundle(args.source, args.sha256)
    candidate, expected = bundle['vpn_session_helper.py']
    upgrade(candidate, expected, bundle=bundle,dhcp_server=args.dhcp_server)
    print('Transport/log modules and public-code baseline updated. '+
          ('The confirmed DHCP policy was refreshed. ' if args.dhcp_server is not None else 'Private settings were preserved. ')+
          'Networking was unchanged. Reopen VPN Desk.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, UpgradeError, subprocess.SubprocessError) as error:
        print('Upgrade stopped: ' + (str(error) if isinstance(error, UpgradeError) else
              'Update incomplete; verify the installed baseline before retrying. Private details withheld.'))
        raise SystemExit(1)
