"""Run the actual guided root installer only in a disposable test container."""
import io
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import stat
import subprocess
import sys
import time
import zipfile

ROOT = Path('/test')
PHASE = 'preflight'


def run_installer(source, answers):
    master, slave = pty.openpty()
    with os.fdopen(master, 'r+b', buffering=0) as terminal, os.fdopen(slave, 'r+b', buffering=0) as child_terminal:
        process = subprocess.Popen(['/usr/bin/python3', '-I', '-B', str(source/'install.py'), '--root'],
            stdin=child_terminal, stdout=child_terminal, stderr=child_terminal, start_new_session=True,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C', 'SUDO_UID':'1000'})
        output = bytearray()
        try:
            terminal.write(answers)
            deadline = time.monotonic()+60
            while time.monotonic()<deadline:
                if select.select([terminal], [], [], .1)[0]:
                    output.extend(os.read(terminal.fileno(), 4096))
                    if len(output)>65536:
                        raise RuntimeError('Installer output exceeded the test limit.')
                elif process.poll() is not None:
                    return process.returncode, output.decode(errors='replace')
            raise RuntimeError('Interactive installation timed out.')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)


def main():
    global PHASE
    if (os.geteuid()!=0 or not Path('/.dockerenv').is_file()
            or os.environ.get('VPN_LAB_DISPOSABLE_INSTALLER_TEST')!='1'):
        raise RuntimeError('Use only the disposable installer test harness.')
    sys.path.insert(0, str(ROOT/'vpn-dashboard'))
    import install as wizard
    sys.path.insert(0, str(ROOT/'vpn-dashboard/tests'))
    from test_security import PROFILE
    required = sorted(set(wizard.HELPERS+wizard.APPLICATION+('install.py','install.sh')))
    for name in required:
        if Path(name).name!=name:
            raise RuntimeError('Unexpected source fixture name.')
    PHASE = 'source archive preparation'
    archive_bytes = io.BytesIO()
    from_archive = len(sys.argv) in (2, 3)
    updated_installer = len(sys.argv)==3 and sys.argv[2]=='--updated-installer'
    if len(sys.argv)>3 or (len(sys.argv)==3 and not updated_installer):
        raise RuntimeError('Unsupported source fixture arguments.')
    legacy = from_archive and not updated_installer
    if from_archive:
        archive = zipfile.ZipFile(sys.argv[1])
        try:
            contents = {}
            for name in required:
                entries = [item for item in archive.namelist() if item.endswith('/vpn-dashboard/'+name)]
                if len(entries)!=1:
                    raise RuntimeError('Legacy source archive has unexpected members.')
                if archive.getinfo(entries[0]).file_size>1_000_000:
                    raise RuntimeError('Legacy source member exceeds the fixture limit.')
                contents[name] = archive.read(entries[0])
        finally:
            archive.close()
        if updated_installer:
            contents['install.py'] = (ROOT/'vpn-dashboard/install.py').read_bytes()
    else:
        contents = {name:(ROOT/'vpn-dashboard'/name).read_bytes() for name in required}
    with zipfile.ZipFile(archive_bytes, 'w') as archive:
        for name, content in contents.items():
            entry = zipfile.ZipInfo(name)
            entry.create_system = 0
            entry.external_attr = 0x20  # GitHub ZIPs do not supply Unix modes.
            archive.writestr(entry, content)
    source = ROOT/'unpacked'
    source.mkdir(mode=0o700)
    os.chown(source,1000,1000)
    previous = os.umask(0o002)
    try:
        with zipfile.ZipFile(archive_bytes) as archive:
            for name in required:
                path = source/name
                path.write_bytes(archive.read(name))
                os.chown(path,1000,1000)
    finally:
        os.umask(previous)
    assert stat.S_IMODE((source/'install.py').stat().st_mode)==0o664
    PHASE = 'unsafe source refusal'
    result, output = run_installer(source, b'')
    expected = 'Unexpected installation bundle member.' if legacy else 'group/other writable'
    if result==0 or expected not in output or Path('/usr/local/libexec/vpn-desk/privileged.py').exists():
        raise RuntimeError('Writable source was not refused before installation.')
    if not legacy:
        check = subprocess.run(['/usr/bin/python3','-I','-B',str(source/'install.py'),'--check'],
            user=1000,group=1000,extra_groups=[],capture_output=True,text=True,timeout=10)
        if check.returncode==0 or 'group/other writable' not in check.stderr:
            raise RuntimeError('Read-only preflight did not diagnose unsafe extracted source.')
    PHASE = 'ordinary-user source permission preparation'
    prepare = ('from pathlib import Path; import stat; p=Path("/test/unpacked"); '
               '[(f.chmod(stat.S_IMODE(f.stat().st_mode)&~0o022)) for f in p.iterdir() if f.is_file()]')
    subprocess.run(['/usr/bin/python3','-I','-B','-c',prepare],user=1000,group=1000,
                   extra_groups=[],check=True,timeout=10)
    if not legacy:
        check = subprocess.run(['/usr/bin/python3','-I','-B',str(source/'install.py'),'--check'],
            user=1000,group=1000,extra_groups=[],capture_output=True,text=True,timeout=10)
        if (check.returncode!=0 or 'Nothing installed' not in check.stdout
                or Path('/usr/local/libexec/vpn-desk/privileged.py').exists()):
            raise RuntimeError('Read-only preflight did not complete without installing files.')
    profile = Path('/home/vpn-install-test/vpn-lab/client.ovpn')
    profile.parent.mkdir(mode=0o700)
    os.chown(profile.parent,1000,1000)
    profile.write_text(PROFILE)
    profile.chmod(0o600)
    os.chown(profile,1000,1000)
    resolver = Path('/etc/resolv.conf').read_bytes()
    routes = subprocess.check_output(['/usr/sbin/ip','-j','route'])
    if not legacy:
        PHASE = 'declining the final confirmation'
        result, output = run_installer(source, b'wlan0\n192.0.2.1\nn\n')
        if (result!=1 or 'Application installation cancelled.' not in output
                or Path('/usr/local/libexec/vpn-desk/privileged.py').exists()
                or Path('/etc/vpn-desk').exists()):
            raise RuntimeError('Declining confirmation did not leave application files untouched.')
    PHASE = 'interactive root installation'
    # No physical Wi-Fi or NetworkManager exists in this unprivileged container.
    # Current installers reuse the default profile, then ask only for the two
    # unavailable network fields and the final confirmation.
    answers = b'\n\n\n\n\n192.0.2.1\n\n\n' if legacy else b'wlan0\n192.0.2.1\ny\n'
    result, output = run_installer(source, answers)
    if result!=0 or 'Installed. Open VPN Desk' not in output:
        raise RuntimeError('The real guided installer did not complete.')
    if not legacy:
        if ('Installation settings:' not in output or 'Profile file path [' in output
                or 'VPN server IPv4 [' in output or 'Expected TLS certificate name (' in output):
            raise RuntimeError('Known profile fields were unnecessarily requested.')
    PHASE = 'installed ownership and configuration'
    helper = Path('/usr/local/libexec/vpn-desk/privileged.py')
    if helper.read_bytes()!=contents['privileged.py'] or helper.stat().st_uid!=0 or helper.stat().st_mode&0o022:
        raise RuntimeError('The installed helper is not the protected reviewed source.')
    config = Path('/etc/vpn-desk/client.ovpn')
    if config.read_text()!=PROFILE or config.stat().st_uid!=0 or stat.S_IMODE(config.stat().st_mode)!=0o600:
        raise RuntimeError('The imported profile is not protected.')
    probe = ('import sys; sys.path.insert(0,"/usr/local/libexec/vpn-desk"); '
             'import privileged; privileged.verify_installation()')
    subprocess.run(['/usr/bin/python3','-I','-B','-c',probe],check=True,timeout=10)
    PHASE = 'same-version rerun'
    result, output = run_installer(source,b'\n')
    if result!=0 or 'Reusing the existing protected configuration' not in output:
        raise RuntimeError('The installed configuration could not be reused.')
    PHASE = 'reviewed transport upgrade'
    candidate = ROOT/'vpn-dashboard'
    update_manifest = json.loads((candidate/'client-update.json').read_text())
    private_config = {path: path.read_bytes() for path in Path('/etc/vpn-desk').iterdir()}
    for _ in range(2):
        result = subprocess.run(['/usr/bin/python3','-I','-B',str(ROOT/'upgrade_client_transport.py'),
                        str(candidate),hashlib.sha256((candidate/'client-update.json').read_bytes()).hexdigest()],
                       timeout=15,capture_output=True,text=True)
        if result.returncode:
            if result.stdout.startswith('Upgrade stopped: ') and len(result.stdout) < 256:
                print('::error title=Transport upgrade fixture::'+result.stdout.strip(),flush=True)
            raise RuntimeError('The reviewed transport upgrade did not complete.')
    if (Path('/usr/local/libexec/vpn-desk/vpn_session_helper.py').read_bytes()!=(candidate/'vpn_session_helper.py').read_bytes()
            or any(path.read_bytes()!=value for path,value in private_config.items())):
        raise RuntimeError('The transport upgrade changed private configuration or missed its target.')
    for name in ('app.py','session_channel.py','session_ui.py'):
        if hashlib.sha256(Path('/opt/vpn-desk',name).read_bytes()).hexdigest()!=update_manifest['files'][name]:
            raise RuntimeError('The desktop logging modules did not match the reviewed bundle.')
    # Load the real protected installation after source-module imports. This
    # verifies the refresh loader does not reuse sibling/cached checkout code.
    sys.path.insert(0,str(ROOT))
    import upgrade_client_transport as checked_upgrade
    recorded=json.loads(Path('/opt/vpn-desk/install-manifest.json').read_text())['files']
    with checked_upgrade.installed_helpers(recorded) as installed:
        policy=installed.security.load_policy()
        installed.security.validate_profile(config.read_text(),policy)
        uid=installed.security.service_account().pw_uid
        if installed.firewall_policy.render_batch(policy,uid)!=json.loads(Path('/etc/vpn-desk/vpn-guard.candidate.json').read_text()):
            raise RuntimeError('The protected private candidate did not match its installed renderer.')
    audit = ('import sys;sys.path.insert(0,"/opt/vpn-desk");import install_audit;'
             'raise SystemExit(0 if install_audit.check()["state"]=="matches_baseline" else 1)')
    subprocess.run(['/usr/bin/python3','-I','-B','-c',audit],check=True,timeout=10)
    if (Path('/etc/resolv.conf').read_bytes()!=resolver
            or subprocess.check_output(['/usr/sbin/ip','-j','route'])!=routes
            or Path('/etc/vpn-desk/network-state.json').exists()):
        raise RuntimeError('Installation changed networking before Connect.')
    print('PASS: ZIP source guards, real installation/rerun, reviewed transport upgrade with matching audit, unchanged private settings and networking.')


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print('::error title=Installer integration::Failed during '+PHASE+' ('+type(error).__name__+').',flush=True)
        raise SystemExit(1)
