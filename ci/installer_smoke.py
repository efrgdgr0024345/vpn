"""Run the actual guided root installer only in a disposable test container."""
import io
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
    legacy = len(sys.argv)==2
    if legacy:
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
    PHASE = 'interactive root installation'
    result, output = run_installer(source, b'\n\n\n\n\n192.0.2.1\n\n\n')
    if result!=0 or 'Installed. Open VPN Desk' not in output:
        raise RuntimeError('The real guided installer did not complete.')
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
    if (Path('/etc/resolv.conf').read_bytes()!=resolver
            or subprocess.check_output(['/usr/sbin/ip','-j','route'])!=routes
            or Path('/etc/vpn-desk/network-state.json').exists()):
        raise RuntimeError('Installation changed networking before Connect.')
    print('PASS: extracted ZIP permission refusal, owner-only preparation, interactive installation, protected helper/profile, same-version rerun and unchanged networking.')


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print('::error title=Installer integration::Failed during '+PHASE+' ('+type(error).__name__+').',flush=True)
        raise SystemExit(1)
