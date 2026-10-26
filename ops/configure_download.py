"""Enroll a public key for temporary, chrooted, read-only VPN-file download."""
import base64
import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile

if __name__=='__main__':
    library=Path('/usr/local/libexec/vpn-lab/server_foundation.py')
    for path in (*reversed(library.parents),library):
        info=path.lstat()
        if (info.st_uid!=0 or info.st_mode&0o022 or
                not (stat.S_ISREG(info.st_mode) if path==library else stat.S_ISDIR(info.st_mode))):
            raise SystemExit('Installed download helper library is not protected.')
    sys.path.insert(0,str(library.parent))

import server_foundation as server

USER='vpn-lab-download'
BASE=Path('/var/lib/vpn-lab-export')
KEYS=Path('/etc/ssh/vpn-lab-export.keys')
BEGIN='# BEGIN VPN LAB DOWNLOAD'
END='# END VPN LAB DOWNLOAD'


def public_key(value):
    value=value.strip()
    fields=value.split()
    if '\n' in value or '\r' in value or len(fields)<2 or fields[0]!='ssh-ed25519':
        raise server.SetupError('Supply one ED25519 public-key line, not a private key.')
    try:
        wire=base64.b64decode(fields[1],validate=True)
    except ValueError:
        raise server.SetupError('Malformed public key.') from None
    if len(wire)!=51 or wire[:19]!=b'\0\0\0\x0bssh-ed25519\0\0\0\x20':
        raise server.SetupError('Malformed ED25519 public key.')
    fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip('=')
    return 'ssh-ed25519 '+fields[1]+' vpn-lab-download',fingerprint


def ssh_configuration(before):
    if BEGIN in before or END in before:
        if before.count(BEGIN)!=1 or before.count(END)!=1 or before.index(BEGIN)>before.index(END):
            raise server.SetupError('Ambiguous previous download configuration.')
        start,end=before.index(BEGIN),before.index(END)+len(END)
        before=before[:start]+before[end:]
    if not re.search(r'^\s*Subsystem\s+sftp\s+',before,re.M|re.I):
        before='Subsystem sftp internal-sftp\n'+before
    return before.rstrip()+f'''\n
{BEGIN}
Match User {USER}
    AllowUsers {USER}
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    AuthorizedKeysFile {KEYS}
    AuthorizedKeysCommand none
    TrustedUserCAKeys none
    ChrootDirectory {BASE}
    ForceCommand internal-sftp -R -d /files
    DisableForwarding yes
    PermitTTY no
    PermitUserRC no
{END}
'''


def export_file(path,value,uid,gid):
    try:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,uid) or info.st_nlink!=1:
            raise server.SetupError('Unsafe existing download file.')
    except FileNotFoundError:
        pass
    fd,temporary=tempfile.mkstemp(prefix='.vpn-download-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            stream.write(value)
            stream.flush()
            os.fchmod(stream.fileno(),0o400)
            os.fchown(stream.fileno(),uid,gid)
            os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def configure(value,configuration=Path('/etc/ssh/sshd_config'),reload_service=True):
    if os.geteuid()!=0:
        raise server.SetupError('Download enrollment requires local lab root.')
    public,fingerprint=public_key(value)
    profile=server.read_owned(server.EXPORT/'client.ovpn')
    login=server.read_owned(server.EXPORT/'login.txt')
    if len(login.splitlines())!=2 or login.splitlines()[0]!=server.CLIENT:
        raise server.SetupError('Protected VPN credentials are not ready.')
    try:
        account=pwd.getpwnam(USER)
    except KeyError:
        server.run(['/usr/sbin/useradd','--system','--user-group','--home-dir','/files',
                    '--no-create-home','--shell','/usr/sbin/nologin',USER])
        account=pwd.getpwnam(USER)
    group=grp.getgrnam(USER)
    if (account.pw_uid<=0 or account.pw_gid<=0 or account.pw_gid!=group.gr_gid
            or account.pw_shell!='/usr/sbin/nologin' or account.pw_dir!='/files'
            or set(os.getgrouplist(USER,account.pw_gid))!={account.pw_gid}
            or any(p.pw_uid==account.pw_uid and p.pw_name!=USER for p in pwd.getpwall())):
        raise server.SetupError('Download account conflicts with existing local permissions.')
    # Keep the account accessible to public-key auth even if sshd uses no PAM;
    # the unknown random password is never stored or permitted by sshd.
    server.run(['/usr/sbin/chpasswd'],data=USER+':'+secrets.token_urlsafe(32)+'\n')
    server.directory(BASE)
    BASE.chmod(0o755)
    files=BASE/'files'
    server.directory(files)
    os.chown(files,0,account.pw_gid)
    files.chmod(0o750)
    export_file(files/'client.ovpn',profile,account.pw_uid,account.pw_gid)
    export_file(files/'login.txt',login,account.pw_uid,account.pw_gid)
    expiry=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=24)).strftime('%Y%m%d%H%M%SZ')
    server.write(KEYS,'restrict,expiry-time="'+expiry+'" '+public+'\n',0o644)
    before=server.read_owned(configuration)
    candidate=configuration.with_name(configuration.name+'.download-candidate')
    server.write(candidate,ssh_configuration(before))
    try:
        server.run(['/usr/sbin/sshd','-t','-f',str(candidate)])
        effective=server.run(['/usr/sbin/sshd','-T','-f',str(candidate),
                              '-C','user='+USER+',host=localhost,addr=127.0.0.1'])
        options={line.split()[0]:' '.join(line.split()[1:]) for line in effective.splitlines() if line.split()}
        expected={'forcecommand':'internal-sftp -R -d /files','chrootdirectory':str(BASE),
                  'passwordauthentication':'no','kbdinteractiveauthentication':'no',
                  'permittty':'no','disableforwarding':'yes','authenticationmethods':'publickey',
                  'pubkeyauthentication':'yes','authorizedkeyscommand':'none','trustedusercakeys':'none'}
        if any(options.get(k)!=v for k,v in expected.items()):
            raise server.SetupError('The effective download sandbox differs from policy.')
        if USER not in options.get('allowusers','').split() or options.get('authorizedkeysfile')!=str(KEYS):
            raise server.SetupError('Download key/user selection differs from policy.')
        server.write(configuration,server.read_owned(candidate),0o644)
        if reload_service:
            server.run(['/usr/bin/systemctl','reload','ssh.service'])
    finally:
        candidate.unlink(missing_ok=True)
    return {'download_user':USER,'public_key_fingerprint':fingerprint,
            'expires_utc':expiry,'chrooted':True,'read_only':True,'shell_access':False,
            'credential_contents_returned':False}


def revoke():
    if os.geteuid()!=0:
        raise server.SetupError('Download revocation requires lab root.')
    KEYS.unlink(missing_ok=True)
    files=BASE/'files'
    if files.exists():
        server.directory(files)
        for name in ('client.ovpn','login.txt'):
            path=files/name
            try:
                info=path.lstat()
            except FileNotFoundError:
                continue
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise server.SetupError('Unexpected private export file type.')
            path.unlink()
    return {'new_download_access_closed':True,'private_export_copies_removed':True}


if __name__=='__main__':
    try:
        result=revoke() if globals().get('REVOKE_DOWNLOAD') is True else configure(globals().get('DOWNLOAD_PUBLIC_KEY',''))
        print(json.dumps(result,sort_keys=True))
    except (server.SetupError,OSError,ValueError,KeyError,subprocess.SubprocessError):
        print(json.dumps({'error':'setup_failed','detail':'Read-only download enrollment failed.'}))
        raise SystemExit(1)
