"""Compare installed public code to its root-protected installation baseline.

This detects differences from that baseline, not compromise of the baseline or
the OS. Keep an independently trusted source/release copy for later review.
"""
import hashlib
import json
import re
from pathlib import Path
import stat

MANIFEST = Path('/opt/vpn-desk/install-manifest.json')
PREFIXES = ('/opt/vpn-desk/', '/usr/local/libexec/vpn-desk/')
EXACT = {'/usr/local/bin/vpn-desk', '/usr/local/share/applications/vpn-desk.desktop'}
REQUIRED=EXACT | {'/usr/local/libexec/vpn-desk/'+name for name in
                  ('privileged.py','security.py','safe_io.py','portal_helper.py',
                   'vpn_session_helper.py','session_channel.py','network_setup.py','firewall_policy.py')}
REQUIRED |= {'/opt/vpn-desk/'+name for name in ('app.py','install_audit.py','session_ui.py','session_channel.py')}


class AuditError(RuntimeError):
    pass


def code_digest(path):
    path=Path(path)
    for parent in reversed(path.parents):
        info=parent.lstat()
        if info.st_uid!=0 or not stat.S_ISDIR(info.st_mode) or info.st_mode&0o022:
            raise AuditError('Unprotected installed code directory.')
    import os
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022:
            raise AuditError('Unprotected installed code file.')
        value=stream.read(2_000_001)
        if len(value)>2_000_000:
            raise AuditError('Installed code file is oversized.')
        return hashlib.sha256(value).hexdigest(),value


def make_manifest(files):
    return {'version':1,'files':{str(path):hashlib.sha256(value).hexdigest()
                              for path,value in sorted(files.items(),key=lambda row:str(row[0]))}}


def check(manifest=MANIFEST):
    try:
        _,raw=code_digest(manifest)
        document=json.loads(raw)
        if not isinstance(document,dict) or set(document)!={'version','files'} or document['version']!=1:
            raise AuditError('Unsupported installation baseline.')
        files=document['files']
        if not isinstance(files,dict) or not 10<=len(files)<=80:
            raise AuditError('Unsupported installation inventory.')
        if not REQUIRED<=set(files):
            raise AuditError('Incomplete installation inventory.')
        missing=[]
        changed=[]
        checked=[]
        for name,digest in files.items():
            path=Path(name)
            if (not path.is_absolute() or '..' in path.parts or str(path)!=name
                    or not (name in EXACT or any(name.startswith(p) and '/' not in name[len(p):] for p in PREFIXES))
                    or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',path.name)
                    or not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest)):
                raise AuditError('Unsupported installation inventory.')
            try:
                actual,_=code_digest(path)
            except FileNotFoundError:
                missing.append(path.name)
            else:
                if actual!=digest:
                    changed.append(path.name)
                checked.append(path.name)
        unexpected=0
        for prefix in PREFIXES:
            try:
                children=list(Path(prefix).iterdir())
            except FileNotFoundError:
                continue
            for child in children:
                if str(child) not in files and child!=Path(manifest):
                    unexpected+=1
        return {'state':'mismatch' if missing or changed or unexpected else 'matches_baseline',
                'checked':len(checked),'missing':sorted(missing),'changed':sorted(changed),
                'unexpected_files':unexpected,
                'note':'Compared with the recorded install baseline; this does not attest the operating system or baseline itself.'}
    except FileNotFoundError:
        return {'state':'not_installed','note':'No installed baseline is available.'}
    except (AuditError,OSError,ValueError,TypeError,KeyError):
        return {'state':'unverified','note':'The installed baseline or code could not be safely checked.'}


def format_report(report):
    states={'matches_baseline':'Installed files match the recorded baseline.',
            'mismatch':'Installed files differ from the recorded baseline.',
            'not_installed':'No installed baseline is available.',
            'unverified':'Installation integrity is unverified.'}
    text=states[report['state']]+'\n'+report['note']
    if report['state'] in ('matches_baseline','mismatch'):
        text+='\nFiles checked: '+str(report['checked'])
        if report['changed']:
            text+='\nChanged: '+', '.join(report['changed'])
        if report['missing']:
            text+='\nMissing: '+', '.join(report['missing'])
        if report.get('unexpected_files'):
            text+='\nUnexpected files/directories: '+str(report['unexpected_files'])
    return text+'\n'
