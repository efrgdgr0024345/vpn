"""Make a deterministic source-only review ZIP from an immutable Git commit.

Keep the printed whole-archive hash independently. The manifest inside the ZIP
is useful inventory, not an independent trust anchor or a maintainer signature.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import subprocess
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def git(*arguments):
    return subprocess.check_output(['git','-C',str(ROOT),*arguments],timeout=30)


def source_files(revision):
    forbidden={'.key','.pem','.ovpn','.p12','.pfx','.crt','.cer','.zip'}
    for record in git('ls-tree','-r','-z',revision).split(b'\0'):
        if not record:
            continue
        metadata,name=record.split(b'\t',1)
        mode,kind,blob=metadata.decode('ascii').split()
        name=name.decode('utf-8')
        path=PurePosixPath(name)
        if (mode not in ('100644','100755') or kind!='blob' or path.is_absolute() or '..' in path.parts
                or any(ord(c)<32 for c in name) or path.suffix.lower() in forbidden
                or path.name.startswith('.env') or path.name in ('login.txt','auth.txt','id_ed25519','id_rsa')):
            raise RuntimeError('Unsupported or potentially private tracked file; review bundle refused.')
        value=git('cat-file','blob',blob)
        if len(value)>2_000_000:
            raise RuntimeError('Tracked source exceeds the review-bundle file limit.')
        yield name,mode,value


def build(output,revision):
    if not re.fullmatch(r'[0-9a-f]{40}',revision):
        raise RuntimeError('Use an exact Git commit ID.')
    files=list(source_files(revision))
    manifest={'version':1,'source_commit':revision,'files':{
        name:{'sha256':hashlib.sha256(value).hexdigest(),'git_mode':mode} for name,mode,value in files}}
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'wb') as stream,zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_STORED) as archive:
            for name,mode,value in files:
                info=zipfile.ZipInfo('source/'+name,date_time=(1980,1,1,0,0,0))
                info.create_system=3
                info.external_attr=(int(mode,8)<<16)
                info.compress_type=zipfile.ZIP_STORED
                archive.writestr(info,value)
            info=zipfile.ZipInfo('REVIEW_MANIFEST.json',date_time=(1980,1,1,0,0,0))
            info.create_system=3
            info.external_attr=(0o100644<<16)
            info.compress_type=zipfile.ZIP_STORED
            archive.writestr(info,json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    except BaseException:
        Path(output).unlink(missing_ok=True)
        raise
    return hashlib.sha256(Path(output).read_bytes()).hexdigest()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--revision')
    args=parser.parse_args()
    revision=args.revision or git('rev-parse','HEAD').decode().strip()
    digest=build(args.output,revision)
    print(json.dumps({'source_commit':revision,'archive_sha256':digest,'archive':str(args.output)},sort_keys=True))
