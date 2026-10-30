from contextlib import contextmanager
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ops'))
import inspect_test_peer as peer

WIRE=peer.WIRE_PREFIX+bytes(range(32))
BLOB=base64.b64encode(WIRE).decode()
PIN='SHA256:'+base64.b64encode(hashlib.sha256(WIRE).digest()).decode().rstrip('=')
SCAN='192.0.2.12 ssh-ed25519 '+BLOB+'\n'
REPORT={'version':1,'root_confirmed':True,'os':{'ID':'debian','VERSION_ID':'13'},
        'kernel':'6.12.113+deb13-amd64','access_server_active':None,
        'openvpn_client':{'path':None,'version':None},
        'tools':{'ip':True,'python3':True,'curl':False,'nft':False}}


class PeerInspectionTests(unittest.TestCase):
    @contextmanager
    def key(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)/'key'
            folder.mkdir(mode=0o700)
            key=folder/'id_ed25519'
            key.write_bytes(b'PRIVATE TEST FIXTURE ONLY')
            key.chmod(0o600)
            real_lstat,real_fstat=Path.lstat,os.fstat
            def root_directory(path):
                if path==folder:
                    value=real_lstat(path)
                    return SimpleNamespace(st_mode=value.st_mode,st_uid=0)
                return SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
            def root_file(fd):
                value=real_fstat(fd)
                fields=list(value)
                fields[4]=0
                return os.stat_result(fields)
            with patch.object(peer,'KEY',key),patch.object(peer,'RUNTIME',Path(directory)), \
                    patch.object(Path,'lstat',root_directory), \
                    patch.object(os,'fstat',side_effect=root_file):
                yield key

    def result(self,text=SCAN,code=0,stderr=''):
        return subprocess.CompletedProcess([],code,text,stderr)

    def test_literal_peer_identity_is_required_without_shell_or_hostname_input(self):
        self.assertEqual(peer.settings('192.0.2.12','022',PIN),('192.0.2.12','22',PIN))
        for host,port,pin in (('example.com','22',PIN),('127.0.0.1','22',PIN),
                ('169.254.169.254','22',PIN),('255.255.255.255','22',PIN),
                ('0.0.0.0','22',PIN),('224.0.0.1','22',PIN),
                ('192.0.2.12','22 -v',PIN),('192.0.2.12','65536',PIN),
                ('192.0.2.12','22','SHA256:short')):
            with self.assertRaises(peer.PeerError):
                peer.settings(host,port,pin)

    def test_bad_or_mismatched_host_identity_never_authenticates(self):
        for output,code in (('',1),('',0),('192.0.2.12 ssh-ed25519 !!!\n',0),
                (SCAN.replace('192.0.2.12','192.0.2.13'),0),
                (SCAN.replace(BLOB,base64.b64encode(peer.WIRE_PREFIX+b'x'*32).decode()),0)):
            calls=[]
            def execute(argv,**kwargs):
                calls.append(argv)
                return self.result(output,code)
            with self.key(),patch.object(os,'geteuid',return_value=0), \
                    self.assertRaisesRegex(peer.PeerError,'host_pin_failed'):
                peer.inspect('192.0.2.12','22',PIN,execute)
            self.assertEqual(len(calls),1)
            self.assertEqual(calls[0][0],'/usr/bin/ssh-keyscan')

    def test_actual_file_permissions_links_and_parent_metadata_remain_required(self):
        for kind in ('writeable','hardlink','symlink','parent_writeable'):
            with self.subTest(kind=kind),self.key() as key:
                if kind=='writeable':
                    key.chmod(0o644)
                elif kind=='hardlink':
                    os.link(key,key.with_name('other'))
                elif kind=='symlink':
                    backup=key.with_name('saved')
                    key.rename(backup)
                    key.symlink_to(backup)
                else:
                    key.parent.chmod(0o777)
                with self.assertRaisesRegex(peer.PeerError,'unsafe_key'):
                    peer.check_key()

    def test_pinned_fixed_inventory_uses_private_known_hosts_and_cleans_it_up(self):
        paths=[]
        def execute(argv,**kwargs):
            if argv[0].endswith('ssh-keyscan'):
                return self.result()
            self.assertEqual(argv[0],'/usr/bin/ssh')
            for flag in ('IdentitiesOnly=yes','BatchMode=yes','StrictHostKeyChecking=yes',
                    'IdentityAgent=none','ForwardAgent=no','ClearAllForwardings=yes',
                    'GlobalKnownHostsFile=/dev/null','PreferredAuthentications=publickey',
                    'HostKeyAlgorithms=ssh-ed25519'):
                self.assertIn(flag,argv)
            path=Path(next(item.split('=',1)[1] for item in argv if item.startswith('UserKnownHostsFile=')))
            paths.append(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            self.assertEqual(path.read_text(),SCAN)
            self.assertEqual(kwargs['input'],peer.REMOTE)
            self.assertEqual(argv[-1],'/usr/bin/python3 -I -B -')
            self.assertNotIn('PRIVATE',str(argv)+kwargs['input'])
            return self.result(json.dumps(REPORT))
        with self.key(),patch.object(os,'geteuid',return_value=0):
            self.assertEqual(peer.inspect('192.0.2.12','22',PIN,execute),REPORT)
        self.assertTrue(paths)
        self.assertTrue(all(not path.exists() for path in paths))

    def test_remote_authentication_errors_or_private_output_are_withheld(self):
        for report,code in (('PRIVATE CREDENTIAL OUTPUT',255),('PRIVATE CREDENTIAL OUTPUT',0),
                (json.dumps({**REPORT,'password':'PRIVATE'}),0)):
            paths=[]
            def execute(argv,**kwargs):
                if argv[0].endswith('ssh-keyscan'):
                    return self.result()
                paths.append(Path(next(item.split('=',1)[1] for item in argv if item.startswith('UserKnownHostsFile='))))
                return self.result(report,code,'PRIVATE STDERR')
            with self.key(),patch.object(os,'geteuid',return_value=0), \
                    self.assertRaises(peer.PeerError) as error:
                peer.inspect('192.0.2.12','22',PIN,execute)
            self.assertNotIn('PRIVATE',str(error.exception))
            self.assertTrue(all(not path.exists() for path in paths))

    def test_report_accepts_only_fixed_public_fields(self):
        self.assertEqual(peer.validate_report(copy.deepcopy(REPORT)),REPORT)
        values=[]
        for key,value in (('root_confirmed',1),('version',True),('kernel','PRIVATE\n'),
                ('access_server_active','PRIVATE'),('tools',{'ip':True,'password':'PRIVATE'}),
                ('openvpn_client',{'path':'/root/private','version':'2.7.3'}),
                ('os',{'ID':'PRIVATE','VERSION_ID':'13'})):
            value_report=copy.deepcopy(REPORT)
            value_report[key]=value
            values.append(value_report)
        values.extend(({**REPORT,'credentials':'PRIVATE'}, {'PRIVATE':'PRIVATE'}, None))
        for value in values:
            with self.assertRaises(ValueError) as error:
                peer.validate_report(value)
            self.assertEqual(str(error.exception),'Unsupported peer inspection report.')

    def test_nonroot_stops_before_key_or_host_checks(self):
        with patch.object(os,'geteuid',return_value=1000),patch.object(peer,'check_key') as key, \
                self.assertRaisesRegex(peer.PeerError,'root_required'):
            peer.inspect('192.0.2.12','22',PIN)
        key.assert_not_called()

    def test_command_output_and_deadline_are_bounded_without_exposing_data(self):
        for program,kwargs in (("print('PRIVATE'*1000)",{'limit':16}),
                               ('import time;time.sleep(1)',{'timeout':.02})):
            with self.assertRaises(peer.PeerError) as error:
                peer.run([sys.executable,'-I','-B','-c',program],**kwargs)
            self.assertEqual(str(error.exception),'command_failed')


if __name__=='__main__':
    unittest.main()
