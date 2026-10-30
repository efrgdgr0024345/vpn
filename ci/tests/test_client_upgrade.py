from contextlib import ExitStack, contextmanager, nullcontext
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

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ops'))
import upgrade_client_transport as upgrade
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'vpn-dashboard'))
import firewall_policy
import security

OLD = b'# reviewed old fixture\n'
NEW = b'# reviewed new fixture\n'


class UpgradeTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            base = Path(directory)
            app, helpers = base / 'app', base / 'helpers'
            app.mkdir()
            helpers.mkdir()
            helper, manifest = helpers / 'vpn_session_helper.py', app / 'install-manifest.json'
            exact = {str(base / 'launcher'), str(base / 'menu.desktop')}
            files = {str(helper): upgrade.digest(OLD)}
            helper.write_bytes(OLD)
            for path in [*(Path(p) for p in exact), *(app / ('public'+str(i)+'.py') for i in range(7))]:
                path.write_bytes(b'# public fixture\n')
                files[str(path)] = upgrade.digest(path.read_bytes())
            for path in (helpers/'session_channel.py', app/'session_channel.py', app/'session_ui.py',
                         helpers/'portal_helper.py', app/'app.py'):
                path.write_bytes(OLD)
                files[str(path)] = upgrade.digest(OLD)
            manifest.write_text(json.dumps({'version': 1, 'files': files}))
            private = base / 'client.ovpn'
            private.write_bytes(b'private fixture must remain unchanged')
            real_fstat = os.fstat
            def root_metadata(fd):
                info = real_fstat(fd)
                return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink)
            for name, value in {'HELPER': helper, 'MANIFEST': manifest, 'LOCK': base/'lock',
                                'ROOTS': (app, helpers), 'EXACT': exact,
                                'OLD_SHA256': upgrade.digest(OLD),
                                'LEGACY': {name: {upgrade.digest(OLD)} for name in upgrade.LEGACY}}.items():
                stack.enter_context(patch.object(upgrade, name, value))
            stack.enter_context(patch.object(upgrade.os, 'fstat', side_effect=root_metadata))
            stack.enter_context(patch.object(upgrade, 'read_file', side_effect=lambda p, **kwargs: p.read_bytes()))
            stack.enter_context(patch.object(upgrade.subprocess, 'run', return_value=
                                            subprocess.CompletedProcess([], 1, '', '')))
            yield base, private
            self.assertEqual(private.read_bytes(), b'private fixture must remain unchanged')

    def test_checked_update_and_same_version_rerun_preserve_private_settings(self):
        with self.fixture():
            for _ in range(2):
                upgrade.upgrade(NEW, upgrade.digest(NEW))
                self.assertEqual(upgrade.HELPER.read_bytes(), NEW)
                self.assertEqual(json.loads(upgrade.MANIFEST.read_text())['files'][str(upgrade.HELPER)],
                                 upgrade.digest(NEW))
                self.assertEqual(stat.S_IMODE(upgrade.HELPER.stat().st_mode), 0o644)

    def test_unknown_transport_or_other_installed_changes_are_preserved(self):
        for target in ('transport', 'other'):
            with self.subTest(target=target), self.fixture():
                path = upgrade.HELPER if target == 'transport' else next(upgrade.ROOTS[0].glob('public*.py'))
                path.write_bytes(b'unknown change\n')
                before = upgrade.MANIFEST.read_bytes()
                with self.assertRaises(upgrade.UpgradeError):
                    upgrade.upgrade(NEW, upgrade.digest(NEW))
                self.assertEqual(path.read_bytes(), b'unknown change\n')
                self.assertEqual(upgrade.MANIFEST.read_bytes(), before)

    def test_unexpected_shadow_module_is_refused(self):
        with self.fixture():
            (upgrade.ROOTS[1] / 'unexpected.py').write_bytes(b'pass\n')
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(upgrade.HELPER.read_bytes(), OLD)

    def test_bad_candidate_hash_or_syntax_is_refused_before_lock_or_writes(self):
        for value, expected in ((NEW, '0'*64), (b'invalid (\n', upgrade.digest(b'invalid (\n'))):
            with self.fixture():
                with self.assertRaises(upgrade.UpgradeError):
                    upgrade.upgrade(value, expected)
                self.assertFalse(upgrade.LOCK.exists())
                self.assertEqual(upgrade.HELPER.read_bytes(), OLD)

    def test_inventory_cannot_redirect_writes_or_read_private_material(self):
        with self.fixture() as (_, private):
            document = json.loads(upgrade.MANIFEST.read_text())
            document['files'][str(private)] = upgrade.digest(private.read_bytes())
            upgrade.MANIFEST.write_text(json.dumps(document))
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(upgrade.HELPER.read_bytes(), OLD)

    def test_active_process_and_held_action_lock_refuse_upgrade(self):
        with self.fixture(), patch.object(upgrade.subprocess, 'run', return_value=
                                          subprocess.CompletedProcess([], 0, '123\n', '')):
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(upgrade.HELPER.read_bytes(), OLD)
        with self.fixture(), patch.object(upgrade.fcntl, 'flock', side_effect=BlockingIOError):
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(upgrade.HELPER.read_bytes(), OLD)

    def test_known_interrupted_pair_can_finish_without_blessing_other_changes(self):
        with self.fixture():
            publish = upgrade.publish
            def interrupt(path, value):
                if path == upgrade.MANIFEST:
                    raise OSError('fixture power loss')
                publish(path, value)
            with patch.object(upgrade, 'publish', side_effect=interrupt):
                with self.assertRaises(OSError):
                    upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(upgrade.HELPER.read_bytes(), NEW)
            upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(json.loads(upgrade.MANIFEST.read_text())['files'][str(upgrade.HELPER)],
                             upgrade.digest(NEW))

    def test_source_metadata_still_rejects_writes_symlinks_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'SUDO_UID': str(os.getuid())}):
            source = Path(directory) / 'source.py'
            source.write_bytes(NEW)
            source.chmod(0o644)
            self.assertEqual(upgrade.read_file(source, source=True), NEW)
            source.chmod(0o666)
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.read_file(source, source=True)
            source.chmod(0o644)
            link = source.with_name('link.py')
            link.symlink_to(source)
            with self.assertRaises(OSError):
                upgrade.read_file(link, source=True)
            link.unlink()
            os.link(source, link)
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.read_file(source, source=True)

    def test_complete_bundle_updates_both_channel_copies_and_preserves_private_config(self):
        with self.fixture():
            bundle = {name: (NEW, upgrade.digest(NEW)) for name in upgrade.targets()}
            for _ in range(2):
                upgrade.upgrade(NEW, upgrade.digest(NEW), bundle=bundle)
                files = json.loads(upgrade.MANIFEST.read_text())['files']
                for paths in upgrade.targets().values():
                    for path in paths:
                        self.assertEqual(path.read_bytes(), NEW)
                        self.assertEqual(files[str(path)], upgrade.digest(NEW))

    def test_public_bundle_manifest_is_pinned_and_cannot_import_private_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            for name in upgrade.targets():
                (source/name).write_bytes(NEW)
            manifest = {'version': 1, 'files': {name: upgrade.digest(NEW) for name in upgrade.targets()}}
            path = source/'client-update.json'
            path.write_text(json.dumps(manifest))
            with patch.object(upgrade, 'read_file', side_effect=lambda p, **kwargs: p.read_bytes()):
                bundle = upgrade.load_bundle(source, upgrade.digest(path.read_bytes()))
                self.assertEqual(set(bundle), set(upgrade.targets()))
                with self.assertRaises(upgrade.UpgradeError):
                    upgrade.load_bundle(source, '0'*64)
                manifest['files']['../client.ovpn'] = '0'*64
                path.write_text(json.dumps(manifest))
                with self.assertRaises(upgrade.UpgradeError):
                    upgrade.load_bundle(source, upgrade.digest(path.read_bytes()))


class DhcpUpgradeTests(unittest.TestCase):
    fixture=UpgradeTests.fixture

    @contextmanager
    def network(self):
        with self.fixture() as (base,private), ExitStack() as stack:
            config=base/'config'
            config.mkdir(mode=0o700)
            policy={'wifi_interface':'wlan0','vpn_server_ipv4':'192.0.2.10','vpn_port':1194,
                    'vpn_protocol':'udp','dhcp_server_ipv4':'192.0.2.1','server_name':'VPNLabServer'}
            profile=('client\ndev tun0\nproto udp\nremote 192.0.2.10 1194\n'
                     'remote-cert-tls server\nverify-x509-name VPNLabServer name\n'
                     'tls-version-min 1.3\ndata-ciphers AES-256-GCM:AES-128-GCM\n'+
                     ''.join('<'+name+'>\nPRIVATE TEST FIXTURE\n</'+name+'>\n'
                             for name in ('ca','cert','key','tls-crypt'))).encode()
            for name,value in {'policy.json':json.dumps(policy).encode(),'client.ovpn':profile,
                'vpn-guard.candidate.json':json.dumps(firewall_policy.render_batch(policy,995)).encode()}.items():
                (config/name).write_bytes(value)
                (config/name).chmod(0o600)
            responses={
                ('/usr/sbin/nft','-j','list','ruleset'):{'nftables':[{'metainfo':{}}]},
                ('/usr/sbin/ip','-j','-d','link','show'):[{'ifname':'wlan0','flags':['UP']}],
                ('/usr/sbin/ip','-j','-4','route','show','table','all'):[{'dst':'default','dev':'wlan0','gateway':'192.0.2.1'}],
                ('/usr/sbin/ip','-j','-4','route','get','192.0.2.10'):[{'dev':'wlan0','gateway':'192.0.2.1','prefsrc':'192.0.2.4'}],
                ('/usr/bin/nmcli','-g','DHCP4.OPTION','device','show','wlan0'):'host_name = PRIVATE\n dhcp_server_identifier = 192.0.2.200\n'}
            def run(argv,**kwargs):
                value=responses[tuple(argv)]
                if callable(value):
                    value=value()
                return subprocess.CompletedProcess(argv,0,value if isinstance(value,str) else json.dumps(value),'')
            modules=SimpleNamespace(
                security=SimpleNamespace(validate_policy=security.validate_policy,
                    validate_profile=security.validate_profile,service_account=lambda:SimpleNamespace(pw_uid=995)),
                firewall_policy=firewall_policy,safe_io=SimpleNamespace(bounded_run=run),
                portal_helper=SimpleNamespace(active_openvpn=lambda:False))
            stack.enter_context(patch.object(upgrade,'CONFIG',config))
            stack.enter_context(patch.object(upgrade,'installed_helpers',side_effect=lambda files:nullcontext(modules)))
            yield config,policy,profile,responses,modules
            self.assertEqual((config/'client.ovpn').read_bytes(),profile)

    def test_confirmed_refresh_changes_only_dhcp_and_derived_candidate_at_mode_0600(self):
        with self.network() as (config,policy,profile,responses,modules):
            for _ in range(2):
                upgrade.upgrade(NEW,upgrade.digest(NEW),dhcp_server='192.0.2.200')
                target={**policy,'dhcp_server_ipv4':'192.0.2.200'}
                self.assertEqual(json.loads((config/'policy.json').read_bytes()),target)
                self.assertEqual(json.loads((config/'vpn-guard.candidate.json').read_bytes()),
                                 firewall_policy.render_batch(target,995))
                for name in ('policy.json','client.ovpn','vpn-guard.candidate.json'):
                    self.assertEqual(stat.S_IMODE((config/name).stat().st_mode),0o600)
                self.assertFalse((config/'network-state.json').exists())
                manifest=json.loads(upgrade.MANIFEST.read_bytes())
                self.assertFalse(any(str(config) in name for name in manifest['files']))

    def test_saved_state_including_broken_symlink_blocks_every_write(self):
        for kind in ('file','symlink'):
            with self.subTest(kind=kind),self.network() as (config,*rest):
                state=config/'network-state.json'
                if kind=='file':
                    state.write_text('PRIVATE SAVED RECOVERY')
                else:
                    state.symlink_to(config/'missing')
                before={p.name:p.read_bytes() for p in config.iterdir() if p.name!='network-state.json'}
                with patch.object(upgrade,'publish') as public,self.assertRaises(upgrade.UpgradeError):
                    upgrade.upgrade(NEW,upgrade.digest(NEW),dhcp_server='192.0.2.200')
                public.assert_not_called()
                self.assertEqual({p.name:p.read_bytes() for p in config.iterdir() if p.name!='network-state.json'},before)

    def test_guard_tunnel_wrong_route_or_lease_mismatch_refuses_before_public_writes(self):
        cases=(('/usr/sbin/nft','-j','list','ruleset'),
               ('/usr/sbin/ip','-j','-d','link','show'),
               ('/usr/sbin/ip','-j','-4','route','get','192.0.2.10'),
               ('/usr/bin/nmcli','-g','DHCP4.OPTION','device','show','wlan0'))
        bad=({'nftables':[{'table':{'family':'inet','name':'vpn_guard'}}]},
             [{'ifname':'wlan0','flags':['UP']},{'ifname':'tun0','flags':['UP']}],
             [{'dev':'eth0'}], 'dhcp_server_identifier = 192.0.2.201\n')
        for command,value in zip(cases,bad):
            with self.subTest(command=command),self.network() as (config,policy,profile,responses,modules):
                responses[command]=value
                before=(config/'policy.json').read_bytes()
                with patch.object(upgrade,'publish') as public,self.assertRaises(upgrade.UpgradeError):
                    upgrade.upgrade(NEW,upgrade.digest(NEW),dhcp_server='192.0.2.200')
                public.assert_not_called()
                self.assertEqual((config/'policy.json').read_bytes(),before)

    def test_unknown_private_candidate_or_profile_is_not_blessed(self):
        for name in ('vpn-guard.candidate.json','client.ovpn'):
            with self.subTest(name=name),self.network() as (config,policy,profile,responses,modules):
                original=(config/name).read_bytes()
                (config/name).write_bytes(b'UNKNOWN PRIVATE CHANGE')
                with patch.object(upgrade,'publish') as public,self.assertRaises(upgrade.UpgradeError):
                    upgrade.upgrade(NEW,upgrade.digest(NEW),dhcp_server='192.0.2.200')
                public.assert_not_called()
                self.assertEqual((config/name).read_bytes(),b'UNKNOWN PRIVATE CHANGE')
                (config/name).write_bytes(original)

    def test_policy_last_commit_resumes_after_candidate_publication_interruption(self):
        with self.network() as (config,policy,profile,responses,modules):
            publish=upgrade.publish_private
            def interrupted(path,value):
                if path.name=='policy.json':
                    raise OSError('simulated interruption')
                publish(path,value)
            with patch.object(upgrade,'publish_private',side_effect=interrupted),self.assertRaises(OSError):
                upgrade.upgrade(NEW,upgrade.digest(NEW),dhcp_server='192.0.2.200')
            self.assertEqual(json.loads((config/'policy.json').read_bytes()),policy)
            target={**policy,'dhcp_server_ipv4':'192.0.2.200'}
            self.assertEqual(json.loads((config/'vpn-guard.candidate.json').read_bytes()),
                             firewall_policy.render_batch(target,995))
            upgrade.upgrade(NEW,upgrade.digest(NEW),dhcp_server='192.0.2.200')
            self.assertEqual(json.loads((config/'policy.json').read_bytes()),target)

    def test_lease_change_during_public_update_leaves_private_policy_unchanged(self):
        with self.network() as (config,policy,profile,responses,modules):
            leases=iter(('dhcp_server_identifier = 192.0.2.200\n','dhcp_server_identifier = 192.0.2.201\n'))
            responses[('/usr/bin/nmcli','-g','DHCP4.OPTION','device','show','wlan0')]=lambda:next(leases)
            before={name:(config/name).read_bytes() for name in ('policy.json','vpn-guard.candidate.json')}
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.upgrade(NEW,upgrade.digest(NEW),dhcp_server='192.0.2.200')
            self.assertEqual(upgrade.HELPER.read_bytes(),NEW)
            for name,value in before.items():
                self.assertEqual((config/name).read_bytes(),value)

    def test_dhcp_input_and_private_file_modes_remain_strict(self):
        for value in ('192.0.2.001','127.0.0.1','0.0.0.0','224.0.0.1','255.255.255.255','example.com'):
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.dhcp_address(value)
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'SUDO_UID':str(os.getuid())}):
            path=Path(folder)/'policy.json'
            path.write_text('PRIVATE')
            path.chmod(0o644)
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.read_file(path,source=True,private=True)
            path.chmod(0o600)
            self.assertEqual(upgrade.read_file(path,source=True,private=True),b'PRIVATE')
