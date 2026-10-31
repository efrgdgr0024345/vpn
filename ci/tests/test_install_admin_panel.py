import base64
import contextlib
import json
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ops'))
import install_admin_panel as panel
import server_foundation as server

LIVE_RULE = panel.live_rule
PUBLIC_PEM = '-----BEGIN CERTIFICATE-----\n'+base64.b64encode(b'public certificate fixture').decode()+'\n-----END CERTIFICATE-----\n'


class PanelInstallationTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(self.temp)
        for name, suffix in (('CODE', 'code'), ('CONFIG', 'config'), ('EXPORT', 'export'),
                             ('UNITS', 'units'), ('FIREWALL', 'nftables.conf'),
                             ('MANIFEST', 'config/install-manifest.json'), ('VPN_CONFIG', 'vpn-server.conf')):
            self.stack.enter_context(patch.object(panel, name, self.root/suffix))
        self.stack.enter_context(patch.object(server, 'CONFIG', self.root/'vpn'))
        self.stack.enter_context(patch.object(panel.os, 'geteuid', return_value=0))
        self.stack.enter_context(patch.object(panel.resource, 'setrlimit'))
        self.stack.enter_context(patch.object(panel.os, 'chown'))
        self.stack.enter_context(patch.object(panel.os, 'fstat', side_effect=self.root_fstat))
        self.stack.enter_context(patch.object(panel, 'owned', side_effect=self.read))
        self.stack.enter_context(patch.object(panel, 'public_parent'))
        self.stack.enter_context(patch.object(server, 'directory', side_effect=self.directory))
        self.stack.enter_context(patch.object(server, 'write', side_effect=self.write))
        self.uid, self.gid = os.getuid(), os.getgid()
        self.stack.enter_context(patch.object(panel, 'account', return_value=(self.uid, self.gid)))
        self.stack.enter_context(patch.object(panel, 'runtime_identity', return_value={'vpn': ('77', '100')}))
        self.stack.enter_context(patch.object(panel, 'listener_private', return_value=True))
        self.stack.enter_context(patch.object(panel, 'http_ready', return_value=True))
        self.firewall_installed = False
        self.stack.enter_context(patch.object(panel, 'live_rule', side_effect=lambda **kw: (self.firewall_installed, 30)))
        self.stack.enter_context(patch.object(panel,'legacy_rule_handle',return_value=None))
        self.commands = []
        self.stack.enter_context(patch.object(server, 'run', side_effect=self.fake_run))
        self.directory(server.CONFIG)
        self.write(panel.VPN_CONFIG, '# known public VPN configuration\n')
        self.write(server.CONFIG/'state.json', json.dumps({'endpoint': '192.0.2.1', 'ssh_port': 22}))
        self.write(panel.FIREWALL, panel.ipv4_firewall(server.firewall('eth0', 22)))
        self.sources = {name: '# public source fixture\n' if name.endswith('.py') else 'public static fixture\n'
                        for name in panel.SOURCE_FILES}
        self.revision = 'a'*40
        # Credential/TLS behavior gets separate real crypto tests below; the
        # transition test has deterministic public hashes and no real secrets.
        self.stack.enter_context(patch.object(panel, 'credentials'))
        self.stack.enter_context(patch.object(panel, 'certificates', return_value=(hashlib.sha256(b'public certificate fixture').hexdigest(), 'sha256//'+base64.b64encode(bytes(32)).decode(), PUBLIC_PEM)))

    def root_fstat(self, fd):
        values = list(self.original_fstat(fd))
        values[4] = 0
        return os.stat_result(values)

    original_fstat = staticmethod(os.fstat)

    def directory(self, path, mode=0o755):
        Path(path).mkdir(parents=True, exist_ok=True)
        Path(path).chmod(mode)

    def read(self, path, missing=False):
        try:
            return Path(path).read_text()
        except FileNotFoundError:
            if missing:
                return None
            raise

    def write(self, path, content, mode=0o600):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)

    def fake_run(self, argv, data=None, **kwargs):
        self.commands.append((argv, data))
        if argv[:5] == ['/usr/sbin/ip', '-j', '-4', 'route', 'show']:
            return '[{"dev":"eth0"}]'
        if argv[:3] == ['/usr/sbin/nft', '-f', '-']:
            self.assertNotIn('flush', data)
            self.assertIn('position 30', data)
            self.firewall_installed = True
        if argv[:2] == ['/usr/bin/systemctl', 'is-active']:
            return 'active\n'
        return ''

    def test_install_preserves_vpn_and_adds_only_the_private_panel_rule(self):
        result = panel.install(self.sources, self.revision)
        self.assertTrue(result['vpn_runtime_preserved'])
        self.assertFalse(result['credential_contents_returned'])
        self.assertTrue(result['firewall_rule_verified'])
        restart = [argv for argv, _ in self.commands if argv[:2] == ['/usr/bin/systemctl', 'restart']]
        self.assertEqual(restart, [['/usr/bin/systemctl', 'restart', *panel.PANEL_UNITS]])
        value = panel.FIREWALL.read_text()
        self.assertLess(value.index(panel.RULE), value.index(panel.HOST_DROP))
        self.assertIn('ip saddr @authorized', panel.RULE)
        self.assertTrue(all('flush' not in argv for argv, _ in self.commands))

    def test_unrelated_existing_listener_is_preserved_before_any_panel_write(self):
        with patch.object(panel, 'port_in_use', return_value=True), self.assertRaises(server.SetupError):
            panel.install(self.sources, self.revision)
        self.assertFalse(panel.CONFIG.exists())
        panel.account.assert_not_called()
        panel.credentials.assert_not_called()
        self.assertFalse(any(argv[0] == '/usr/bin/systemctl' for argv, _ in self.commands))

    def test_rerun_does_not_duplicate_live_rule_and_preserves_known_files(self):
        panel.install(self.sources, self.revision)
        self.commands.clear()
        panel.install(self.sources, self.revision)
        self.assertFalse(any(argv[:3] == ['/usr/sbin/nft', '-f', '-'] for argv, _ in self.commands))
        self.assertEqual(panel.FIREWALL.read_text().count(panel.RULE), 1)

    def test_legacy_https_rule_is_replaced_in_one_nft_transaction(self):
        panel.install(self.sources,self.revision)
        old_config=json.loads((panel.CONFIG/'config.json').read_text())
        old_config.update(port=8443,origin='https://172.27.240.1:8443',certificate=str(panel.CONFIG/'server.crt'),private_key=str(panel.CONFIG/'server.key'))
        self.write(panel.CONFIG/'config.json',json.dumps(old_config))
        record=json.loads(panel.MANIFEST.read_text())
        record['files'][str(panel.CONFIG/'config.json')]=hashlib.sha256((panel.CONFIG/'config.json').read_bytes()).hexdigest()
        self.write(panel.MANIFEST,json.dumps(record))
        self.write(panel.FIREWALL,panel.FIREWALL.read_text().replace(panel.RULE,panel.LEGACY_RULE))
        panel.legacy_rule_handle.return_value=77
        self.commands.clear()
        report=panel.install(self.sources,'b'*40)
        batches=[data for argv,data in self.commands if argv[:3]==['/usr/sbin/nft','-f','-']]
        self.assertEqual(len(batches),1)
        self.assertIn('tcp dport 8080',batches[0]);self.assertIn('delete rule inet vpn_lab input handle 77',batches[0])
        self.assertTrue(report['legacy_https_closed'])
        self.assertNotIn(panel.LEGACY_RULE,panel.FIREWALL.read_text())
        panel.certificates.assert_not_called()

    def test_known_migrated_legacy_ipv6_exceptions_are_preserved(self):
        original = panel.FIREWALL.read_text()
        marker = '  iifname "eth0" ip protocol icmp accept\n'
        legacy = original.replace(marker,
            '  iifname "eth0" udp sport 547 udp dport 546 accept\n'+marker+
            '  iifname "eth0" meta l4proto ipv6-icmp accept\n')
        self.write(panel.FIREWALL, legacy)
        panel.install(self.sources, self.revision)
        self.assertEqual(panel.FIREWALL.read_text().replace(panel.RULE, ''), legacy)

    def test_unknown_persistent_firewall_stops_before_credentials_or_account_changes(self):
        self.write(panel.FIREWALL, 'operator firewall\n')
        with self.assertRaises(server.SetupError):
            panel.install(self.sources, self.revision)
        panel.account.assert_not_called()
        panel.credentials.assert_not_called()
        self.assertEqual(panel.FIREWALL.read_text(), 'operator firewall\n')

    def test_changed_installed_source_is_preserved_and_refused(self):
        panel.install(self.sources, self.revision)
        path = panel.CODE/'server.py'
        self.write(path, '# changed locally\n')
        self.commands.clear()
        with self.assertRaises(server.SetupError):
            panel.install(self.sources, self.revision)
        self.assertEqual(path.read_text(), '# changed locally\n')
        self.assertFalse(any(argv[0] == '/usr/bin/systemctl' for argv, _ in self.commands))

    def test_known_status_only_manifest_upgrades_but_unrelated_new_file_is_preserved(self):
        panel.install(self.sources,self.revision)
        record=json.loads(panel.MANIFEST.read_text())
        added=(panel.CODE/'history.py',panel.CODE/'observer.py',panel.UNITS/'vpn-lab-admin-observer.service')
        for path in added:
            record['files'].pop(str(path));path.unlink()
        self.write(panel.MANIFEST,json.dumps(record))
        self.write(panel.CODE/'observer.py','# unrelated code\n')
        with self.assertRaises(server.SetupError): panel.install(self.sources,'b'*40)
        self.assertEqual((panel.CODE/'observer.py').read_text(),'# unrelated code\n')
        (panel.CODE/'observer.py').unlink()
        panel.install(self.sources,'b'*40)
        self.assertTrue(all(path.is_file() for path in added))

    def test_known_partial_source_update_resumes_without_replacing_unknown_files(self):
        panel.install(self.sources, self.revision)
        changed = {**self.sources, 'server.py': '# next approved public source\n'}
        self.write(panel.CODE/'server.py', changed['server.py'])
        panel.install(changed, 'c'*40)
        self.assertEqual((panel.CODE/'server.py').read_text(), changed['server.py'])

    def test_unknown_code_symlink_directory_is_refused(self):
        panel.install(self.sources, self.revision)
        (panel.CODE/'shadow').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(server.SetupError):
            panel.install(self.sources, self.revision)

    def test_report_refuses_unknown_secret_fields_and_false_types(self):
        report = panel.install(self.sources, self.revision)
        for changed in ({**report, 'password': 'PRIVATE'}, {**report, 'version': True},
                        {**report, 'web_service_active': 1}, {**report, 'credential_contents_returned': True},
                        {**report, 'leaf_spki_pin': 'PRIVATE'},
                        {**report, 'ca_certificate_pem': '-----BEGIN PRIVATE KEY-----\nPRIVATE\n-----END PRIVATE KEY-----\n'}):
            with self.assertRaises(ValueError):
                panel.validate_report(changed)

    def test_observer_is_separate_from_web_and_cannot_open_ip_sockets(self):
        units=panel.service_units()
        observer=units['vpn-lab-admin-observer.service']
        self.assertIn('CapabilityBoundingSet=CAP_NET_RAW\n',observer)
        self.assertIn('RestrictAddressFamilies=AF_PACKET AF_UNIX\n',observer)
        self.assertIn('ReadWritePaths=/var/lib/vpn-lab-admin\n',observer)
        self.assertIn('ProtectSystem=strict\n',observer)
        self.assertNotIn('CAP_NET_RAW',units['vpn-lab-admin.service'])

    def test_sandbox_restricts_web_and_preserves_collector_runtime_ownership(self):
        units = panel.service_units()
        web, collector = units['vpn-lab-admin.service'], units['vpn-lab-admin-collector.service']
        self.assertIn('User=vpn-lab-admin\n', web)
        self.assertIn('CapabilityBoundingSet=\n', web)
        self.assertNotIn('RuntimeDirectory=', web)
        self.assertIn('SocketBindAllow=ipv4:tcp:8080', web)
        self.assertIn('Group=vpn-lab-admin\n', collector)
        self.assertIn('ReadWritePaths=/run/vpn-lab-admin', collector)
        self.assertNotIn('PrivateNetwork=yes', collector)
        self.assertIn('-/etc/openvpn/lab/pki', collector)
        self.assertIn('-/etc/vpn-lab-admin\n', collector)
        self.assertIn('-/etc/vpn-lab-admin/ca-private', web)

    def test_live_rule_cannot_skip_lease_membership_or_follow_host_drop(self):
        first = {'comment': 'vpn-lab-block-ipv6-input', 'expr': [
            {'match': {'op': '==', 'left': {'meta': {'key': 'nfproto'}}, 'right': 'ipv6'}},
            {'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}
        drop = {'comment': 'vpn-lab-block-host', 'handle': 30, 'expr': [
            {'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'tun-lab'}},
            {'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}
        admin = {'comment': panel.COMMENT, 'expr': panel.admin_expression(), 'handle': 31}
        chain = {'chain': {'family': 'inet', 'table': 'vpn_lab', 'name': 'input', 'hook': 'input', 'type': 'filter', 'policy': 'drop'}}
        for ordered, valid in (([first, admin, drop], True), ([first, drop, admin], False)):
            document = json.dumps({'nftables': [chain]+[{'rule': rule} for rule in ordered]})
            with patch.object(server, 'run', return_value=document):
                if valid:
                    self.assertEqual(LIVE_RULE(), (True, 30))
                else:
                    with self.assertRaises(server.SetupError):
                        LIVE_RULE()
        admin['expr'][1]['match']['right'] = '172.27.240.10'
        document = json.dumps({'nftables': [chain]+[{'rule': rule} for rule in (first, admin, drop)]})
        with patch.object(server, 'run', return_value=document), self.assertRaises(server.SetupError):
            LIVE_RULE()



class PanelCryptoTests(unittest.TestCase):
    def test_tls_probe_rejects_a_different_leaf_even_with_a_trusted_context(self):
        channel = unittest.mock.MagicMock()
        channel.__enter__.return_value = channel
        channel.getpeercert.return_value = b'different public leaf'
        context = unittest.mock.MagicMock()
        context.wrap_socket.return_value = channel
        with patch.object(panel.ssl, 'create_default_context', return_value=context), \
             patch.object(panel.socket, 'create_connection'), patch.object(panel, 'owned', return_value=PUBLIC_PEM):
            self.assertFalse(panel.tls_matches_certificate())
        channel.getpeercert.return_value = b'public certificate fixture'
        with patch.object(panel.ssl, 'create_default_context', return_value=context), \
             patch.object(panel.socket, 'create_connection'), patch.object(panel, 'owned', return_value=PUBLIC_PEM):
            self.assertTrue(panel.tls_matches_certificate())

    def test_scrypt_verifier_matches_only_the_right_password(self):
        salt = bytes(range(16))
        first = panel.password_verifier('a'*43, salt)
        self.assertEqual(len(first), 32)
        self.assertEqual(first, panel.password_verifier('a'*43, salt))
        self.assertNotEqual(first, panel.password_verifier('b'*43, salt))

    def test_real_panel_certificate_generation_and_rerun_preserve_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, export = root/'config', root/'export'
            config.mkdir(mode=0o750)
            export.mkdir(mode=0o700)
            def owned(path, missing=False):
                try:
                    return Path(path).read_text()
                except FileNotFoundError:
                    if missing:
                        return None
                    raise
            def mkdir(path, mode=0o755, gid=None):
                Path(path).mkdir(parents=True, exist_ok=True)
                Path(path).chmod(mode)
            def write(path, content, mode=0o600):
                Path(path).write_text(content)
                Path(path).chmod(mode)
            with patch.object(panel, 'CONFIG', config), patch.object(panel, 'EXPORT', export), \
                 patch.object(panel, 'owned', side_effect=owned), patch.object(panel, 'directory', side_effect=mkdir), \
                 patch.object(panel.os, 'chown'), patch.object(server, 'write', side_effect=write):
                first = panel.certificates(os.getgid())
                key = (config/'server.key').read_bytes()
                ca = (config/'ca-private'/'ca.key').read_bytes()
                self.assertEqual(panel.certificates(os.getgid()), first)
                self.assertEqual((config/'server.key').read_bytes(), key)
                self.assertEqual((config/'ca-private'/'ca.key').read_bytes(), ca)
                self.assertEqual((config/'ca.crt').read_bytes(), (export/'ca.crt').read_bytes())
                self.assertEqual(len(first[0]), 64)
                self.assertTrue(first[1].startswith('sha256//'))
                # Reject an accidentally concatenated private key before any
                # public CA publication or leaf group permission expansion.
                originals = {path: path.read_text() for path in (config/'ca-private'/'ca.crt', config/'server.crt')}
                for public in (config/'ca.crt', export/'ca.crt'):
                    public.unlink()
                (config/'server.key').chmod(0o600)
                for target in originals:
                    target.write_text(originals[target]+(config/'ca-private'/'ca.key').read_text())
                    with self.assertRaises(server.SetupError):
                        panel.certificates(os.getgid())
                    self.assertFalse((config/'ca.crt').exists())
                    self.assertFalse((export/'ca.crt').exists())
                    self.assertEqual((config/'server.key').stat().st_mode & 0o777, 0o600)
                    target.write_text(originals[target])
                # A manually replaced CA-capable leaf must never be shared with
                # the web UID, even when its key, issuer and IP still match.
                request, extensions = root/'bad.csr', root/'bad.extensions'
                extensions.write_text('basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:172.27.240.1\n')
                server.run(['/usr/bin/openssl', 'req', '-new', '-key', str(config/'server.key'),
                            '-subj', '/CN=VPN Lab Admin', '-out', str(request)])
                server.run(['/usr/bin/openssl', 'x509', '-req', '-in', str(request),
                            '-CA', str(config/'ca-private'/'ca.crt'),
                            '-CAkey', str(config/'ca-private'/'ca.key'), '-set_serial', '12345',
                            '-extfile', str(extensions), '-out', str(config/'server.crt')])
                with self.assertRaises(server.SetupError):
                    panel.certificates(os.getgid())

    def test_private_credentials_are_stable_and_broad_permissions_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, export = root/'config', root/'export'
            config.mkdir()
            export.mkdir()
            def owned(path, missing=False):
                try:
                    return Path(path).read_text()
                except FileNotFoundError:
                    if missing:
                        return None
                    raise
            def write(path, content, mode=0o600):
                Path(path).write_text(content)
                Path(path).chmod(mode)
            with patch.object(panel, 'CONFIG', config), patch.object(panel, 'EXPORT', export), \
                 patch.object(panel, 'owned', side_effect=owned), patch.object(panel.os, 'chown'), \
                 patch.object(server, 'write', side_effect=write):
                panel.credentials(os.getgid())
                original = [(export/'login.txt').read_bytes(), (config/'auth.json').read_bytes()]
                panel.credentials(os.getgid())
                self.assertEqual(original, [(export/'login.txt').read_bytes(), (config/'auth.json').read_bytes()])
                (export/'login.txt').chmod(0o644)
                with self.assertRaises(server.SetupError):
                    panel.credentials(os.getgid())
                (export/'login.txt').chmod(0o600)
                (config/'auth.json').chmod(0o644)
                with self.assertRaises(server.SetupError):
                    panel.credentials(os.getgid())

    def test_public_code_directory_remains_readable_under_private_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/'code'
            previous = os.umask(0o077)
            try:
                with patch.object(server, 'directory', side_effect=lambda p, mode: Path(p).mkdir(mode=mode)):
                    panel.directory(destination)
            finally:
                os.umask(previous)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)

    def test_unrelated_private_parent_is_not_broadened(self):
        safe = types.SimpleNamespace(st_mode=0o040755, st_uid=0)
        private = types.SimpleNamespace(st_mode=0o040700, st_uid=0)
        parent = types.SimpleNamespace(parents=(), lstat=lambda: safe)
        with patch.object(panel, 'CODE', types.SimpleNamespace(parent=parent)):
            panel.public_parent()
        parent.lstat = lambda: private
        with patch.object(panel, 'CODE', types.SimpleNamespace(parent=parent)), self.assertRaises(server.SetupError):
            panel.public_parent()

    def test_account_rejects_extra_members_and_alias_group(self):
        account = types.SimpleNamespace(pw_uid=400, pw_gid=400, pw_dir='/nonexistent', pw_shell='/usr/sbin/nologin', pw_name=panel.USER)
        group = types.SimpleNamespace(gr_gid=400, gr_name=panel.USER, gr_mem=['unrelated'])
        with patch.object(panel.pwd, 'getpwnam', return_value=account), patch.object(panel.grp, 'getgrnam', return_value=group), \
             patch.object(panel.os, 'getgrouplist', return_value=[400]), patch.object(panel.pwd, 'getpwall', return_value=[account]), \
             patch.object(panel.grp, 'getgrall', return_value=[group]), self.assertRaises(server.SetupError):
            panel.account()
