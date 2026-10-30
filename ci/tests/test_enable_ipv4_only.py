import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ops'))
import enable_ipv4_only as migration
import server_foundation as server


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(self.temporary)
        self.config = self.root/'etc/openvpn/lab'
        self.export = self.root/'root/vpn-lab'
        self.config.mkdir(parents=True)
        self.export.mkdir(parents=True)
        self.stack.enter_context(patch.object(server, 'CONFIG', self.config))
        self.stack.enter_context(patch.object(server, 'EXPORT', self.export))
        self.stack.enter_context(patch.object(migration.os, 'geteuid', return_value=0))
        self.stack.enter_context(patch.object(migration, 'ROOT_UID', os.getuid()))
        self.stack.enter_context(patch.dict(migration.os.environ, {'SSH_CONNECTION': '192.0.2.2 1234 192.0.2.3 22'}))
        self.stack.enter_context(patch.object(migration.resource, 'setrlimit'))
        self.stack.enter_context(patch.object(migration, 'protected_file', side_effect=self.read))
        self.stack.enter_context(patch.object(server, 'directory', side_effect=lambda p, mode=0o755: Path(p).mkdir(parents=True, exist_ok=True)))
        self.writes = []
        self.stack.enter_context(patch.object(server, 'write', side_effect=self.write))
        self.commands = []
        self.missing_rules = ['input', 'forward', 'output']
        self.busy = False
        self.stack.enter_context(patch.object(migration, 'firewall_state', side_effect=lambda: (self.missing_rules.copy(), self.busy)))
        self.stack.enter_context(patch.object(migration, 'boot_configured', side_effect=lambda: migration.GRUB_CONFIG.exists()))
        self.stack.enter_context(patch.object(migration.os, 'access', return_value=True))
        self.stack.enter_context(patch.object(migration, 'report', side_effect=self.report))
        for name in ('SERVER_CONFIG', 'FIREWALL_CONFIG', 'SYSCTL_CONFIG', 'FOUNDATION_SYSCTL', 'GRUB_CONFIG', 'GRUB_OUTPUT', 'SELFTEST'):
            path = self.root/str(getattr(migration, name)).lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            self.stack.enter_context(patch.object(migration, name, path))
        self.legacy = 'proto udp4\nplugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so vpn-lab\nserver-ipv6 fd47:27:240::/64\npush "redirect-gateway def1 ipv6"\npush "block-ipv6"\n'
        self.stack.enter_context(patch.object(server, 'server_configuration', return_value=self.legacy))
        self.stack.enter_context(patch.object(server, 'run', side_effect=self.fake_run))
        self.write(self.config/'state.json', json.dumps({'endpoint': '192.0.2.3', 'ssh_port': 22}))
        self.write(migration.SERVER_CONFIG, self.legacy)
        self.write(migration.FIREWALL_CONFIG, server.firewall('eth0', 22))
        self.write(migration.SELFTEST, '# old selftest\n')
        self.write(migration.FOUNDATION_SYSCTL, migration.FOUNDATION_SYSCTL_CONTENT)
        self.write(migration.GRUB_OUTPUT, 'linux /boot/vmlinuz root=/dev/vda1\n')
        self.stack.enter_context(patch.dict(migration.__dict__, {
            'SELFTEST_SOURCE': '# reviewed selftest\n',
            'SELFTEST_PREVIOUS_SHA256': hashlib.sha256(b'# old selftest\n').hexdigest()}))
        self.writes.clear()

    def read(self, path, missing=False):
        path = Path(path)
        if str(path) in ('/etc/default/grub', '/usr/sbin/update-grub'):
            return '# protected boot configuration\n'
        try:
            return path.read_text()
        except FileNotFoundError:
            if missing:
                return None
            raise

    def write(self, path, content, mode=0o600):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
        self.writes.append(path)

    def fake_run(self, command, data=None, timeout=120):
        self.commands.append((command, data))
        if command[:5] == ['/usr/sbin/ip', '-j', '-4', 'route', 'show']:
            return '[{"dst":"default","dev":"eth0"}]'
        if command == ['/usr/sbin/nft', '-f', '-']:
            self.assertNotIn('flush', data)
            self.missing_rules.clear()
        return ''

    def report(self, operation):
        result = {name: True for name in migration.BOOL_FIELDS}
        result.update(version=1, operation=operation, kernel_ipv6_disabled=False,
                      boot_argument_active=False, reboot_required=True,
                      credential_contents_returned=False)
        return result

    def test_conversion_preserves_ipv4_and_authentication_and_never_touches_credentials(self):
        result = migration.administer('enable-ipv4-only')
        value = migration.SERVER_CONFIG.read_text()
        self.assertIn('proto udp4', value)
        self.assertIn('plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so vpn-lab', value)
        self.assertIn('push "redirect-gateway def1"', value)
        self.assertNotIn('server-ipv6', value)
        self.assertNotIn('block-ipv6', value)
        self.assertTrue(result['reboot_required'])
        self.assertFalse(result['kernel_ipv6_disabled'])
        self.assertFalse(result['credential_contents_returned'])
        self.assertEqual(migration.SELFTEST.read_text(), '# reviewed selftest\n')
        self.assertFalse(any('pki' in str(path) or 'login' in str(path) or 'shadow' in str(path) for path in self.writes))
        calls = [item[0] for item in self.commands]
        self.assertLess(calls.index(['/usr/bin/systemctl', 'stop', migration.UNITS[0], migration.UNITS[1]]),
                        calls.index(['/usr/sbin/sysctl', '-p', str(migration.SYSCTL_CONFIG)]))
        self.assertFalse(any(command[:2] == ['/usr/sbin/nft', 'flush'] for command in calls))

    def test_retry_preserves_original_recovery_copies_and_does_not_duplicate_rules(self):
        migration.administer('enable-ipv4-only')
        original_backup = (self.export/'recovery/vpn-lab.before-ipv4-only.conf').read_text()
        self.commands.clear()
        migration.administer('enable-ipv4-only')
        self.assertEqual(original_backup, self.legacy)
        self.assertEqual((self.export/'recovery/vpn-lab.before-ipv4-only.conf').read_text(), self.legacy)
        self.assertFalse(any(command == ['/usr/sbin/nft', '-f', '-'] for command, _ in self.commands))

    def test_active_session_or_unknown_files_stop_before_writes_and_preserve_configuration(self):
        for failure in ('busy', 'vpn', 'sysctl', 'selftest'):
            with self.subTest(failure=failure):
                self.busy = failure == 'busy'
                path = {'vpn': migration.SERVER_CONFIG, 'sysctl': migration.SYSCTL_CONFIG,
                        'selftest': migration.SELFTEST}.get(failure)
                prior = path.read_bytes() if path and path.exists() else None
                if path:
                    self.write(path, 'unknown contents\n')
                self.writes.clear()
                with self.assertRaises(server.SetupError):
                    migration.administer('enable-ipv4-only')
                self.assertEqual(self.writes, [])
                if path:
                    self.assertEqual(path.read_text(), 'unknown contents\n')
                    if prior is None:
                        path.unlink()
                    else:
                        path.write_bytes(prior)

    def test_boot_failure_does_not_stop_vpn_or_apply_firewall(self):
        with patch.object(migration, 'boot_configured', return_value=False), self.assertRaises(server.SetupError):
            migration.administer('enable-ipv4-only')
        self.assertFalse(any(command[0] == '/usr/bin/systemctl' for command, _ in self.commands))
        self.assertFalse(any(command[0] == '/usr/sbin/nft' for command, _ in self.commands))
        self.assertEqual(migration.SERVER_CONFIG.read_text(), self.legacy)

    def test_failure_after_stop_does_not_restart_partially_applied_session(self):
        original_run = self.fake_run
        def failed(command, **kwargs):
            if command[0] == '/usr/sbin/sysctl':
                raise server.SetupError('fixture failure')
            return original_run(command, **kwargs)
        with patch.object(server, 'run', side_effect=failed), self.assertRaises(server.SetupError):
            migration.administer('enable-ipv4-only')
        self.assertIn((['/usr/bin/systemctl', 'stop', migration.UNITS[0], migration.UNITS[1]], None), self.commands)
        self.assertFalse(any(command[:2] == ['/usr/bin/systemctl', 'start'] for command, _ in self.commands))

    def test_ipv6_ssh_channel_and_unsupported_operations_are_refused(self):
        with patch.dict(migration.os.environ, {'SSH_CONNECTION': '2001:db8::1 1 2001:db8::2 22'}), self.assertRaises(server.SetupError):
            migration.administer('enable-ipv4-only')
        with self.assertRaises(server.SetupError):
            migration.administer('arbitrary-command')
        self.assertEqual(self.writes, [])


class ReportAndFirewallTests(unittest.TestCase):
    def valid(self):
        value = {key: True for key in migration.BOOL_FIELDS}
        value.update(version=1, operation='ipv4-only-status', credential_contents_returned=False,
                     reboot_required=False)
        return value

    def test_report_is_strict_and_distinguishes_interface_disablement_from_kernel_disablement(self):
        result = self.valid()
        self.assertEqual(migration.validate_report(result), result)
        result.update(kernel_ipv6_disabled=False, boot_argument_active=False, reboot_required=True)
        self.assertTrue(migration.validate_report(result)['interface_ipv6_disabled'])
        self.assertFalse(result['kernel_ipv6_disabled'])
        for key, value in (('version', True), ('kernel_ipv6_disabled', 1), ('credential_contents_returned', True),
                           ('operation', 'shell'), ('reboot_required', False), ('unexpected', 'raw data')):
            changed = dict(result, **{key: value})
            with self.assertRaises(ValueError):
                migration.validate_report(changed)

    def test_firewall_requires_an_exact_first_drop_rule_and_preserves_unrelated_objects(self):
        objects = [{'table': {'family': 'inet', 'name': 'vpn_lab'}},
                   {'set': {'name': 'authorized', 'type': 'ipv4_addr'}}]
        for name in ('input', 'forward', 'output'):
            objects.append({'chain': {'name': name, 'hook': name}})
            objects.append({'rule': {'chain': name, 'comment': 'vpn-lab-block-ipv6-'+name,
                'expr': [{'match': {'op': '==', 'left': {'meta': {'key': 'nfproto'}}, 'right': 'ipv6'}},
                         {'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}})
        with patch.object(server, 'run', return_value=json.dumps({'nftables': objects})):
            self.assertEqual(migration.firewall_state(), ([], False))
        objects.insert(3, {'rule': {'chain': 'input', 'expr': [{'accept': None}]}})
        with patch.object(server, 'run', return_value=json.dumps({'nftables': objects})), self.assertRaises(server.SetupError):
            migration.firewall_state()

    def test_kernel_disabled_report_checks_socket_instead_of_suppressing_ip_errors(self):
        def read_text(path):
            if str(path) == '/proc/cmdline':
                return 'root=/dev/vda1 ipv6.disable=1'
            raise AssertionError('Unexpected kernel read')
        commands = []
        def run(argv):
            commands.append(argv)
            if argv[:2] == ['/usr/bin/systemctl', 'show']:
                return 'active\n'
            raise AssertionError('IPv6 tools must not run after kernel disablement')
        with patch.object(migration, 'expected_configurations', return_value=('proto udp4\n', 'proto udp4\n', '', '')), \
                patch.object(migration, 'firewall_state', return_value=([], False)), \
                patch.object(migration, 'kernel_disabled', return_value=True), \
                patch.object(migration, 'boot_configured', return_value=True), \
                patch.object(Path, 'read_text', read_text), \
                patch.object(server, 'run', side_effect=run), \
                patch.object(migration.socket, 'socket', side_effect=OSError(errno.EAFNOSUPPORT, 'disabled')):
            report = migration.report('ipv4-only-status')
        self.assertTrue(report['kernel_ipv6_disabled'])
        self.assertTrue(report['ipv6_addresses_absent'])
        self.assertTrue(report['ipv6_routes_absent'])
        self.assertFalse(report['reboot_required'])
        with patch.object(migration, 'expected_configurations', return_value=('proto udp4\n', 'proto udp4\n', '', '')), \
                patch.object(migration, 'firewall_state', return_value=([], False)), \
                patch.object(migration, 'kernel_disabled', return_value=True), \
                patch.object(Path, 'read_text', read_text), \
                patch.object(migration.socket, 'socket', side_effect=OSError(errno.EMFILE, 'descriptor exhaustion')), \
                self.assertRaises(OSError):
            migration.report('ipv4-only-status')

    def test_grub_status_requires_generated_kernel_entries_and_rejects_later_override(self):
        for entry, expected in (('linux /vmlinuz root=/dev/vda1 ipv6.disable=1', True),
                                ('linux /vmlinuz root=/dev/vda1', False),
                                ('linux /vmlinuz ipv6.disable=1 ipv6.disable=0', False),
                                ('# no kernel entries', False)):
            def read(path, missing=False):
                return migration.GRUB_CONTENT if path == migration.GRUB_CONFIG else entry
            with patch.object(migration, 'protected_file', side_effect=read):
                self.assertIs(migration.boot_configured(), expected)

    def test_unsafe_ancestor_is_refused_without_reading_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'file'
            target.write_text('keep')
            # /tmp is deliberately writable, so cannot be a privileged input ancestor.
            with self.assertRaises(server.SetupError):
                migration.protected_file(target)
            self.assertEqual(target.read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
