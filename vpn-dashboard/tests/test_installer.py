"""Guided-installer tests. System changes are mocked; writes stay in temp dirs."""
from contextlib import ExitStack, contextmanager
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch

import install as wizard
import security
import firewall_policy
from test_security import PROFILE, POLICY


class FileTests(unittest.TestCase):
    def context(self):
        stack = ExitStack()
        real_fstat = os.fstat
        def root_metadata(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink)
        stack.enter_context(patch.object(wizard, 'check_directory'))
        stack.enter_context(patch.object(wizard.os, 'fstat', side_effect=root_metadata))
        return stack

    def test_private_atomic_install_and_same_version_rerun(self):
        with tempfile.TemporaryDirectory() as directory, self.context():
            destination = Path(directory)
            contents = {'client.ovpn': b'private fixture', 'policy.json': b'{}'}
            wizard.install_files(destination, contents, mode=0o600, private=True)
            wizard.install_files(destination, contents, mode=0o600, private=True)
            self.assertEqual(set(p.name for p in destination.iterdir()), set(contents))
            for name, value in contents.items():
                self.assertEqual((destination / name).read_bytes(), value)
                self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), 0o600)
                self.assertEqual((destination / name).stat().st_nlink, 1)

    def test_conflict_is_detected_before_other_files_are_written(self):
        with tempfile.TemporaryDirectory() as directory, self.context():
            destination = Path(directory)
            existing = destination / 'existing.py'
            existing.write_bytes(b'keep this')
            with self.assertRaises(wizard.InstallationError):
                wizard.install_files(destination, {'first.py': b'new', 'existing.py': b'replacement'})
            self.assertEqual(existing.read_bytes(), b'keep this')
            self.assertFalse((destination / 'first.py').exists())

    def test_existing_destination_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory, self.context():
            target = Path(directory) / 'target'
            target.write_bytes(b'keep')
            link = Path(directory) / 'client.ovpn'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                wizard.install_files(Path(directory), {'client.ovpn': b'new'}, mode=0o600, private=True)
            self.assertEqual(target.read_bytes(), b'keep')

    def test_publish_never_overwrites_a_racing_destination(self):
        with tempfile.TemporaryDirectory() as directory, self.context():
            path = Path(directory) / 'existing'
            path.write_bytes(b'original')
            with self.assertRaises(FileExistsError):
                wizard.publish_file(path, b'new', 0o600)
            self.assertEqual(path.read_bytes(), b'original')
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_interrupted_write_cleans_up_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory, self.context(), \
                patch.object(wizard.os, 'fsync', side_effect=OSError('fixture')):
            with self.assertRaises(OSError):
                wizard.publish_file(Path(directory) / 'client.ovpn', b'private', 0o600)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_profile_import_refuses_symlinks_and_writable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile'
            path.write_text(PROFILE)
            path.chmod(0o600)
            self.assertEqual(wizard.read_profile_source(path, os.getuid()), PROFILE)
            path.chmod(0o666)
            with self.assertRaises(wizard.InstallationError):
                wizard.read_profile_source(path, os.getuid())
            path.chmod(0o600)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                wizard.read_profile_source(link, os.getuid())


class WizardTests(unittest.TestCase):
    def test_check_only_never_elevates_or_installs(self):
        with patch.object(wizard, 'required_packages', return_value=['nftables']), \
                patch.object(wizard.subprocess, 'run') as run, patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(wizard.main(['--check']), 2)
            run.assert_not_called()

    def test_elevation_uses_fixed_system_interpreter_and_literal_argv(self):
        with patch.object(wizard.os, 'geteuid', return_value=1000), \
                patch.object(wizard.sys.stdin, 'isatty', return_value=True), \
                patch.object(wizard.subprocess, 'run', return_value=SimpleNamespace(returncode=7)) as run, \
                patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(wizard.main([]), 7)
            self.assertEqual(run.call_args.args[0], ['/usr/bin/sudo', '--', '/usr/bin/python3',
                                                  '-I', '-B', str(wizard.SOURCE / 'install.py'), '--root'])
            self.assertNotIn('shell', run.call_args.kwargs)

    def test_noninteractive_install_is_refused(self):
        with patch.object(wizard.os, 'geteuid', return_value=1000), \
                patch.object(wizard.sys.stdin, 'isatty', return_value=False), self.assertRaises(wizard.InstallationError):
            wizard.main([])

    def test_dependency_install_requires_explicit_yes(self):
        with patch.object(wizard, 'required_packages', return_value=['nftables']), \
                patch.object(wizard.os, 'access', return_value=True), patch.object(wizard, 'confirm', return_value=False), \
                patch.object(wizard.subprocess, 'run') as run, patch('sys.stdout', new_callable=io.StringIO):
            with self.assertRaises(wizard.InstallationError):
                wizard.ensure_dependencies()
            run.assert_not_called()

    def test_explicit_dependency_install_keeps_apt_verification(self):
        with patch.object(wizard, 'required_packages', side_effect=[['nftables'], []]), \
                patch.object(wizard.os, 'access', return_value=True), patch.object(wizard, 'confirm', return_value=True), \
                patch.object(wizard.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='OpenVPN 2.6.0')) as run, \
                patch('sys.stdout', new_callable=io.StringIO):
            wizard.ensure_dependencies()
            self.assertEqual([call.args[0] for call in run.call_args_list[:2]], [
                ['/usr/bin/apt-get', 'update'],
                ['/usr/bin/apt-get', 'install', '--yes', '--no-install-recommends', 'nftables']])

    def test_old_or_unknown_openvpn_version_is_refused(self):
        for output in ('OpenVPN 2.4.12', 'unexpected output'):
            with patch.object(wizard, 'required_packages', return_value=[]), \
                    patch.object(wizard.os, 'access', return_value=True), \
                    patch.object(wizard.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=output)), \
                    self.assertRaises(wizard.InstallationError):
                wizard.ensure_dependencies()

    def test_profile_suggestions_never_include_inline_private_material(self):
        defaults = wizard.profile_defaults(PROFILE)
        self.assertEqual(defaults['vpn_server_ipv4'], '192.0.2.10')
        self.assertEqual(defaults['server_name'], 'vpn.example.invalid')
        self.assertNotIn('TEST KEY', json.dumps(defaults))

    def test_existing_configuration_reused_without_prompt_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'policy.json').write_text(json.dumps(POLICY))
            (root / 'client.ovpn').write_text(PROFILE)
            with patch.object(wizard, 'CONFIG_DIR', root), \
                    patch.object(wizard, 'existing_bytes', side_effect=lambda p, private: p.read_bytes()), \
                    patch.object(wizard, 'ask') as ask, patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(wizard.collect_configuration(security, os.getuid()), (POLICY, PROFILE))
                ask.assert_not_called()

    def test_full_deployment_plan_contains_no_firewall_execution(self):
        contents = {name: ('fixture: ' + name).encode() for name in set(wizard.HELPERS + wizard.APPLICATION)}
        @contextmanager
        def lock():
            yield
        with tempfile.TemporaryDirectory() as directory, patch.object(wizard, 'CONFIG_DIR', Path(directory)), \
                patch.object(wizard, 'verify_destinations'), \
                patch.object(wizard, 'installation_lock', lock), \
                patch.object(wizard, 'ensure_account', return_value=SimpleNamespace(pw_uid=995)), \
                patch.object(wizard, 'install_files') as install, \
                patch.object(wizard.subprocess, 'run') as run:
            wizard.install(security, firewall_policy, contents, POLICY, PROFILE)
        self.assertEqual(install.call_count, 5)
        config_call = next(call for call in install.call_args_list if call.args[0] == Path(directory))
        self.assertEqual(config_call.kwargs, {'mode': 0o600, 'private': True})
        self.assertEqual(config_call.args[1]['client.ovpn'], PROFILE.encode())
        self.assertIn('vpn-guard.candidate.json', config_call.args[1])
        helper_call = next(call for call in install.call_args_list if call.args[0] == wizard.HELPER_DIR)
        self.assertEqual(list(helper_call.args[1])[-1], 'privileged.py')
        run.assert_not_called()

    def test_complete_local_install_can_resume_without_overwrite_or_system_commands(self):
        from contextlib import nullcontext
        contents = {name: ('fixture: ' + name).encode() for name in set(wizard.HELPERS + wizard.APPLICATION)}
        with tempfile.TemporaryDirectory() as directory, FileTests().context(), ExitStack() as stack:
            base = Path(directory)
            for name in ('HELPER_DIR', 'APP_DIR', 'CONFIG_DIR', 'BIN_DIR', 'MENU_DIR'):
                destination = base / name.lower()
                destination.mkdir(mode=0o700)
                stack.enter_context(patch.object(wizard, name, destination))
            stack.enter_context(patch.object(wizard, 'installation_lock', nullcontext))
            stack.enter_context(patch.object(wizard, 'ensure_account', return_value=SimpleNamespace(pw_uid=995)))
            run = stack.enter_context(patch.object(wizard.subprocess, 'run'))
            wizard.install(security, firewall_policy, contents, POLICY, PROFILE)
            wizard.install(security, firewall_policy, contents, POLICY, PROFILE)
            self.assertEqual((wizard.CONFIG_DIR / 'client.ovpn').read_text(), PROFILE)
            self.assertEqual(stat.S_IMODE((wizard.CONFIG_DIR / 'client.ovpn').stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((wizard.BIN_DIR / 'vpn-desk').stat().st_mode), 0o755)
            self.assertEqual((wizard.HELPER_DIR / 'privileged.py').read_bytes(), contents['privileged.py'])
            self.assertEqual((wizard.MENU_DIR / 'vpn-desk.desktop').read_bytes(), wizard.DESKTOP)
            self.assertTrue((wizard.CONFIG_DIR / 'vpn-guard.candidate.json').is_file())
            run.assert_not_called()


class DetectionTests(unittest.TestCase):
    @contextmanager
    def fresh_profile(self, text=PROFILE):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / 'home'
            source = home / 'vpn-lab/client.ovpn'
            source.parent.mkdir(parents=True)
            source.write_text(text)
            source.chmod(0o600)
            with patch.object(wizard, 'CONFIG_DIR', root / 'config'), \
                    patch.object(wizard.pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(home))):
                yield source

    def test_detected_configuration_needs_no_field_answers_and_prints_only_summary(self):
        with self.fresh_profile(), patch.object(wizard, 'wifi_interface_for', return_value='wlp2s0'), \
                patch.object(wizard, 'dhcp_server_for', return_value='192.0.2.1') as dhcp, \
                patch.object(wizard, 'ask') as ask, patch('sys.stdout', new_callable=io.StringIO) as output:
            policy, text = wizard.collect_configuration(security, os.getuid())
            self.assertEqual(policy, {**POLICY, 'wifi_interface': 'wlp2s0'})
            self.assertEqual(text, PROFILE)
            ask.assert_not_called()
            dhcp.assert_called_once_with('wlp2s0')
            self.assertIn('192.0.2.10:1194 (udp)', output.getvalue())
            self.assertIn('vpn.example.invalid', output.getvalue())
            self.assertNotIn('TEST KEY', output.getvalue())
            self.assertNotIn('TEST CONTROL KEY', output.getvalue())

    def test_only_missing_dhcp_is_requested(self):
        with self.fresh_profile(), patch.object(wizard, 'wifi_interface_for', return_value='wlan0'), \
                patch.object(wizard, 'dhcp_server_for', return_value=None), \
                patch.object(wizard, 'ask', return_value='192.0.2.1') as ask, \
                patch('sys.stdout', new_callable=io.StringIO):
            policy, _ = wizard.collect_configuration(security, os.getuid())
            self.assertEqual(policy, POLICY)
            ask.assert_called_once_with('Current Wi-Fi DHCP server IPv4', None)

    def test_missing_interface_is_requested_before_its_lease(self):
        with self.fresh_profile(), patch.object(wizard, 'wifi_interface_for', return_value=None), \
                patch.object(wizard, 'dhcp_server_for', return_value='192.0.2.1') as dhcp, \
                patch.object(wizard, 'ask', return_value='wlan0') as ask, \
                patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(wizard.collect_configuration(security, os.getuid())[0], POLICY)
            ask.assert_called_once_with('Wi-Fi interface', None)
            dhcp.assert_called_once_with('wlan0')

    def test_manual_mode_can_review_source_and_local_values(self):
        with self.fresh_profile() as source, \
                patch.object(wizard, 'wifi_interface_for', return_value='wlan0'), \
                patch.object(wizard, 'dhcp_server_for', return_value='192.0.2.1') as dhcp, \
                patch.object(wizard, 'ask', side_effect=[str(source), 'wlp3s0', '198.51.100.1']) as ask, \
                patch('sys.stdout', new_callable=io.StringIO):
            policy, _ = wizard.collect_configuration(security, os.getuid(), manual=True)
            self.assertEqual(policy['wifi_interface'], 'wlp3s0')
            self.assertEqual(policy['dhcp_server_ipv4'], '198.51.100.1')
            self.assertEqual(ask.call_count, 3)
            dhcp.assert_called_once_with('wlp3s0')

    def test_missing_profile_only_requests_its_path(self):
        with self.fresh_profile() as source:
            alternate = source.with_name('alternate.ovpn')
            source.rename(alternate)
            with patch.object(wizard, 'wifi_interface_for', return_value='wlan0'), \
                    patch.object(wizard, 'dhcp_server_for', return_value='192.0.2.1'), \
                    patch.object(wizard, 'ask', return_value=str(alternate)) as ask, \
                    patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(wizard.collect_configuration(security, os.getuid())[0], POLICY)
                ask.assert_called_once_with('Profile file path', str(source))

    def test_profile_is_validated_before_commands_or_display(self):
        variants = (PROFILE.replace('192.0.2.10', 'untrusted.example'),
                    PROFILE.replace('vpn.example.invalid', 'bad\x1b[31m'),
                    PROFILE + 'up /tmp/untrusted\n',
                    PROFILE.replace('verify-x509-name vpn.example.invalid name\n', ''),
                    PROFILE + 'remote 198.51.100.10 1194\n')
        for text in variants:
            with self.subTest(text_index=variants.index(text)), self.fresh_profile(text), \
                    patch.object(wizard, 'network_read') as read, \
                    patch('sys.stdout', new_callable=io.StringIO) as output:
                with self.assertRaises((security.Refused, ValueError)):
                    wizard.collect_configuration(security, os.getuid())
                read.assert_not_called()
                self.assertNotIn('Installation settings:', output.getvalue())
                self.assertNotIn('\x1b', output.getvalue())

    def test_invalid_manual_interface_cannot_reach_nmcli(self):
        with self.fresh_profile(), patch.object(wizard, 'wifi_interface_for', return_value=None), \
                patch.object(wizard, 'ask', return_value='--malicious'), \
                patch.object(wizard, 'dhcp_server_for') as dhcp, \
                patch('sys.stdout', new_callable=io.StringIO):
            with self.assertRaises(wizard.InstallationError):
                wizard.collect_configuration(security, os.getuid())
            dhcp.assert_not_called()

    def test_route_lookup_uses_endpoint_and_requires_one_physical_wifi(self):
        with patch.object(wizard, 'network_read', return_value='[{"dev":"wlp2s0"}]') as read, \
                patch.object(Path, 'is_dir', return_value=True):
            self.assertEqual(wizard.wifi_interface_for('192.0.2.10'), 'wlp2s0')
            read.assert_called_once_with(['/usr/sbin/ip', '-j', '-4', 'route', 'get', '192.0.2.10'])
        with patch.object(wizard, 'network_read', return_value='[{"dev":"eth0"}]'), \
                patch.object(Path, 'is_dir', return_value=False):
            self.assertIsNone(wizard.wifi_interface_for('192.0.2.10'))
        for value in ('invalid', '{}', '[]', '[null]', '[{"dev":"lo"}]',
                      '[{"dev":"tun0"}]', '[{"dev":"../bad"}]',
                      '[{"dev":"wlan0"},{"dev":"wlan1"}]',
                      '[{"dev":"wlan0","multipath":[{}]}]'):
            with self.subTest(value=value), patch.object(wizard, 'network_read', return_value=value):
                self.assertIsNone(wizard.wifi_interface_for('192.0.2.10'))

    def test_nmcli_formats_and_exact_interface_are_supported(self):
        for output in ('dhcp_server_identifier = 192.0.2.1\nrouters = 198.51.100.1\n',
                       'routers = 198.51.100.1 | dhcp_server_identifier = 192.0.2.1 | expiry = 42\n'):
            with patch.object(wizard, 'network_read', return_value=output) as read:
                self.assertEqual(wizard.dhcp_server_for('wlp2s0'), '192.0.2.1')
                read.assert_called_once_with(['/usr/bin/nmcli', '-g', 'DHCP4.OPTION', 'device', 'show', 'wlp2s0'])

    def test_dhcp_never_guesses_from_gateway_dns_or_conflicting_identifiers(self):
        for output in ('routers = 192.0.2.1\ndomain_name_servers = 192.0.2.1\n',
                       'dhcp_server_identifier = 192.0.2.1\ndhcp_server_identifier = 192.0.2.2',
                       'dhcp_server_identifier = not-an-ip', 'dhcp_server_identifier = 127.0.0.1',
                       'dhcp_server_identifier = 0.0.0.0', 'dhcp_server_identifier = 224.0.0.1',
                       'dhcp_server_identifier = 255.255.255.255', 'dhcp_server_identifier = 2001:db8::1'):
            with self.subTest(output=output), patch.object(wizard, 'network_read', return_value=output):
                self.assertIsNone(wizard.dhcp_server_for('wlan0'))
        with patch.object(wizard, 'network_read') as read:
            self.assertIsNone(wizard.dhcp_server_for('--bad'))
            read.assert_not_called()

    def test_missing_timed_out_and_oversized_diagnostics_fall_back_without_raw_output(self):
        from safe_io import OutputLimitExceeded
        for error in (FileNotFoundError('fixture'), subprocess.TimeoutExpired(['fixture'], 5),
                      OutputLimitExceeded('private fixture')):
            with patch('safe_io.bounded_run', side_effect=error), \
                    patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(wizard.network_read(['/usr/bin/nmcli']), '')
                self.assertEqual(output.getvalue(), '')

    def test_manual_mode_survives_sudo_with_literal_arguments(self):
        with patch.object(wizard.os, 'geteuid', return_value=1000), \
                patch.object(wizard.sys.stdin, 'isatty', return_value=True), \
                patch.object(wizard.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run, \
                patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(wizard.main(['--manual']), 0)
            self.assertEqual(run.call_args.args[0][-2:], ['--root', '--manual'])


class BundleTests(unittest.TestCase):
    def fixture(self, root):
        for name in set(wizard.HELPERS + wizard.APPLICATION):
            path = root / name
            path.write_bytes(b'pass\n' if name.endswith('.py') else b'public fixture\n')
            path.chmod(0o644)

    def test_zip_extraction_with_shared_umask_is_rejected_then_accepts_owner_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, extracted = root / 'source', root / 'extracted'
            source.mkdir()
            extracted.mkdir()
            self.fixture(source)
            archive_path = root / 'source.zip'
            with zipfile.ZipFile(archive_path, 'w') as archive:
                for path in source.iterdir():
                    info = zipfile.ZipInfo(path.name)
                    info.create_system = 0
                    info.external_attr = 0x20
                    archive.writestr(info, path.read_bytes())
            previous = os.umask(0o002)
            try:
                with zipfile.ZipFile(archive_path) as archive:
                    for name in set(wizard.HELPERS + wizard.APPLICATION):
                        (extracted / name).write_bytes(archive.read(name))
            finally:
                os.umask(previous)
            with patch.object(wizard, 'SOURCE', extracted):
                with self.assertRaisesRegex(wizard.InstallationError, 'group/other writable'):
                    wizard.snapshot_bundle(os.getuid())
                before = {path.name: path.read_bytes() for path in extracted.iterdir()}
                for path in extracted.iterdir():
                    path.chmod(stat.S_IMODE(path.stat().st_mode) & ~0o022)
                self.assertEqual(wizard.snapshot_bundle(os.getuid()), before)

    def test_check_and_install_refuse_unsafe_source_before_elevation_or_dependency_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / 'app.py').chmod(0o666)
            for arguments in (['--check'], []):
                with patch.object(wizard, 'SOURCE', root), patch.object(wizard.subprocess, 'run') as run, \
                        patch.object(wizard.os, 'geteuid', return_value=1000), \
                        patch.object(wizard.sys.stdin, 'isatty', return_value=True):
                    with self.assertRaisesRegex(wizard.InstallationError, 'app.py is group/other writable'):
                        wizard.main(arguments)
                    run.assert_not_called()

    def test_source_links_are_still_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            target = root / 'target'
            target.write_bytes(b'pass\n')
            selected = root / 'app.py'
            selected.unlink()
            selected.symlink_to(target)
            with patch.object(wizard, 'SOURCE', root), self.assertRaises(wizard.InstallationError):
                wizard.snapshot_bundle(os.getuid())
            selected.unlink()
            os.link(target, selected)
            with patch.object(wizard, 'SOURCE', root), self.assertRaisesRegex(wizard.InstallationError, 'one link'):
                wizard.snapshot_bundle(os.getuid())

    def test_source_owner_is_still_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=31415,
                                       st_nlink=1, st_size=5)
            with patch.object(wizard, 'SOURCE', root), patch.object(wizard.os, 'fstat', return_value=metadata), \
                    self.assertRaisesRegex(wizard.InstallationError, 'belong to you or root'):
                wizard.snapshot_bundle(1000)

    def test_syntax_error_does_not_echo_source_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / 'app.py').write_bytes(b'PRIVATE_FIXTURE_CONTENT = (\n')
            with patch.object(wizard, 'SOURCE', root), self.assertRaises(wizard.InstallationError) as error:
                wizard.snapshot_bundle(os.getuid())
            self.assertIn('app.py', str(error.exception))
            self.assertNotIn('PRIVATE_FIXTURE_CONTENT', str(error.exception))
