"""Guided-installer tests. System changes are mocked; writes stay in temp dirs."""
from contextlib import ExitStack, contextmanager
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
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
