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

import privileged
import security as s
from safe_io import bounded_run, OutputLimitExceeded, private_write

POLICY = json.loads((Path(__file__).parents[1] / 'policy.example.json').read_text())
# Deliberately inert fixture data; no real certificate or private key.
PROFILE = '''client
dev tun0
proto udp
remote 192.0.2.10 1194
remote-cert-tls server
verify-x509-name vpn.example.invalid name
tls-version-min 1.3
data-ciphers AES-256-GCM
<ca>
TEST CA
</ca>
<cert>
TEST CERT
</cert>
<key>
TEST KEY
</key>
<tls-crypt>
TEST CONTROL KEY
</tls-crypt>
'''


class ProfileTests(unittest.TestCase):
    def test_supported_profile(self):
        self.assertEqual(s.validate_profile(PROFILE, POLICY), PROFILE)

    def test_access_server_spaced_certificate_name_is_matched_as_one_quoted_value(self):
        policy = s.validate_policy({**POLICY, 'server_name': 'OpenVPN Server'})
        profile = PROFILE.replace('verify-x509-name vpn.example.invalid name',
                                  'verify-x509-name "OpenVPN Server" name')
        self.assertEqual(s.validate_profile(profile, policy), profile)

    def test_spaced_certificate_name_still_requires_exact_match_and_quoting(self):
        policy = s.validate_policy({**POLICY, 'server_name': 'OpenVPN Server'})
        for directive in ('verify-x509-name "OpenVPN Other Server" name',
                          'verify-x509-name OpenVPN Server name',
                          'verify-x509-name "OpenVPN Server" name-prefix'):
            profile = PROFILE.replace('verify-x509-name vpn.example.invalid name', directive)
            with self.subTest(directive=directive), self.assertRaises(s.Refused):
                s.validate_profile(profile, policy)

    def test_dangerous_directives_and_external_assets_refused(self):
        for directive in ('script-security 2', 'up /tmp/hook', 'down /tmp/hook',
                          'plugin /tmp/plugin.so', 'config /tmp/other.conf',
                          'management 127.0.0.1 1234', 'management-client-user root',
                          'daemon', 'log /tmp/output', 'writepid /tmp/pid',
                          'ca /tmp/ca', 'cert /tmp/cert', 'key /tmp/key',
                          'auth-user-pass /tmp/password', 'tls-verify /tmp/hook',
                          'user root', 'group root', 'compress lz4',
                          'cipher AES-128-CBC', '--up /tmp/hook'):
            with self.subTest(directive=directive), self.assertRaises(s.Refused):
                s.validate_profile(PROFILE + directive + '\n', POLICY)

    def test_tls_identity_endpoint_and_crypto_required(self):
        for before, after in (('remote-cert-tls server', ''),
                              ('verify-x509-name vpn.example.invalid name', ''),
                              ('remote 192.0.2.10 1194', 'remote 192.0.2.20 1194'),
                              ('dev tun0', 'dev tun9'), ('proto udp', 'proto tcp-client'),
                              ('tls-version-min 1.3', ''),
                              ('tls-version-min 1.3', 'tls-version-min 1.0'),
                              ('data-ciphers AES-256-GCM', ''),
                              ('data-ciphers AES-256-GCM', 'data-ciphers AES-128-CBC'),
                              ('TEST KEY\n</key>', '</key>')):
            with self.subTest(before=before), self.assertRaises(s.Refused):
                s.validate_profile(PROFILE.replace(before, after), POLICY)

    def test_duplicate_and_nested_config_blocks_refused(self):
        for suffix in ('dev tun0\n', '<connection>\nremote 192.0.2.20 443\n</connection>\n',
                       '<tls-crypt>\nSECOND\n</tls-crypt>\n'):
            with self.assertRaises(s.Refused):
                s.validate_profile(PROFILE + suffix, POLICY)

    def test_unclosed_and_missing_control_key_refused(self):
        for text in (PROFILE.replace('</key>', ''), PROFILE.split('<tls-crypt>')[0]):
            with self.assertRaises(s.Refused):
                s.validate_profile(text, POLICY)

    def test_ambiguous_controls_and_asset_terminators_refused(self):
        for text in (PROFILE.replace('</ca>', '</ca>\x00hidden'),
                     PROFILE.replace('</ca>', '</ca> # comment'),
                     PROFILE.replace('TEST KEY', 'KEY\x0bDATA'),
                     PROFILE.replace('TEST KEY', 'KEY\u0085DATA')):
            with self.assertRaises(s.Refused):
                s.validate_profile(text, POLICY)


class TrustTests(unittest.TestCase):
    def metadata(self, path):
        mode = stat.S_IFREG | 0o600 if path.name == 'client.ovpn' else stat.S_IFDIR | 0o755
        return SimpleNamespace(st_uid=0, st_mode=mode)

    def test_protected_profile_metadata_accepted(self):
        with patch.object(Path, 'lstat', lambda path: self.metadata(path)):
            self.assertEqual(s.trusted_path(s.PROFILE, private=True), s.PROFILE)

    def test_links_writable_ancestors_owners_and_public_key_permissions_refused(self):
        for bad_path, mode, uid in (
                (s.PROFILE, stat.S_IFLNK | 0o777, 0),
                (s.PROFILE, stat.S_IFREG | 0o600, 1000),
                (s.CONFIG_DIR, stat.S_IFDIR | 0o775, 0),
                (s.PROFILE, stat.S_IFREG | 0o644, 0)):
            def metadata(path):
                return SimpleNamespace(st_uid=uid, st_mode=mode) if path == bad_path else self.metadata(path)
            with patch.object(Path, 'lstat', metadata), self.assertRaises(s.Refused):
                s.trusted_path(s.PROFILE, private=True)

    def test_home_profile_and_dotdot_rejected(self):
        with self.assertRaises(s.Refused):
            s.trusted_path(Path('/etc/vpn-desk/../client.ovpn'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'client.ovpn'
            path.write_text(PROFILE)
            with self.assertRaises(s.Refused):
                s.read_trusted(path, private=True)

    def test_open_never_follows_a_profile_symlink_even_after_metadata_check(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.write_text(PROFILE)
            link = Path(directory) / 'client.ovpn'
            link.symlink_to(target)
            with patch.object(s, 'trusted_path'), self.assertRaises(OSError):
                s.read_trusted(link, private=True)

    def test_policy_rejects_injected_or_ambiguous_fields(self):
        for key, value in (('wifi_interface', 'wlan0;accept'), ('vpn_port', True),
                           ('vpn_server_ipv4', '127.0.0.1'), ('vpn_server_ipv4', 123),
                           ('server_name', 'server\nname'), ('vpn_protocol', 'udp;accept')):
            with self.subTest(key=key), self.assertRaises(s.Refused):
                s.validate_policy({**POLICY, key: value})
        with self.assertRaises(s.Refused):
            s.validate_policy({**POLICY, 'extra': 'unsupported'})

    def test_certificate_names_reject_controls_boundary_whitespace_and_oversize(self):
        for name in (' OpenVPN Server', 'OpenVPN Server ', 'OpenVPN\tServer',
                     'OpenVPN\x00Server', 'OpenVPN\rServer', 'A' * 254, ''):
            with self.subTest(name=repr(name)), self.assertRaises(s.Refused):
                s.validate_policy({**POLICY, 'server_name': name})

    def test_service_account_must_be_unprivileged_and_nonlogin(self):
        for uid, gid, shell in ((0, 995, '/usr/sbin/nologin'), (995, 0, '/bin/false'), (995, 995, '/bin/bash')):
            with patch.object(s.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=uid, pw_gid=gid, pw_shell=shell)), self.assertRaises(s.Refused):
                s.service_account()

    def test_dedicated_account_and_group_accepted(self):
        account = SimpleNamespace(pw_name='vpn-desk', pw_uid=995, pw_gid=995, pw_shell='/usr/sbin/nologin')
        with patch.object(s.pwd, 'getpwnam', return_value=account), \
                patch.object(s.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=995, gr_mem=[])), \
                patch.object(s.os, 'getgrouplist', return_value=[995]), \
                patch.object(s.pwd, 'getpwall', return_value=[account]):
            self.assertIs(s.service_account(), account)

    def test_shared_or_supplementary_groups_and_duplicate_uid_refused(self):
        account = SimpleNamespace(pw_name='vpn-desk', pw_uid=995, pw_gid=995, pw_shell='/usr/sbin/nologin')
        for members, groups, users in (
                (['other'], [995], [account]),
                ([], [995, 0], [account]),
                ([], [995], [account, SimpleNamespace(pw_name='other', pw_uid=1000, pw_gid=995)]),
                ([], [995], [account, SimpleNamespace(pw_name='alias', pw_uid=995, pw_gid=1000)])):
            with patch.object(s.pwd, 'getpwnam', return_value=account), \
                    patch.object(s.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=995, gr_mem=members)), \
                    patch.object(s.os, 'getgrouplist', return_value=groups), \
                    patch.object(s.pwd, 'getpwall', return_value=users), self.assertRaises(s.Refused):
                s.service_account()

    def test_checkout_privileged_entry_refused_before_project_imports(self):
        with self.assertRaises(RuntimeError):
            privileged.verify_installation()

    def test_uninstalled_action_has_no_checkout_fallback(self):
        with patch.object(s, 'trusted_path', side_effect=s.Refused('unsafe')), self.assertRaises(s.Refused):
            s.installed_command('connect')
        with self.assertRaises(s.Refused):
            s.installed_command('portal-open')


class IOTests(unittest.TestCase):
    def test_real_child_output_and_input_capture(self):
        command = [sys.executable, '-I', '-c', 'import sys; print(sys.stdin.read()); print("diagnostic", file=sys.stderr)']
        result = bounded_run(command, input='hello', timeout=3)
        self.assertEqual(result.stdout, 'hello\n')
        self.assertEqual(result.stderr, 'diagnostic\n')

    def test_oversized_real_child_is_terminated(self):
        command = [sys.executable, '-I', '-c', 'import sys; sys.stdout.write("x" * 1000000)']
        with self.assertRaises(OutputLimitExceeded):
            bounded_run(command, limit=100, timeout=3)

    def test_hanging_real_child_times_out(self):
        command = [sys.executable, '-I', '-c', 'import time; time.sleep(5)']
        with self.assertRaises(subprocess.TimeoutExpired):
            bounded_run(command, timeout=0.1)

    def test_nonzero_exit_status_preserved(self):
        command = [sys.executable, '-I', '-c', 'raise SystemExit(7)']
        self.assertEqual(bounded_run(command, timeout=3).returncode, 7)
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            bounded_run(command, check=True, timeout=3)
        self.assertEqual(caught.exception.returncode, 7)

    def test_export_stays_private_under_permissive_umask_and_replaces_existing_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'export.txt'
            destination.write_text('old')
            destination.chmod(0o644)
            previous = os.umask(0)
            try:
                private_write(destination, 'sensitive metadata')
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(destination.read_text(), 'sensitive metadata')

    def test_export_does_not_follow_existing_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.write_text('do not overwrite')
            link = Path(directory) / 'export.txt'
            link.symlink_to(target)
            private_write(link, 'export')
            self.assertEqual(target.read_text(), 'do not overwrite')
            self.assertFalse(link.is_symlink())
            self.assertEqual(stat.S_IMODE(link.stat().st_mode), 0o600)

    def test_failed_atomic_export_leaves_existing_file_and_no_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'export.txt'
            destination.write_text('old')
            with patch('safe_io.os.replace', side_effect=OSError('refused')), self.assertRaises(OSError):
                private_write(destination, 'new')
            self.assertEqual(destination.read_text(), 'old')
            self.assertEqual(list(Path(directory).iterdir()), [destination])
