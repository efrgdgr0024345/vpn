import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import unquote
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci'))
sys.path.insert(0, str(ROOT / 'ops'))
import lab_admin as lab
import bootstrap_runner_key as bootstrap

WIRE = b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + bytes(range(32))
BLOB = base64.b64encode(WIRE).decode()
FINGERPRINT = 'SHA256:' + base64.b64encode(hashlib.sha256(WIRE).digest()).decode().rstrip('=')
SETTINGS = {'VPN_LAB_HOST': '192.0.2.10', 'VPN_LAB_PORT': '22',
            'VPN_LAB_HOST_FINGERPRINT': FINGERPRINT}
SCAN = '192.0.2.10 ssh-ed25519 ' + BLOB + '\n'
KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nTEST FIXTURE ONLY\n-----END OPENSSH PRIVATE KEY-----'
REPORT = {'os': {'ID': 'debian'}, 'kernel': 'fixture', 'root_free_bytes': 1024,
          'running_service_units': [], 'listening_ports': [],
          'candidate_vpn_subnet_overlaps_existing_route': False,
          'firewall_summary': None, 'tools': {}}


class ConnectionTests(unittest.TestCase):
    def result(self, text=SCAN, code=0):
        return subprocess.CompletedProcess([], code, text, '')

    def test_public_connectivity_needs_no_private_key(self):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return self.result()
        lab.execute('connectivity', SETTINGS, run)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][:2], ['/usr/bin/ssh-keyscan', '-T'])
        self.assertNotIn('VPN_LAB_SSH_PRIVATE_KEY', calls[0][1]['env'])

    def test_mismatch_refuses_before_authentication(self):
        with self.assertRaisesRegex(lab.LabError, 'HOST KEY MISMATCH'):
            lab.execute('inventory', {**SETTINGS, 'VPN_LAB_HOST_FINGERPRINT': 'SHA256:'+'A'*43},
                        lambda *args, **kwargs: self.result())

    def test_failed_empty_malformed_and_wrong_host_scans_refused(self):
        for output, status in (('', 1), ('', 0), ('192.0.2.10 ssh-ed25519 !!!!!\n', 0),
                               (SCAN.replace('192.0.2.10', '192.0.2.11'), 0),
                               ('192.0.2.10 ssh-ed25519 YWJj\n', 0)):
            with self.subTest(output=output), self.assertRaises(lab.LabError):
                lab.verified_host(*lab.settings(SETTINGS), lambda *a, **kw: self.result(output, status))

    def test_option_injection_and_invalid_settings_refused(self):
        for field, value in (('VPN_LAB_HOST', '-oProxyCommand=bad'), ('VPN_LAB_HOST', '127.0.0.1'),
                             ('VPN_LAB_PORT', '22 -v'), ('VPN_LAB_PORT', '65536'),
                             ('VPN_LAB_HOST_FINGERPRINT', 'SHA256:short')):
            with self.subTest(field=field, value=value), self.assertRaises(lab.LabError):
                lab.settings({**SETTINGS, field: value})

    def test_nonstandard_port_is_pinned_with_known_hosts_brackets(self):
        line = SCAN.replace('192.0.2.10 ', '[192.0.2.10]:2222 ')
        self.assertEqual(lab.verified_host('192.0.2.10', '2222', FINGERPRINT,
                                         lambda *a, **kw: self.result(line)), line)

    def test_missing_or_public_key_secret_refused(self):
        for secret in ('', SCAN):
            with self.assertRaisesRegex(lab.LabError, 'environment needs'):
                lab.execute('inventory', {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': secret},
                            lambda *a, **kw: self.result())

    def test_strict_ssh_and_private_file_cleanup_after_auth_failure(self):
        paths = []
        def run(argv, **kwargs):
            if argv[0].endswith('ssh-keyscan'):
                return self.result()
            key = Path(argv[argv.index('-i')+1])
            paths.append(key)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            self.assertEqual(key.read_text(), KEY+'\n')
            self.assertNotIn(KEY, str(argv))
            self.assertNotIn('VPN_LAB_SSH_PRIVATE_KEY', kwargs['env'])
            for option in ('StrictHostKeyChecking=yes', 'BatchMode=yes', 'IdentitiesOnly=yes',
                           'ForwardAgent=no', 'ClearAllForwardings=yes'):
                self.assertIn(option, argv)
            self.assertEqual(argv[-1], '/usr/bin/python3 -I -B -')
            self.assertEqual(kwargs['input'], lab.INVENTORY)
            return self.result('UNTRUSTED RAW OUTPUT', 255)
        with self.assertRaisesRegex(lab.LabError, 'SSH inventory failed'):
            lab.execute('inventory', {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': KEY}, run)
        self.assertTrue(paths)
        self.assertFalse(paths[0].parent.exists())

    def test_unexpected_remote_fields_are_not_printed(self):
        def run(argv, **kwargs):
            return self.result() if argv[0].endswith('ssh-keyscan') else self.result('{"password":"PRIVATE"}')
        with self.assertRaisesRegex(lab.LabError, 'unexpected fields'):
            lab.execute('inventory', {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': KEY}, run)

    def test_check_report_preserves_literal_percent_sequences_without_publishing_key(self):
        report = {**REPORT, 'running_service_units': ['example%0Aservice.service']}
        def run(argv, **kwargs):
            return self.result() if argv[0].endswith('ssh-keyscan') else self.result(json.dumps(report))
        output = io.StringIO()
        with patch('sys.stdout', output):
            lab.execute('inventory', {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': KEY,
                                     'GITHUB_ACTIONS': 'true'}, run)
        notice = next(line for line in output.getvalue().splitlines()
                      if line.startswith('::notice title=VPN lab inventory::'))
        self.assertEqual(json.loads(unquote(notice.split('::', 2)[2])), report)
        self.assertIn('example%250Aservice.service', notice)
        self.assertNotIn('TEST FIXTURE ONLY', output.getvalue())

    def test_oversized_check_report_fails_before_printing_server_data(self):
        report = {**REPORT, 'running_service_units': ['X'*60001]}
        def run(argv, **kwargs):
            return self.result() if argv[0].endswith('ssh-keyscan') else self.result(json.dumps(report))
        output = io.StringIO()
        with patch('sys.stdout', output), self.assertRaisesRegex(lab.LabError, 'size limit'):
            lab.execute('inventory', {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': KEY,
                                     'GITHUB_ACTIONS': 'true'}, run)
        self.assertNotIn('X'*100, output.getvalue())

    def test_workflow_context_must_be_manual_main_in_this_repo(self):
        with patch.dict(os.environ, {'GITHUB_EVENT_NAME':'pull_request', 'GITHUB_REF':'refs/heads/main',
                                     'GITHUB_REPOSITORY':'efrgdgr0024345/vpn'}, clear=True), \
                self.assertRaisesRegex(lab.LabError, 'manual run'):
            lab.main()


class AuthorizationTests(unittest.TestCase):
    def provision(self, directory, **kwargs):
        bootstrap.authorize(Path(directory), 'ssh-ed25519 '+BLOB, '20300101000000Z',
                            owner=os.getuid(), **kwargs)

    def test_preserves_other_keys_and_only_removes_selected_obsolete_key(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'authorized_keys'
            target.write_text('ssh-ed25519 OLDKEY stale\nssh-ed25519 OTHERKEY operator\n')
            self.provision(directory, remove_blob='OLDKEY')
            self.assertNotIn('OLDKEY', target.read_text())
            self.assertIn('ssh-ed25519 OTHERKEY operator\n', target.read_text())
            self.assertIn('restrict,expiry-time="20300101000000Z"', target.read_text())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.provision(directory)
            self.assertEqual(target.read_text().count(BLOB), 1)

    def test_symlink_and_hardlink_are_refused_without_touching_target(self):
        for kind in ('symlink', 'hardlink'):
            with tempfile.TemporaryDirectory() as directory:
                original = Path(directory) / 'original'
                original.write_text('KEEP\n')
                target = Path(directory) / 'authorized_keys'
                if kind == 'symlink':
                    target.symlink_to(original)
                else:
                    os.link(original, target)
                with self.assertRaises((OSError, RuntimeError)):
                    self.provision(directory)
                self.assertEqual(original.read_text(), 'KEEP\n')

    def test_interrupted_publish_preserves_existing_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'authorized_keys'
            target.write_text('KEEP\n')
            with patch.object(bootstrap.os, 'replace', side_effect=OSError('fixture')), \
                    self.assertRaises(OSError):
                self.provision(directory)
            self.assertEqual(target.read_text(), 'KEEP\n')
            self.assertEqual(list(Path(directory).iterdir()), [target])


if __name__ == '__main__':
    unittest.main()
