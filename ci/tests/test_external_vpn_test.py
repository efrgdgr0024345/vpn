import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ops'))
import external_vpn_test as external


def devices():
    return {name: {'cn': 'vpn-lab-'+name, 'sha256': str(index)*64,
                   'address': '172.27.240.'+str(10+index), 'enabled': True}
            for index, name in enumerate(('kali', 'iphone', 'android'), 1)}


class FakeServer:
    def __init__(self, root):
        self.CONFIG = root/'config'
        self.PKI = root/'pki'
        self.EXPORT = root/'export'
        for path in (self.CONFIG, self.PKI/'issued', self.PKI/'private', self.PKI/'reqs', self.EXPORT):
            path.mkdir(parents=True, exist_ok=True)
        self.original = json.dumps(devices(), indent=2)+'\n'
        (self.CONFIG/'devices.json').write_text(self.original)
        (self.EXPORT/'login.txt').write_text('vpn-lab-client\n'+'PRIVATE_PASSWORD'*4+'\n')
        self.calls = []
        self.busy = False

    def read_owned(self, path):
        return Path(path).read_text()

    def write(self, path, value, mode=0o600):
        path = Path(path)
        path.write_text(value)
        path.chmod(mode)

    def run(self, argv):
        self.calls.append(argv)
        if argv[0].endswith('nft'):
            return json.dumps({'nftables': [{'set': {'family': 'inet', 'table': 'vpn_lab',
                'name': 'authorized', 'type': 'ipv4_addr', 'elem': ['172.27.240.10'] if self.busy else []}}]})
        if argv[0].endswith('openssl'):
            return 'sha256 Fingerprint='+':'.join(['AB']*32)+'\n'
        raise AssertionError('Unexpected command.')

    def easyrsa(self, *arguments):
        self.calls.append(arguments)
        if arguments[0] == 'build-client-full':
            for folder, suffix, value in (('issued', '.crt', 'PUBLIC_CERT'),
                                         ('private', '.key', 'PRIVATE_KEY'), ('reqs', '.req', 'PUBLIC_CSR')):
                path = self.PKI/folder/(arguments[1]+suffix)
                path.write_text(value)
                path.chmod(0o600)
        elif arguments[0] == 'gen-crl':
            (self.PKI/'crl.pem').write_text('PUBLIC_CRL')

    def client_configuration(self, host, cn, portable=False):
        assert cn.startswith('vpn-test-') and portable
        return 'PRIVATE_PROFILE'


class ExternalTestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.server = FakeServer(self.root)
        self.peer = {'settings': Mock(return_value=('192.0.2.2', '22', 'SHA256:PIN')),
                     'check_key': Mock(), 'pin_host': Mock(return_value='PUBLIC_HOST_KEY\n'),
                     'run': Mock(), 'KEY': self.root/'ssh-key', 'RUNTIME': self.root}
        self.client = {'validate_report': lambda value: value}
        self.requests = []
        def remote(peer, known, source, host, port, request, client):
            self.requests.append(request)
            return {'mode': request['mode'], 'passed': True, 'tools_ready': True, 'cleanup_confirmed': True}
        self.remote = Mock(side_effect=remote)
        actual_fstat = os.fstat
        def root_metadata(fd):
            info = actual_fstat(fd)
            values = list(info)
            values[4] = 0
            return os.stat_result(values)
        for patcher in (patch.object(external, 'protected'), patch.object(external.os, 'geteuid', return_value=0),
                        patch.object(external.os, 'fstat', side_effect=root_metadata),
                        patch.object(external.time, 'sleep'),
                        patch.object(external, 'CRL', self.root/'published-crl.pem'),
                        patch.object(external, 'remote', self.remote)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_test(self):
        return external.orchestrate(server=self.server, peer=self.peer, client=self.client,
            client_source='PUBLIC_CLIENT_SOURCE', host='192.0.2.2', port='22', fingerprint='SHA256:PIN',
            server_host='192.0.2.10')

    def test_success_uses_fresh_identity_restores_exact_bytes_and_publishes_crl(self):
        value = self.run_test()
        self.assertIsNone(value['failure'])
        self.assertEqual(value['stage'], 'complete')
        self.assertTrue(value['registry_restored'])
        self.assertTrue(value['ephemeral_certificate_revoked'])
        self.assertEqual((self.server.CONFIG/'devices.json').read_text(), self.server.original)
        self.assertEqual([request['mode'] for request in self.requests], ['prepare', 'test'])
        self.assertEqual(self.requests[1]['expected_ipv4'], '172.27.240.249')
        self.assertIn('PRIVATE_PASSWORD', self.requests[1]['login'])
        self.assertNotIn('PRIVATE', json.dumps(value))
        build = next(call for call in self.server.calls if call[0] == 'build-client-full')
        self.assertRegex(build[1], r'^vpn-test-[0-9a-f]{24}$')
        self.assertIn(('revoke', build[1]), self.server.calls)
        self.assertIn(('gen-crl',), self.server.calls)
        self.assertFalse((self.server.PKI/'private'/(build[1]+'.key')).exists())
        self.assertFalse((self.server.PKI/'reqs'/(build[1]+'.req')).exists())
        self.assertTrue((self.server.PKI/'issued'/(build[1]+'.crt')).exists())
        self.assertEqual(stat.S_IMODE((self.root/'published-crl.pem').stat().st_mode), 0o644)
        self.assertFalse(any('flush' in call or 'restart' in call for call in self.server.calls))

    def test_busy_slot_refuses_without_preparing_peer_or_creating_certificate(self):
        self.server.busy = True
        value = self.run_test()
        self.assertEqual(value['failure'], 'busy')
        self.assertEqual(value['stage'], 'preflight')
        self.remote.assert_not_called()
        self.assertFalse(any(call[0] == 'build-client-full' for call in self.server.calls))
        self.assertEqual((self.server.CONFIG/'devices.json').read_text(), self.server.original)

    def test_registry_settles_before_the_fresh_certificate_is_presented(self):
        observed = []
        def settle(seconds):
            current = json.loads((self.server.CONFIG/'devices.json').read_text())
            self.assertRegex(current['android']['cn'], r'^vpn-test-[0-9a-f]{24}$')
            self.assertEqual(current['android']['address'], '172.27.240.249')
            self.assertEqual([request['mode'] for request in self.requests], ['prepare'])
            observed.append(seconds)
        with patch.object(external.time, 'sleep', side_effect=settle):
            value = self.run_test()
        self.assertIsNone(value['failure'])
        self.assertEqual(observed, [1.25])

    def test_a_legitimate_connection_during_registry_settle_is_preserved(self):
        with patch.object(external.time, 'sleep', side_effect=lambda seconds: setattr(self.server, 'busy', True)):
            value = self.run_test()
        self.assertEqual(value['failure'], 'busy')
        self.assertEqual([request['mode'] for request in self.requests], ['prepare'])
        self.assertTrue(self.server.busy)
        self.assertTrue(value['registry_restored'])
        self.assertTrue(value['ephemeral_certificate_revoked'])

    def test_host_pin_failure_precedes_peer_execution_and_private_file_reads(self):
        self.peer['pin_host'].side_effect = RuntimeError('PRIVATE RAW SSH ERROR')
        value = self.run_test()
        self.assertEqual(value['failure'], 'host_pin_failed')
        self.assertEqual(self.server.calls, [])
        self.remote.assert_not_called()
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_failed_peer_preparation_never_creates_or_exports_credentials(self):
        self.remote.side_effect = lambda *args: {'passed': False, 'tools_ready': False, 'cleanup_confirmed': True}
        value = self.run_test()
        self.assertEqual(value['failure'], 'peer_prepare_failed')
        self.assertEqual(value['stage'], 'peer_prepare')
        self.assertFalse(any(call[0] == 'build-client-full' for call in self.server.calls))

    def test_peer_failure_still_restores_registry_and_revokes_temporary_certificate(self):
        original_remote = self.remote.side_effect
        def failed(*args):
            value = original_remote(*args)
            if args[5]['mode'] == 'test':
                value['passed'] = False
            return value
        self.remote.side_effect = failed
        value = self.run_test()
        self.assertEqual(value['failure'], 'test_failed')
        self.assertTrue(value['registry_restored'])
        self.assertTrue(value['ephemeral_certificate_revoked'])
        self.assertEqual((self.server.CONFIG/'devices.json').read_text(), self.server.original)

    def test_raw_transport_exception_is_withheld_and_cleanup_still_runs(self):
        original_remote = self.remote.side_effect
        def failed(*args):
            if args[5]['mode'] == 'test':
                raise RuntimeError('PRIVATE_PASSWORD PRIVATE_PROFILE')
            return original_remote(*args)
        self.remote.side_effect = failed
        value = self.run_test()
        self.assertNotIn('PRIVATE', json.dumps(value))
        self.assertTrue(value['registry_restored'])
        self.assertTrue(value['ephemeral_certificate_revoked'])

    def test_independent_registry_edit_is_preserved_while_our_android_record_is_removed(self):
        original_remote = self.remote.side_effect
        def changed(*args):
            if args[5]['mode'] == 'test':
                path = self.server.CONFIG/'devices.json'
                current = json.loads(path.read_text())
                current['kali']['enabled'] = False
                path.write_text(json.dumps(current))
            return original_remote(*args)
        self.remote.side_effect = changed
        value = self.run_test()
        self.assertEqual(value['failure'], 'registry_changed')
        self.assertFalse(value['registry_restored'])
        current = json.loads((self.server.CONFIG/'devices.json').read_text())
        self.assertFalse(current['kali']['enabled'])
        self.assertEqual(current['android'], devices()['android'])
        self.assertTrue(value['ephemeral_certificate_revoked'])

    def test_crl_failure_does_not_skip_registry_restore_or_private_key_cleanup(self):
        original = self.server.easyrsa
        def failed(*args):
            if args[0] == 'gen-crl':
                raise RuntimeError('PRIVATE')
            return original(*args)
        self.server.easyrsa = failed
        value = self.run_test()
        self.assertEqual(value['failure'], 'certificate_cleanup_failed')
        self.assertTrue(value['registry_restored'])
        self.assertFalse(value['ephemeral_certificate_revoked'])
        self.assertEqual(list((self.server.PKI/'private').iterdir()), [])
        self.assertNotIn('PRIVATE', json.dumps(value))


class TransportSafetyTests(unittest.TestCase):
    def test_private_payload_is_only_in_ssh_stdin_and_host_options_are_fixed(self):
        source = 'PUBLIC_SOURCE'
        request = {'mode': 'test', 'profile': 'PRIVATE_PROFILE', 'login': 'PRIVATE_PASSWORD'}
        value = {'mode': 'test', 'passed': False}
        peer = {'KEY': Path('/root/private-key'), 'run': Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(value), 'PRIVATE_STDERR'))}
        actual = external.remote(peer, Path('/run/known_hosts'), source, '192.0.2.2', '22', request,
                                 {'validate_report': lambda value: value})
        self.assertEqual(actual, value)
        call = peer['run'].call_args
        argv = call.args[0]
        self.assertNotIn('PRIVATE_PROFILE', ' '.join(argv))
        self.assertNotIn('PRIVATE_PASSWORD', ' '.join(argv))
        self.assertEqual(json.loads(call.kwargs['input']), request)
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn('IdentityAgent=none', argv)
        self.assertIn('ClearAllForwardings=yes', argv)
        self.assertIn('HostKeyAlgorithms=ssh-ed25519', argv)

    def test_wrong_remote_mode_or_extra_private_fields_are_withheld(self):
        def validate(value):
            if set(value) != {'mode', 'passed'}:
                raise ValueError('PRIVATE')
            return value
        for output in ('PRIVATE', json.dumps({'mode': 'prepare', 'passed': True}),
                       json.dumps({'mode': 'test', 'passed': True, 'profile': 'PRIVATE'})):
            peer = {'KEY': Path('/root/key'), 'run': Mock(return_value=subprocess.CompletedProcess([], 0, output, 'PRIVATE'))}
            with self.assertRaises(external.TestError) as error:
                external.remote(peer, Path('/run/known'), 'PUBLIC', '192.0.2.2', '22', {'mode': 'test'}, {'validate_report': validate})
            self.assertEqual(str(error.exception), 'invalid_peer_report')

    def test_public_summary_rejects_unknown_fields_controls_and_false_success(self):
        original = {'version': 1, 'peer_prepared': False, 'test': None, 'registry_restored': True,
                    'ephemeral_certificate_revoked': False, 'credential_contents_returned': False,
                    'stage': 'preflight', 'failure': 'busy'}
        self.assertIs(external.validate_report(original), original)
        for value in ({**original, 'failure': 'PRIVATE'}, {**original, 'stage': 'PRIVATE'},
                      {**original, 'private': 'PRIVATE'}, {**original, 'credential_contents_returned': True},
                      {**original, 'failure': None}, {**original, 'registry_restored': 'yes'}):
            with self.assertRaises(ValueError) as error:
                external.validate_report(value)
            self.assertNotIn('PRIVATE', str(error.exception))


if __name__ == '__main__':
    unittest.main()
