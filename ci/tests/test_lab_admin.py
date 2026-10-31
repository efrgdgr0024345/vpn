import base64
import copy
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
import peer_vpn_client as peer_client

WIRE = b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + bytes(range(32))
BLOB = base64.b64encode(WIRE).decode()
FINGERPRINT = 'SHA256:' + base64.b64encode(hashlib.sha256(WIRE).digest()).decode().rstrip('=')
SETTINGS = {'VPN_LAB_HOST': '192.0.2.10', 'VPN_LAB_PORT': '22',
            'VPN_LAB_HOST_FINGERPRINT': FINGERPRINT}
SCAN = '192.0.2.10 ssh-ed25519 ' + BLOB + '\n'
KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nTEST FIXTURE ONLY\n-----END OPENSSH PRIVATE KEY-----'
REPORT = {'os': {'ID': 'debian'}, 'kernel': 'fixture', 'root_free_bytes': 1024,'uptime_seconds': 100,
          'running_service_units': [], 'listening_ports': [],
          'candidate_vpn_subnet_overlaps_existing_route': False,
          'firewall_summary': None, 'tools': {}}
CONNECTION_REPORT = {
    'version': 1, 'server_utc': '2026-10-30T01:02:03+00:00', 'ntp_synchronized': True,
    'services': [{'unit': unit, 'active_state': 'active', 'sub_state': 'running',
                  'restarts': 0, 'result': 'success'} for unit in (
                      'openvpn-server@vpn-lab.service', 'vpn-lab-broker.service', 'unbound.service')],
    'tunnel': {'present': True, 'kind': 'tun', 'up': True, 'ipv4': ['172.27.240.1/24']},
    'dns_listeners': [{'protocol': protocol, 'address': '172.27.240.1', 'port': 53}
                      for protocol in ('udp', 'tcp')],
    'authorization': {'element_count': 1, 'addresses': [{'ipv4': '172.27.240.10', 'expires_ms': 14000}]},
    'input_counters': {name: {'packets': 0, 'bytes': 0} for name in (
                        'vpn-lab-private-dns', 'vpn-lab-block-host')},
    'dns_probe': {'status': 'ok', 'rcode': 0, 'answer_count': 1, 'elapsed_ms': 1},
}
TEST_ACCESS_REPORT = {'ssh_public_key': 'ssh-ed25519 '+BLOB,
                      'ssh_public_key_fingerprint': FINGERPRINT,
                      'private_key_retained_on_server': True}
TEST_PEER_SETTINGS = {'VPN_TEST_PEER_HOST': '192.0.2.11', 'VPN_TEST_PEER_PORT': '22',
                      'VPN_TEST_PEER_HOST_FINGERPRINT': FINGERPRINT}
TEST_PEER_REPORT = {'version': 1, 'root_confirmed': True,
                    'os': {'ID': 'ubuntu', 'VERSION_ID': '20.04'}, 'kernel': '5.4.0-test',
                    'access_server_active': True,
                    'openvpn_client': {'path': '/usr/sbin/openvpn', 'version': '2.6.14'},
                    'tools': {'ip': True, 'python3': True, 'curl': True, 'nft': True}}
EXTERNAL_BUSY_REPORT = {'version': 1, 'peer_prepared': False, 'test': None,
                        'registry_restored': True, 'ephemeral_certificate_revoked': True,
                        'credential_contents_returned': False, 'stage': 'preflight', 'failure': 'busy'}


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

    def connection_diagnosis(self, report, *, code=0):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[0].endswith('ssh-keyscan'):
                return self.result()
            return subprocess.CompletedProcess([], code, json.dumps(report), 'PRIVATE STDERR')
        lab.execute('diagnose-connection', {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': KEY,
                    'GITHUB_ACTIONS': 'true'}, run)
        return calls

    def test_connection_diagnosis_sends_only_the_fixed_read_only_program(self):
        output = io.StringIO()
        with patch('sys.stdout', output):
            calls = self.connection_diagnosis(CONNECTION_REPORT)
        self.assertEqual(len(calls), 2)
        argv, options = calls[-1]
        self.assertEqual(argv[-1], '/usr/bin/python3 -I -B -')
        self.assertEqual(options['input'], (ROOT/'ops/server_diagnostics.py').read_text())
        self.assertEqual(options['timeout'], 65)
        for setting in ('StrictHostKeyChecking=yes', 'ForwardAgent=no', 'BatchMode=yes'):
            self.assertIn(setting, argv)
        notice = next(line for line in output.getvalue().splitlines()
                      if line.startswith('::notice title=VPN lab diagnose-connection::'))
        self.assertEqual(json.loads(unquote(notice.split('::', 2)[2])), CONNECTION_REPORT)
        self.assertNotIn('TEST FIXTURE ONLY', output.getvalue())
        self.assertNotIn('PRIVATE STDERR', output.getvalue())

    def test_connection_diagnosis_rejects_unexpected_nested_fields_and_private_values(self):
        reports = []
        for section, key in ((None, 'password'), ('tunnel', 'profile'), ('dns_probe', 'raw_response')):
            report = copy.deepcopy(CONNECTION_REPORT)
            (report if section is None else report[section])[key] = 'PRIVATE DATA'
            reports.append(report)
        report = copy.deepcopy(CONNECTION_REPORT)
        report['services'][0]['active_state'] = 'PRIVATE DATA'
        reports.append(report)
        report = copy.deepcopy(CONNECTION_REPORT)
        report['authorization']['addresses'][0]['ipv4'] = 'PRIVATE DATA'
        reports.append(report)
        report = copy.deepcopy(CONNECTION_REPORT)
        report['dns_probe']['status'] = 'PRIVATE DATA'
        reports.append(report)
        report = copy.deepcopy(CONNECTION_REPORT)
        report['input_counters']['vpn-lab-private-dns']['packets'] = 'PRIVATE DATA'
        reports.append(report)
        for report in reports:
            output = io.StringIO()
            with patch('sys.stdout', output), self.assertRaises(lab.LabError) as error:
                self.connection_diagnosis(report)
            self.assertNotIn('PRIVATE DATA', output.getvalue())
            self.assertNotIn('PRIVATE DATA', str(error.exception))
            self.assertNotIn('::notice', output.getvalue())

    def test_connection_diagnosis_failure_withholds_all_remote_details(self):
        output = io.StringIO()
        with patch('sys.stdout', output), self.assertRaises(lab.LabError) as error:
            self.connection_diagnosis({'error': 'setup_failed', 'detail': 'PRIVATE DATA'}, code=1)
        self.assertIn('diagnosis failed', str(error.exception))
        self.assertNotIn('PRIVATE', str(error.exception))
        self.assertNotIn('PRIVATE', output.getvalue())

    def test_connection_diagnosis_has_no_workflow_mutation_gate(self):
        workflow = (ROOT/'.github/workflows/lab-admin.yml').read_text()
        option_line = next(line for line in workflow.splitlines() if 'options: [connectivity' in line)
        gate_line = next(line for line in workflow.splitlines() if "if: inputs.operation == 'install-foundation'" in line)
        self.assertIn('diagnose-connection', option_line)
        self.assertNotIn('diagnose-connection', gate_line)

    def prepare_test_access(self, report, *, code=0):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[0].endswith('ssh-keyscan'):
                return self.result()
            return subprocess.CompletedProcess([], code, json.dumps(report), 'PRIVATE STDERR')
        lab.execute('prepare-test-access', {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': KEY,
                    'GITHUB_ACTIONS': 'true'}, run)
        return calls

    def test_test_access_preparation_sends_fixed_program_and_reports_only_public_key(self):
        output = io.StringIO()
        with patch('sys.stdout', output):
            calls = self.prepare_test_access(TEST_ACCESS_REPORT)
        self.assertEqual(len(calls), 2)
        argv, options = calls[-1]
        self.assertEqual(argv[-1], '/usr/bin/python3 -I -B -')
        self.assertEqual(options['input'], (ROOT/'ops/prepare_test_access.py').read_text())
        for setting in ('StrictHostKeyChecking=yes', 'ForwardAgent=no', 'BatchMode=yes'):
            self.assertIn(setting, argv)
        notice = next(line for line in output.getvalue().splitlines()
                      if line.startswith('::notice title=VPN lab prepare-test-access::'))
        self.assertEqual(json.loads(unquote(notice.split('::', 2)[2])), TEST_ACCESS_REPORT)
        self.assertNotIn('TEST FIXTURE ONLY', output.getvalue())
        self.assertNotIn('PRIVATE STDERR', output.getvalue())

    def test_test_access_preparation_refuses_private_fields_bad_wire_and_fingerprint(self):
        reports = [{**TEST_ACCESS_REPORT, 'ssh_private_key': 'PRIVATE DATA'},
                   {**TEST_ACCESS_REPORT, 'ssh_public_key': 'PRIVATE DATA'},
                   {**TEST_ACCESS_REPORT, 'ssh_public_key': KEY},
                   {**TEST_ACCESS_REPORT, 'ssh_public_key': 'ssh-ed25519 '+base64.b64encode(WIRE[:-1]).decode()},
                   {**TEST_ACCESS_REPORT, 'ssh_public_key': 'ssh-rsa '+BLOB},
                   {**TEST_ACCESS_REPORT, 'ssh_public_key': 'ssh-ed25519 '+BLOB+'\nPRIVATE DATA'},
                   {**TEST_ACCESS_REPORT, 'ssh_public_key_fingerprint': 'SHA256:'+'A'*43},
                   {**TEST_ACCESS_REPORT, 'private_key_retained_on_server': 'PRIVATE DATA'},
                   {**TEST_ACCESS_REPORT, 'private_key_retained_on_server': False}]
        for report in reports:
            output = io.StringIO()
            with patch('sys.stdout', output), self.assertRaises(lab.LabError) as error:
                self.prepare_test_access(report)
            for private in ('PRIVATE DATA', 'TEST FIXTURE ONLY'):
                self.assertNotIn(private, output.getvalue())
                self.assertNotIn(private, str(error.exception))
            self.assertNotIn('::notice', output.getvalue())

    def test_test_access_preparation_failure_withholds_remote_details(self):
        output = io.StringIO()
        with patch('sys.stdout', output), self.assertRaises(lab.LabError) as error:
            self.prepare_test_access({'error': 'setup_failed', 'detail': 'PRIVATE DATA'}, code=1)
        self.assertIn('preparation failed', str(error.exception))
        self.assertNotIn('PRIVATE', str(error.exception))
        self.assertNotIn('PRIVATE', output.getvalue())

    def test_test_access_preparation_requires_matching_build_gate(self):
        workflow = (ROOT/'.github/workflows/lab-admin.yml').read_text()
        option_line = next(line for line in workflow.splitlines() if 'options: [connectivity' in line)
        gate_line = next(line for line in workflow.splitlines() if "if: inputs.operation == 'install-foundation'" in line)
        self.assertIn('prepare-test-access', option_line)
        self.assertIn("inputs.operation == 'prepare-test-access'", gate_line)
        self.assertIn('secrets.VPN_LAB_SSH_PRIVATE_KEY', workflow)
        self.assertNotIn('VPN_TEST_SSH_PRIVATE_KEY', workflow)

    def inspect_test_peer(self, report, *, code=0):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[0].endswith('ssh-keyscan'):
                return self.result()
            return subprocess.CompletedProcess([], code, json.dumps(report), 'PRIVATE STDERR')
        lab.execute('inspect-test-peer', {**SETTINGS, **TEST_PEER_SETTINGS,
                    'VPN_LAB_SSH_PRIVATE_KEY': KEY, 'GITHUB_ACTIONS': 'true'}, run)
        return calls

    def test_peer_inspection_embeds_only_validated_settings_in_fixed_program(self):
        output = io.StringIO()
        with patch('sys.stdout', output):
            calls = self.inspect_test_peer(TEST_PEER_REPORT)
        self.assertEqual(len(calls), 2)
        argv, options = calls[-1]
        self.assertEqual(argv[-2:], ['root@192.0.2.10', '/usr/bin/python3 -I -B -'])
        expected = ("TEST_PEER_HOST = '192.0.2.11'\nTEST_PEER_HOST_FINGERPRINT = "
                    +repr(FINGERPRINT)+"\nTEST_PEER_PORT = '22'\n"
                    +(ROOT/'ops/inspect_test_peer.py').read_text())
        self.assertEqual(options['input'], expected)
        notice = next(line for line in output.getvalue().splitlines()
                      if line.startswith('::notice title=VPN lab inspect-test-peer::'))
        self.assertEqual(json.loads(unquote(notice.split('::', 2)[2])), TEST_PEER_REPORT)
        self.assertNotIn('TEST FIXTURE ONLY', output.getvalue())
        self.assertNotIn('PRIVATE STDERR', output.getvalue())

    def test_invalid_peer_settings_stop_before_any_network_or_authentication(self):
        for key, value in (('VPN_TEST_PEER_HOST', ''), ('VPN_TEST_PEER_HOST', '192.0.2.11; id'),
                           ('VPN_TEST_PEER_HOST', '127.0.0.1'), ('VPN_TEST_PEER_PORT', '22 -v'),
                           ('VPN_TEST_PEER_PORT', '65536'), ('VPN_TEST_PEER_HOST_FINGERPRINT', ''),
                           ('VPN_TEST_PEER_HOST_FINGERPRINT', 'SHA256:short')):
            def no_network(*args, **kwargs):
                self.fail('Invalid external peer settings reached a network tool.')
            for operation in ('inspect-test-peer', 'test-from-peer'):
                with self.assertRaises(lab.LabError):
                    lab.execute(operation, {**SETTINGS, **TEST_PEER_SETTINGS, key: value,
                                'VPN_LAB_SSH_PRIVATE_KEY': KEY}, no_network)

    def test_peer_inspection_rejects_private_or_unknown_nested_output(self):
        reports = [{**TEST_PEER_REPORT, 'private_key': 'PRIVATE DATA'},
                   {**TEST_PEER_REPORT, 'kernel': 'PRIVATE DATA'},
                   {**TEST_PEER_REPORT, 'os': {'ID': 'PRIVATE DATA', 'VERSION_ID': None}},
                   {**TEST_PEER_REPORT, 'tools': {**TEST_PEER_REPORT['tools'], 'raw': 'PRIVATE DATA'}},
                   {**TEST_PEER_REPORT, 'openvpn_client': {'path': '/root/PRIVATE', 'version': None}},
                   {**TEST_PEER_REPORT, 'root_confirmed': False}]
        for report in reports:
            output = io.StringIO()
            with patch('sys.stdout', output), self.assertRaises(lab.LabError) as error:
                self.inspect_test_peer(report)
            self.assertNotIn('PRIVATE', output.getvalue())
            self.assertNotIn('PRIVATE', str(error.exception))
            self.assertNotIn('::notice', output.getvalue())

    def test_peer_inspection_failure_withholds_remote_details(self):
        output = io.StringIO()
        with patch('sys.stdout', output), self.assertRaises(lab.LabError) as error:
            self.inspect_test_peer({'error': 'setup_failed', 'detail': 'PRIVATE DATA'}, code=1)
        self.assertIn('inspection failed', str(error.exception))
        self.assertNotIn('PRIVATE', str(error.exception))
        self.assertNotIn('PRIVATE', output.getvalue())

    def test_peer_inspection_is_read_only_and_uses_public_inputs_not_a_new_secret(self):
        workflow = (ROOT/'.github/workflows/lab-admin.yml').read_text()
        gate_line = next(line for line in workflow.splitlines() if "if: inputs.operation == 'install-foundation'" in line)
        self.assertNotIn("inputs.operation == 'inspect-test-peer'", gate_line)
        for field, name in (('test_peer_host', 'VPN_TEST_PEER_HOST'),
                            ('test_peer_host_fingerprint', 'VPN_TEST_PEER_HOST_FINGERPRINT'),
                            ('test_peer_port', 'VPN_TEST_PEER_PORT')):
            self.assertIn(name+': ${{ inputs.'+field+' }}', workflow)
        self.assertNotIn('secrets.VPN_TEST_SSH_PRIVATE_KEY', workflow)

    def external_vpn_test(self, report, *, code=0, calls=None):
        calls = [] if calls is None else calls
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[0].endswith('ssh-keyscan'):
                return self.result()
            return subprocess.CompletedProcess([], code, json.dumps(report), 'PRIVATE STDERR')
        lab.execute('test-from-peer', {**SETTINGS, **TEST_PEER_SETTINGS,
                    'VPN_LAB_SSH_PRIVATE_KEY': KEY, 'GITHUB_ACTIONS': 'true'}, run)
        return calls

    def successful_external_report(self):
        test = peer_client.empty_report()
        test.update({name: True for name in ('passed','tools_ready','namespace_isolated','handshake',
                      'host_routes_unchanged','host_dns_unchanged','cleanup_confirmed')})
        test.update({'stage': 'complete', 'client_version': '2.6.14',
                     'private_dns': {'status': 'ok', 'rcode': 0, 'answers': 1},
                     'public_dns': {'status': 'ok', 'rcode': 0, 'answers': 1}, 'https_status': 'ok'})
        return {'version': 1, 'peer_prepared': True, 'test': test, 'registry_restored': True,
                'ephemeral_certificate_revoked': True, 'credential_contents_returned': False,
                'stage': 'complete', 'failure': None}

    def test_successful_external_vpn_acceptance_is_reported_without_failing(self):
        report = self.successful_external_report()
        output = io.StringIO()
        with patch('sys.stdout', output):
            calls = self.external_vpn_test(report)
        self.assertEqual(len(calls), 2)
        self.assertIn('Lab test-from-peer completed', output.getvalue())
        notice = next(line for line in output.getvalue().splitlines()
                      if line.startswith('::notice title=VPN lab test-from-peer::'))
        self.assertEqual(json.loads(unquote(notice.split('::', 2)[2])), report)

    def test_failed_external_packets_or_cleanup_log_typed_report_then_fail_the_job(self):
        packet_failure = self.successful_external_report()
        packet_failure.update(stage='peer_test', failure='test_failed')
        packet_failure['test'].update(passed=False, stage='private_dns', error='dns_failed')
        packet_failure['test']['private_dns'] = {'status': 'timeout', 'rcode': None, 'answers': None}
        registry_failure = self.successful_external_report()
        registry_failure.update(stage='cleanup', failure='registry_changed', registry_restored=False)
        certificate_failure = self.successful_external_report()
        certificate_failure.update(stage='cleanup', failure='certificate_cleanup_failed', ephemeral_certificate_revoked=False)
        for report in (packet_failure, registry_failure, certificate_failure):
            output = io.StringIO()
            with patch('sys.stdout', output), self.assertRaisesRegex(lab.LabError, 'at '+report['stage']):
                self.external_vpn_test(report)
            notice = next(line for line in output.getvalue().splitlines()
                          if line.startswith('::notice title=VPN lab test-from-peer::'))
            self.assertEqual(json.loads(unquote(notice.split('::', 2)[2])), report)
            self.assertNotIn('Lab test-from-peer completed', output.getvalue())
            self.assertNotIn('PRIVATE STDERR', output.getvalue())

    def test_external_vpn_payload_contains_only_public_source_and_validated_endpoints(self):
        output, calls = io.StringIO(), []
        with patch('sys.stdout', output), self.assertRaisesRegex(lab.LabError, 'at preflight'):
            self.external_vpn_test(EXTERNAL_BUSY_REPORT, calls=calls)
        self.assertEqual(len(calls), 2)
        argv, options = calls[-1]
        self.assertEqual(argv[-2:], ['root@192.0.2.10', '/usr/bin/python3 -I -B -'])
        expected = ("TEST_PEER_HOST = '192.0.2.11'\nTEST_PEER_HOST_FINGERPRINT = "
                    +repr(FINGERPRINT)+"\nTEST_PEER_PORT = '22'\nTEST_SERVER_HOST = '192.0.2.10'\n"
                    +'PEER_LIBRARY_SOURCE = '+repr((ROOT/'ops/inspect_test_peer.py').read_text())+'\n'
                    +'PEER_CLIENT_SOURCE = '+repr((ROOT/'ops/peer_vpn_client.py').read_text())+'\n'
                    +(ROOT/'ops/external_vpn_test.py').read_text())
        self.assertEqual(options['input'], expected)
        self.assertEqual(options['timeout'], 900)
        self.assertNotIn(KEY, options['input'])
        notice = next(line for line in output.getvalue().splitlines()
                      if line.startswith('::notice title=VPN lab test-from-peer::'))
        self.assertEqual(json.loads(unquote(notice.split('::', 2)[2])), EXTERNAL_BUSY_REPORT)
        self.assertNotIn('PRIVATE STDERR', output.getvalue())

    def test_external_vpn_reports_reject_secret_fields_and_untyped_failures_before_printing(self):
        reports = [{**EXTERNAL_BUSY_REPORT, 'private_key': 'PRIVATE DATA'},
                   {**EXTERNAL_BUSY_REPORT, 'failure': 'PRIVATE DATA'},
                   {**EXTERNAL_BUSY_REPORT, 'stage': 'PRIVATE DATA'},
                   {**EXTERNAL_BUSY_REPORT, 'credential_contents_returned': True},
                   {**EXTERNAL_BUSY_REPORT, 'test': {'passed': False, 'raw_log': 'PRIVATE DATA'}}]
        for report in reports:
            output = io.StringIO()
            with patch('sys.stdout', output), self.assertRaises(lab.LabError) as error:
                self.external_vpn_test(report)
            self.assertNotIn('PRIVATE', output.getvalue())
            self.assertNotIn('PRIVATE', str(error.exception))
            self.assertNotIn('::notice', output.getvalue())

    def test_external_vpn_command_failure_withholds_raw_remote_output(self):
        output = io.StringIO()
        with patch('sys.stdout', output), self.assertRaises(lab.LabError) as error:
            self.external_vpn_test({'error': 'setup_failed', 'detail': 'PRIVATE DATA'}, code=1)
        self.assertIn('external VPN test failed', str(error.exception))
        self.assertNotIn('PRIVATE', str(error.exception))
        self.assertNotIn('PRIVATE', output.getvalue())

    def test_external_vpn_operation_requires_build_gate_and_no_extra_private_inputs(self):
        workflow = (ROOT/'.github/workflows/lab-admin.yml').read_text()
        option_line = next(line for line in workflow.splitlines() if 'options: [connectivity' in line)
        gate_line = next(line for line in workflow.splitlines() if "if: inputs.operation == 'install-foundation'" in line)
        self.assertIn('test-from-peer', option_line)
        self.assertIn("inputs.operation == 'test-from-peer'", gate_line)
        self.assertNotIn('secrets.VPN_TEST_SSH_PRIVATE_KEY', workflow)
        self.assertNotIn('inputs.profile', workflow)
        self.assertNotIn('inputs.password', workflow)

    def test_auth_rejection_is_classified_without_disclosing_stderr(self):
        def run(argv, **kwargs):
            if argv[0].endswith('ssh-keyscan'):
                return self.result()
            return subprocess.CompletedProcess([], 255, 'PRIVATE OUTPUT',
                'root@192.0.2.10: Permission denied (publickey). PRIVATE STDERR')
        with self.assertRaises(lab.LabError) as error:
            lab.execute('inventory', {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': KEY}, run)
        self.assertIn('SSH authentication rejected', str(error.exception))
        self.assertNotIn('PRIVATE', str(error.exception))
        self.assertNotIn('192.0.2.10', str(error.exception))

    def ipv4_report(self, operation):
        report = dict.fromkeys(lab.IPV4_REPORT_FIELDS, True)
        report.update(version=1, operation=operation, credential_contents_returned=False,
                      reboot_required=False)
        return report

    def ipv4_operation(self, operation, report):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return self.result() if argv[0].endswith('ssh-keyscan') else self.result(json.dumps(report))
        lab.execute(operation, {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': KEY,
                               'GITHUB_ACTIONS': 'true'}, run)
        return calls

    def test_ipv4_operations_use_fixed_sources_and_strict_reports(self):
        for operation in ('ipv4-only-status', 'enable-ipv4-only'):
            with self.subTest(operation=operation):
                report = self.ipv4_report(operation)
                output = io.StringIO()
                with patch('sys.stdout', output):
                    calls = self.ipv4_operation(operation, report)
                argv, options = calls[-1]
                self.assertEqual(argv[-1], '/usr/bin/python3 -I -B -')
                self.assertTrue(options['input'].startswith('IPV4_ONLY_OPERATION = '+repr(operation)+'\n'))
                self.assertTrue(options['input'].endswith((ROOT/'ops/enable_ipv4_only.py').read_text()))
                self.assertEqual('SELFTEST_SOURCE = ' in options['input'], operation == 'enable-ipv4-only')
                self.assertEqual(options['timeout'], 300 if operation == 'enable-ipv4-only' else 65)
                notice = next(line for line in output.getvalue().splitlines()
                              if line.startswith('::notice title=VPN lab '+operation+'::'))
                self.assertEqual(json.loads(unquote(notice.split('::', 2)[2])), report)
                self.assertNotIn('PRIVATE', output.getvalue())

    def test_ipv4_reports_reject_untyped_unknown_and_wrong_operation_values(self):
        base = self.ipv4_report('ipv4-only-status')
        reports = [{**base, 'raw': 'PRIVATE DATA'},
                   {**base, 'kernel_ipv6_disabled': 'PRIVATE DATA'},
                   {**base, 'version': True},
                   {**base, 'operation': 'enable-ipv4-only'},
                   {**base, 'credential_contents_returned': True}]
        for report in reports:
            output = io.StringIO()
            with self.subTest(report=report), patch('sys.stdout', output), self.assertRaises(lab.LabError):
                self.ipv4_operation('ipv4-only-status', report)
            self.assertNotIn('PRIVATE DATA', output.getvalue())
            self.assertNotIn('::notice', output.getvalue())

    def test_ipv4_migration_requires_build_gate_but_status_is_read_only(self):
        workflow = (ROOT/'.github/workflows/lab-admin.yml').read_text()
        gate = next(line for line in workflow.splitlines()
                    if "if: inputs.operation == 'install-foundation'" in line)
        self.assertIn("inputs.operation == 'enable-ipv4-only'", gate)
        self.assertNotIn('ipv4-only-status', gate)

    def test_private_panel_installation_embeds_only_fixed_public_sources(self):
        revision = 'a'*40
        public_der = b'panel public CA fixture'
        public_pem = '-----BEGIN CERTIFICATE-----\n'+base64.b64encode(public_der).decode()+'\n-----END CERTIFICATE-----\n'
        report = {'version': 1, 'source_commit': revision, 'panel_url': 'https://172.27.240.1:8443',
            'web_service_active': True, 'collector_service_active': True, 'history_service_active': True,
            'vpn_runtime_preserved': True, 'firewall_rule_verified': True,
            'vpn_only_listener': True, 'credential_contents_returned': False,
            'ca_certificate_sha256': hashlib.sha256(public_der).hexdigest(),
            'ca_certificate_pem': public_pem, 'leaf_spki_pin': 'sha256//'+'A'*43+'='}
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return self.result() if argv[0].endswith('ssh-keyscan') else self.result(json.dumps(report))
        with patch('sys.stdout', io.StringIO()):
            lab.execute('install-admin-panel', {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': KEY,
                                               'GITHUB_SHA': revision}, run)
        self.assertEqual(calls[-1][1]['timeout'], 360)
        self.assertTrue(calls[-1][1]['input'].startswith('ADMIN_SOURCES = '))
        self.assertIn('SOURCE_REVISION = '+repr(revision), calls[-1][1]['input'])
        self.assertTrue(calls[-1][1]['input'].endswith((ROOT/'ops/install_admin_panel.py').read_text()))
        self.assertNotIn(KEY, calls[-1][1]['input'])
        workflow = (ROOT/'.github/workflows/lab-admin.yml').read_text()
        gate = next(line for line in workflow.splitlines()
                    if "if: inputs.operation == 'install-foundation'" in line)
        self.assertIn("inputs.operation == 'install-admin-panel'", gate)

    def test_panel_report_rejects_secrets_and_wrong_revision_before_printing(self):
        public_der = b'panel public CA fixture'
        public_pem = '-----BEGIN CERTIFICATE-----\n'+base64.b64encode(public_der).decode()+'\n-----END CERTIFICATE-----\n'
        report = {'version': 1, 'source_commit': 'b'*40, 'panel_url': 'https://172.27.240.1:8443',
            'web_service_active': True, 'collector_service_active': True, 'history_service_active': True,
            'vpn_runtime_preserved': True, 'firewall_rule_verified': True,
            'vpn_only_listener': True, 'credential_contents_returned': False,
            'ca_certificate_sha256': hashlib.sha256(public_der).hexdigest(),
            'ca_certificate_pem': public_pem, 'leaf_spki_pin': 'sha256//'+'A'*43+'='}
        for changes in ({}, {'admin_password': 'PRIVATE DATA'}, {'credential_contents_returned': True}):
            def run(argv, **kwargs):
                return self.result() if argv[0].endswith('ssh-keyscan') else self.result(json.dumps({**report, **changes}))
            output = io.StringIO()
            with patch('sys.stdout', output), self.assertRaises(lab.LabError):
                lab.execute('install-admin-panel', {**SETTINGS, 'VPN_LAB_SSH_PRIVATE_KEY': KEY,
                                                   'GITHUB_SHA': 'a'*40}, run)
            self.assertNotIn('PRIVATE DATA', output.getvalue())

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
