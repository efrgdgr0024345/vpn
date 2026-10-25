import json
import subprocess
import unittest
import tempfile
from unittest.mock import patch
import app
import launch_vpn
import portal_terminal

class DashboardTests(unittest.TestCase):
    def fixtures(self):
        return {key: app.Result(False, error='denied') for key in app.COMMANDS}
    def test_permission_denied_never_secure(self):
        result = app.summarize(self.fixtures())
        self.assertIn('UNKNOWN', result['Firewall'])
        self.assertIn('UNKNOWN', result['Tunnel'])
    def test_tunnel_not_health(self):
        data = self.fixtures()
        data['links'] = app.Result(True, '[{"ifname":"tun0"}]')
        self.assertIn('health unverified', app.summarize(data)['Tunnel'])
    def test_absent_and_malformed(self):
        data = self.fixtures()
        data['links'] = app.Result(True, '[]')
        self.assertIn('NOT FOUND', app.summarize(data)['Tunnel'])
        for raw in ('bad json', '{}', 'null'):
            data['links'] = app.Result(True, raw)
            self.assertIn('UNKNOWN', app.summarize(data)['Tunnel'])
    def test_routes_not_leak_claim(self):
        data = self.fixtures()
        data['routes'] = app.Result(True, json.dumps([{'dst': x, 'dev': 'tun0'} for x in ('0.0.0.0/1', '128.0.0.0/1')]))
        self.assertIn('no leak test', app.summarize(data)['Routes'])
    def test_readable_firewall_not_audited(self):
        data = self.fixtures()
        data['firewall'] = app.Result(True, '{"nftables":[]}')
        self.assertIn('NOT audited', app.summarize(data)['Firewall'])
    def test_redaction(self):
        s = app.redact('alice laptop 192.168.1.1/24 aa:bb:cc:dd:ee:ff 2001:db8::1 fe80::1%wlan0\nSSID=SecretWiFi\npassword=bad', ('alice', 'laptop'))
        for secret in ('alice', 'laptop', '192.168', 'aa:bb', '2001:db8', 'fe80', 'SecretWiFi', 'bad'):
            self.assertNotIn(secret, s)
    def test_raw_identifiers_not_exported(self):
        data = self.fixtures()
        data['nm'] = app.Result(True, 'vpn:secret-device\nwifi:private-device')
        data['dns'] = app.Result(True, 'IP4.DNS[1]:10.1.2.3')
        data['services'] = app.Result(True, 'openvpn-secret.service loaded active secret')
        log = app.export_log(app.summarize(data))
        for secret in ('secret-device', 'private-device', '10.1.2.3', 'openvpn-secret'):
            self.assertNotIn(secret, log)
    @patch('app.bounded_run')
    def test_fixed_argv_timeout(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, '', 'SECRET')
        result = app.run_command('firewall')
        self.assertFalse(result.ok)
        self.assertNotIn('SECRET', result.error)
        args, kwargs = run.call_args
        self.assertEqual(args[0], app.COMMANDS['firewall'])
        self.assertNotIn('shell', kwargs)
        self.assertEqual(kwargs['timeout'], 6)
    @patch('app.bounded_run', side_effect=subprocess.TimeoutExpired('ip', 6))
    def test_timeout(self, run):
        self.assertFalse(app.run_command('links').ok)
    @patch('app.bounded_run', side_effect=FileNotFoundError())
    def test_missing_tool(self, run):
        self.assertIn('not installed', app.run_command('nm').error)
    def test_collection_mock_only(self):
        called = []
        def runner(key):
            called.append(key)
            return app.Result(False)
        self.assertIn('Firewall', app.collect(runner))
        self.assertEqual(set(called), set(app.COMMANDS))
    @patch('security.trusted_path')
    def test_launcher_exact_argv_no_shell(self, trust):
        self.assertEqual(launch_vpn.argv(), [
            '/usr/bin/sudo', '--', '/usr/bin/python3', '-I', '-B',
            '/usr/local/libexec/vpn-desk/privileged.py', 'connect'])
        self.assertEqual(trust.call_count, 5)
    @patch('security.trusted_path', side_effect=FileNotFoundError())
    def test_launcher_missing_installation_no_fallback(self, trust):
        with self.assertRaises(FileNotFoundError):
            launch_vpn.argv()

class LauncherSafetyTests(unittest.TestCase):
    @patch('launch_vpn.bounded_run')
    def test_existing_process(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, '123\n', '')
        self.assertTrue(launch_vpn.existing_openvpn())
        self.assertEqual(run.call_args.args[0], ['/usr/bin/ps', '-C', 'openvpn', '-o', 'pid='])
    @patch('launch_vpn.bounded_run')
    def test_no_process(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, '', '')
        self.assertFalse(launch_vpn.existing_openvpn())
    @patch('launch_vpn.bounded_run')
    def test_unknown_process_check(self, run):
        for code in (0, 2):
            run.return_value = subprocess.CompletedProcess([], code, '', '')
            with self.assertRaises(ValueError):
                launch_vpn.existing_openvpn()
    def test_lock_blocks_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('launch_vpn.tempfile.gettempdir', return_value=directory):
                fd = launch_vpn.session_lock()
                try:
                    with self.assertRaises(ValueError):
                        launch_vpn.session_lock()
                finally:
                    launch_vpn.os.close(fd)
                fd = launch_vpn.session_lock()
                launch_vpn.os.close(fd)

class PortalTerminalTests(unittest.TestCase):
    @patch('security.trusted_path')
    def test_action_allowlist(self, trust):
        for action in ('close', 'status'):
            command = portal_terminal.command(action)
            self.assertEqual(command[0], '/usr/bin/sudo')
            self.assertEqual(command[-1], 'portal-' + action)
            self.assertEqual(command[-2], '/usr/local/libexec/vpn-desk/privileged.py')
        for action in ('open', 'open; echo unsafe'):
            with self.assertRaises(ValueError):
                portal_terminal.command(action)

if __name__ == '__main__':
    unittest.main()
