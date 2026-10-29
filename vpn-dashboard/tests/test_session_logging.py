import copy
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import session_channel as channel
import session_ui


class LoggingTests(unittest.TestCase):
    def test_known_endpoint_versions_and_ciphers_are_extracted_without_raw_text(self):
        lines = ('2026-10-29 01:00:00.123456 OpenVPN 2.7.3 PLATFORM_SECRET',
                 '2026-10-29 01:00:01 library versions: OpenSSL 3.6.2 PRIVATE_OTHER_TEXT',
                 '2026-10-29 01:00:02 UDPv4 link remote: [AF_INET]192.0.2.10:1194',
                 '2026-10-29 01:00:03 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, PRIVATE_OTHER_TEXT',
                 "2026-10-29 01:00:04 Data Channel: cipher 'AES-256-GCM', peer-id: 0",
                 '2026-10-29 01:00:05 TUN/TAP device tun0 opened')
        events = channel.Events()
        for line in lines:
            events.set_details(channel.parse_details(line))
            code = channel.classify(line)
            if code:
                events.add(code)
        details = events.snapshot()['details']
        self.assertEqual(details['server_ipv4'], '192.0.2.10')
        self.assertEqual(details['server_port'], 1194)
        self.assertEqual(details['openvpn_version'], '2.7.3')
        self.assertEqual(details['tls_version'], 'TLSv1.3')
        self.assertEqual(details['data_cipher'], 'AES-256-GCM')
        self.assertNotIn('SECRET', channel.format_events(events.snapshot()))
        self.assertNotIn('PRIVATE_OTHER_TEXT', json.dumps(events.snapshot()))

    def test_secret_lines_and_fake_cipher_values_never_enter_details(self):
        for line in ('PUSH_REPLY,auth-token SESS_ID_AT_SECRET',
                     'UDPv4 link remote: [AF_INET]192.0.2.10:1194 password=SECRET',
                     'Control Channel: TLSv1.3, cipher TLSv1.3 SECRET,',
                     "Data Channel: cipher 'SECRET', peer-id: 0",
                     'UDPv4 link remote: [AF_INET]invalid:1194',
                     'UDPv4 link remote: [AF_INET]192.0.2.10:99999'):
            self.assertEqual(channel.parse_details(line), {})

    def test_diagnostic_schema_rejects_unknown_fields_controls_and_bad_types(self):
        for details in ({'password': 'SECRET'}, {'server_ipv4': '192.0.2.10\nSECRET'},
                        {'local_port': True}, {'server_port': 65536}, {'wifi_interface': '--bad'},
                        {'expected_tls_name': 'good\x1bSECRET'}, {'split_routes_verified': 'yes'},
                        {'data_cipher': 'UNKNOWN'}, {'openvpn_version': '2.7.3 SECRET'}):
            with self.assertRaises(channel.ChannelError):
                channel.validate_details(details)

    def test_timing_and_failure_reason_survive_stopping(self):
        with patch.object(channel.time, 'monotonic', return_value=100):
            events = channel.Events()
        with patch.object(channel.time, 'monotonic', return_value=102):
            events.add('transport_start')
        self.assertEqual(events.snapshot()['events'][0]['elapsed_ms'], 2000)
        events.add('server_timeout')
        events.add('stopping')
        events.add('stopped')
        self.assertEqual(events.snapshot()['state'], 'error')
        self.assertIn('No VPN server reply', channel.format_events(events.snapshot()))
        invalid = copy.deepcopy(events.snapshot())
        invalid['events'][0]['elapsed_ms'] = True
        with self.assertRaises(channel.ChannelError):
            channel.validate_snapshot(invalid)

    def test_private_history_is_bounded_validated_and_available_after_session_exit(self):
        owner = os.getuid() or 1000
        real_fstat = os.fstat
        def root_metadata(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink)
        acls = {}
        def set_acl(target, name, value):
            acls[name] = value
            (os.fchmod if isinstance(target, int) else os.chmod)(target, 0o640)
        with tempfile.TemporaryDirectory() as directory, patch.object(channel, 'HISTORY', Path(directory)), \
                patch.object(channel, 'protected_parent'), patch.object(channel.os, 'geteuid', return_value=0), \
                patch.object(channel.os, 'getuid', return_value=owner), \
                patch.object(channel.os, 'fstat', side_effect=root_metadata), \
                patch.object(channel.os, 'setxattr', side_effect=set_acl), \
                patch.object(channel.os, 'getxattr', side_effect=lambda target, name: acls[name]):
            events = channel.Events()
            events.set_details({'server_ipv4': '192.0.2.10', 'server_port': 1194})
            events.add('server_timeout')
            channel.save_last(owner, events.snapshot(), -15)
            path = Path(directory)/(str(owner)+'.json')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            record = channel.read_last()
            self.assertEqual(record['exit_status'], -15)
            self.assertEqual(record['snapshot']['state'], 'error')
            path.chmod(0o644)
            with self.assertRaises(channel.ChannelError):
                channel.read_last()
            os.setxattr(path, 'system.posix_acl_access', channel.history_acl(owner))
            record['snapshot']['details']['password'] = 'SECRET'
            path.write_text(json.dumps(record))
            with self.assertRaises(channel.ChannelError):
                channel.read_last()

    def test_live_report_is_preferred_and_saved_report_is_explicitly_historical(self):
        events = channel.Events()
        events.set_details({'server_ipv4': '192.0.2.10', 'server_port': 1194})
        events.add('server_timeout')
        snapshot = events.snapshot()
        with patch.object(channel, 'request', return_value=snapshot), patch.object(channel, 'read_last') as read:
            kind, _, text = session_ui.session_report()
            self.assertEqual(kind, 'live')
            read.assert_not_called()
            self.assertIn('192.0.2.10', text)
        with patch.object(channel, 'request', side_effect=FileNotFoundError), \
                patch.object(channel, 'read_last', return_value={'snapshot': snapshot, 'exit_status': -15}):
            kind, state, text = session_ui.session_report()
            self.assertEqual((kind, state), ('saved', 'error'))
            self.assertIn('read-only to the desktop user', text)
            self.assertIn('OpenVPN exit status: -15', text)
            self.assertIn('No VPN server reply', text)

    def test_corrupt_or_absent_history_never_becomes_a_success_report(self):
        with patch.object(channel, 'request', side_effect=FileNotFoundError), \
                patch.object(channel, 'read_last', side_effect=channel.ChannelError('fixture')):
            self.assertEqual(session_ui.session_report(), ('unavailable', 'unavailable', None))

    def test_kernel_flag_requires_a_protected_exact_value(self):
        with tempfile.TemporaryDirectory() as directory:
            flag=Path(directory)/'disable'
            metadata=SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o444)
            with patch.object(channel,'IPV6_FLAG',flag),patch.object(channel,'protected_parent'), \
                    patch.object(channel.os,'fstat',return_value=metadata):
                for value,expected in (('1\n',True),('Y\n',True),('0\n',False),('1\nextra',False)):
                    flag.write_text(value)
                    self.assertEqual(channel.kernel_ipv6_disabled(),expected)
