import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ops'))
import session_broker as broker

DEVICES = {
    'kali': {'cn': 'vpn-lab-client', 'sha256': 'a'*64, 'address': '172.27.240.10', 'enabled': True},
    'iphone': {'cn': 'vpn-lab-iphone', 'sha256': 'b'*64, 'address': '172.27.240.11', 'enabled': True},
}


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.commands, self.grants, self.clears = [], [], []
        self.devices = copy.deepcopy(DEVICES)
        self.policy = broker.Policy(self.devices, self.commands.append, self.grants.append,
                                    lambda: self.clears.append(True), lambda: self.now)

    def connect(self, cid=1, device='kali', **changes):
        record = self.devices[device]
        environment = {'common_name': record['cn'], 'username': 'vpn-lab-client',
                       'tls_digest_sha256_0': record['sha256'], 'session_state': 'Initial'}
        environment.update(changes)
        self.policy.event('CONNECT', cid, 1, environment)

    def establish(self, cid=1, address='172.27.240.10'):
        self.policy.event('ESTABLISHED', cid, None, {'ifconfig_pool_remote_ip': address})

    def test_no_forwarding_until_established_after_password_and_cert_auth(self):
        self.connect()
        self.assertFalse(self.grants)
        self.establish()
        self.assertEqual(self.grants, ['172.27.240.10'])

    def test_stolen_password_unapproved_pin_wrong_name_and_tokens_cannot_enter(self):
        for changes in ({'tls_digest_sha256_0': 'c'*64}, {'common_name': 'vpn-lab-iphone'},
                        {'session_state': 'Authenticated'}, {'session_state': 'Invalid'},
                        {'session_state': 'Expired'}, {'session_state': 'AuthenticatedEmptyUser'},
                        {'username': 'root'}):
            self.connect(**changes)
            self.assertIsNone(self.policy.pending)
            self.assertTrue(self.commands[-1].startswith('client-deny'))
        self.assertFalse(self.grants)

    def test_simultaneous_pending_devices_never_both_reserve(self):
        self.connect()
        self.connect(cid=2, device='iphone')
        self.assertEqual(self.policy.pending['cid'], 1)
        self.assertTrue(self.commands[-1].startswith('client-deny 2 '))
        self.establish()
        self.establish(2, '172.27.240.11')
        self.assertEqual(self.grants, ['172.27.240.10'])
        self.assertEqual(self.commands[-1], 'client-kill 2 "AUTH_FAILED,SESSION"\n')

    def test_active_owner_cannot_be_displaced_or_cleared_by_unrelated_disconnect(self):
        self.connect()
        self.establish()
        self.connect(cid=2, device='iphone')
        self.policy.event('DISCONNECT', 2, None, {})
        self.assertEqual(self.policy.owner['cid'], 1)
        self.assertFalse(self.clears)

    def test_transfer_requires_confirmed_disconnect_and_clears_old_first(self):
        self.connect()
        self.establish()
        self.policy.event('DISCONNECT', 1, None, {})
        self.assertEqual(self.clears, [True])
        self.connect(cid=2, device='iphone')
        self.establish(2, '172.27.240.11')
        self.assertEqual(self.grants, ['172.27.240.10', '172.27.240.11'])
        self.policy.event('DISCONNECT', 1, None, {})
        self.assertEqual(len(self.clears), 1)

    def test_unadmitted_token_reconnect_or_wrong_ip_never_gets_forwarding(self):
        self.establish()
        self.assertFalse(self.grants)
        self.connect(cid=2)
        self.establish(2, '172.27.240.11')
        self.assertFalse(self.grants)

    def test_only_current_daemon_cid_can_refresh_lease(self):
        self.connect()
        self.establish()
        self.policy.event('LIVE', 2, None, {})
        self.assertEqual(len(self.grants), 1)
        self.now = 5
        self.policy.event('LIVE', 1, None, {})
        self.assertEqual(len(self.grants), 2)

    def test_heartbeat_expiry_denies_packets_before_kill_and_blocks_replacement(self):
        self.connect()
        self.establish()
        self.now = 13
        self.policy.event('LIVE', 1, None, {})
        self.assertEqual(len(self.grants), 1)
        self.assertTrue(self.clears)
        self.assertEqual(self.commands[-1], 'client-kill 1 "HALT,VPN authorization ended"\n')
        self.connect(cid=2, device='iphone')
        self.assertTrue(self.commands[-1].startswith('client-deny'))

    def test_revocation_or_identity_replacement_revokes_active_owner(self):
        for key, value in (('enabled', False), ('sha256', 'c'*64), ('cn', 'replacement')):
            self.setUp()
            self.connect()
            self.establish()
            self.devices['kali'][key] = value
            self.policy.tick(self.devices)
            self.assertTrue(self.policy.stopping)
            self.assertTrue(self.clears)

    def test_expired_pending_and_late_established_never_authorize(self):
        self.connect()
        self.now = 16
        self.establish()
        self.assertFalse(self.grants)

    def test_wall_clock_cannot_extend_monotonic_session_limit(self):
        self.connect()
        self.establish()
        self.now = broker.SESSION_SECONDS
        self.policy.event('LIVE', 1, None, {})
        self.assertTrue(self.policy.stopping)

    def test_invalid_registry_and_duplicate_pins_addresses_and_names_are_rejected(self):
        self.assertEqual(broker.registry(json.dumps(DEVICES)), DEVICES)
        for key in ('sha256', 'address', 'cn'):
            devices = copy.deepcopy(DEVICES)
            devices['iphone'][key] = devices['kali'][key]
            with self.assertRaises(broker.BrokerError):
                broker.registry(json.dumps(devices))
        for address in ('127.0.0.1', '172.27.240.1', '172.27.240.255'):
            devices = copy.deepcopy(DEVICES)
            devices['kali']['address'] = address
            with self.assertRaises(broker.BrokerError):
                broker.registry(json.dumps(devices))

    def test_parser_drops_secrets_and_binds_only_atomic_daemon_events(self):
        parser = broker.Parser()
        for line in ('>CLIENT:CONNECT,10,2', '>CLIENT:ENV,password=SECRET',
                     '>CLIENT:ENV,session_id=SECRET', '>CLIENT:ENV,common_name=vpn-lab-client'):
            self.assertIsNone(parser.feed(line))
        event = parser.feed('>CLIENT:ENV,END')
        self.assertEqual(event, ('CONNECT', 10, 2, {'common_name': 'vpn-lab-client'}))
        self.assertNotIn('SECRET', repr(event))

    def test_malformed_oversized_and_duplicate_identity_events_fail_closed(self):
        for lines in (['>CLIENT:CONNECT,1;bad,2'], ['>CLIENT:ENV,END'],
                      ['>CLIENT:CONNECT,1,2', '>CLIENT:ENV,username=a', '>CLIENT:ENV,username=b'],
                      ['>BYTECOUNT_CLI:1,2,bad'], ['x'*16385]):
            parser = broker.Parser()
            with self.assertRaises(broker.BrokerError):
                for line in lines:
                    parser.feed(line)


if __name__ == '__main__':
    unittest.main()
