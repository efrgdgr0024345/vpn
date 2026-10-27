import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import network_setup as network
from security import Refused

POLICY={'server_name':'VPNLabServer'}


class NetworkSetupTests(unittest.TestCase):
    def test_unrelated_firewall_is_preserved_before_dns_or_state_changes(self):
        with patch.object(network,'load_policy',return_value=POLICY), \
                patch.object(network,'service_account',return_value=SimpleNamespace(pw_uid=995)), \
                patch.object(network,'resolver_read',return_value='nameserver 192.0.2.1\n'), \
                patch.object(network.portal_helper,'js',return_value={'nftables':[{'table':{'name':'unrelated'}}]}), \
                patch.object(Path,'exists',return_value=False), \
                patch.object(network,'write_state') as state,patch.object(network,'resolver_write') as dns, \
                patch.object(network.portal_helper,'mutate') as mutate:
            with self.assertRaises(Refused):
                network.prepare()
            state.assert_not_called()
            dns.assert_not_called()
            mutate.assert_not_called()

    def test_resolver_repair_happens_only_after_guard_verification(self):
        operations=[]
        with patch.object(network.portal_helper,'js',return_value={}), \
                patch.object(network.portal_helper,'inspect_guard',side_effect=lambda value:(operations.append('guard') or (False,False))), \
                patch.object(network,'resolver_read',return_value='nameserver 192.0.2.1\n'), \
                patch.object(network,'resolver_write',side_effect=lambda value:operations.append('dns')):
            self.assertFalse(network.verify_during_session())
        self.assertEqual(operations,['guard','dns'])

    def test_failed_guard_check_does_not_rewrite_dns(self):
        with patch.object(network.portal_helper,'js',return_value={}), \
                patch.object(network.portal_helper,'inspect_guard',side_effect=Refused('bad guard')), \
                patch.object(network,'resolver_write') as dns,self.assertRaises(Refused):
            network.verify_during_session()
        dns.assert_not_called()

    def test_restore_requires_no_vpn_and_never_uses_a_broad_flush(self):
        with patch.object(network.portal_helper,'active_openvpn',return_value=True), \
                patch.object(network.portal_helper,'mutate') as mutate,self.assertRaises(Refused):
            network.restore()
        mutate.assert_not_called()

    def test_foreign_resolver_change_blocks_release_of_guard(self):
        state={'policy':POLICY,'vpn_uid':995,'resolver_before':'before'}
        with patch.object(network.portal_helper,'active_openvpn',return_value=False), \
                patch.object(network,'state_read',return_value=state),patch.object(network,'load_policy',return_value=POLICY), \
                patch.object(network,'service_account',return_value=SimpleNamespace(pw_uid=995)), \
                patch.object(network.portal_helper,'js',return_value={}), \
                patch.object(network.portal_helper,'inspect_guard'),patch.object(network,'resolver_read',return_value='foreign'), \
                patch.object(network.portal_helper,'mutate') as mutate,self.assertRaises(Refused):
            network.restore()
        mutate.assert_not_called()
