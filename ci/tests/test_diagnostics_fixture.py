"""Guard the disposable fixture's baseline precondition and secret-free diagnostics."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import diagnostics_client_smoke as fixture


class DiagnosticsBaselineTests(unittest.TestCase):
    def grant(self, elements):
        return json.dumps({'nftables': [{'set': {'name': 'authorized', 'type': 'ipv4_addr', 'elem': elements}}]})

    def test_baseline_waits_for_real_empty_grant_without_mutation(self):
        with patch.object(fixture, 'command', side_effect=[self.grant(['172.27.240.10']), self.grant([])]) as run, \
             patch.object(fixture.time, 'sleep'):
            fixture.wait_for_idle_authorization()
        self.assertEqual(run.call_count, 2)
        self.assertTrue(all(call.args[0] == ['/usr/sbin/nft', '-j', 'list', 'set', 'inet', 'vpn_lab', 'authorized']
                            for call in run.call_args_list))

    def test_busy_precondition_fails_before_a_namespace_or_firewall_change(self):
        with patch.object(fixture, 'command', return_value=self.grant(['172.27.240.10'])) as run, \
             patch.object(fixture.time, 'monotonic', side_effect=[0, 11]), \
             self.assertRaisesRegex(RuntimeError, 'idle forwarding lease'):
            fixture.wait_for_idle_authorization()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][2], 'list')

    def test_dynamic_element_difference_is_named_without_exposing_values(self):
        before = json.loads(self.grant(['PRIVATE_VALUE']))
        after = json.loads(self.grant([]))
        result = fixture.nft_difference_categories(before, after)
        self.assertEqual(result, ['set_elements'])
        self.assertNotIn('PRIVATE_VALUE', json.dumps(result))

    def test_policy_rule_changes_are_not_filtered_out(self):
        before = {'nftables': [{'rule': {'expr': [{'drop': None}]}}]}
        after = copy.deepcopy(before)
        after['nftables'][0]['rule']['expr'] = [{'accept': None}]
        self.assertEqual(fixture.nft_difference_categories(before, after), ['rules'])

    def test_global_object_order_is_reported_without_weakening_assertions(self):
        before = {'nftables': [{'table': {'name': 'test'}}, {'chain': {'name': 'input'}}]}
        after = {'nftables': list(reversed(before['nftables']))}
        self.assertEqual(fixture.nft_difference_categories(before, after), ['object_order'])
