"""Pure mocked tests: no host networking or firewall changes."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import portal_helper as h
from firewall_policy import render_batch

POLICY = json.loads((Path(__file__).parents[1] / 'policy.example.json').read_text())


def baseline():
    # Independently authored JSON; not derived from the implementation's allowlist.
    return json.loads((Path(__file__).parent / 'fixtures' / 'guard.json').read_text())


def owned(active=False):
    doc = baseline()
    value = {'family': 'inet', 'table': 'vpn_guard', 'name': h.SET,
             'type': 'ifname', 'flags': ['timeout'], 'timeout': 30000}
    if active:
        value['elem'] = [{'elem': {'val': 'wlan0', 'timeout': 30000, 'expires': 25000}}]
    doc['nftables'] += [{'set': value}, {'rule': {'family': 'inet', 'table': 'vpn_guard',
                       'chain': 'output', 'expr': h.portal_expr(), 'comment': h.COMMENT}}]
    return doc


class PolicyFixture(unittest.TestCase):
    def setUp(self):
        for name, value in (('load_policy', POLICY), ('service_account', SimpleNamespace(pw_uid=995))):
            patcher = patch.object(h, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)


class GuardTests(PolicyFixture):
    def test_independent_baseline_and_generated_policy_agree(self):
        self.assertEqual(h.inspect_guard(baseline()), (False, False))
        rendered = {'nftables': [x['add'] for x in render_batch(POLICY, 995)['nftables']]}
        self.assertEqual(rendered, baseline())

    def test_missing_inbound_filter_refused(self):
        doc = baseline()
        doc['nftables'] = [x for x in doc['nftables'] if x.get('chain', {}).get('name') != 'input'
                          and x.get('rule', {}).get('chain') != 'input']
        with self.assertRaises(h.Refused):
            h.inspect_guard(doc)

    def test_kernel_set_order_does_not_change_policy_meaning(self):
        doc = baseline()
        for item in doc['nftables']:
            for statement in item.get('rule', {}).get('expr', []):
                right = statement.get('match', {}).get('right')
                if isinstance(right, dict) and 'set' in right:
                    right['set'].reverse()
        self.assertEqual(h.inspect_guard(doc), (False, False))

    def test_kernel_readback_omits_redundant_ipv4_and_uses_state_equality(self):
        doc = baseline()
        for item in doc['nftables']:
            expr = item.get('rule', {}).get('expr', [])
            if any(part.get('match', {}).get('left') in (
                    h.payload('ip', 'saddr'), h.payload('ip', 'daddr')) for part in expr):
                expr[:] = [part for part in expr if part != h.match(h.meta('nfproto'), 'ipv4')]
            for part in expr:
                if part.get('match', {}).get('left') == {'ct': {'key': 'state'}}:
                    part['match']['op'] = '=='
        self.assertEqual(h.inspect_guard(doc), (False, False))

    def test_address_family_normalization_does_not_allow_different_or_negated_addresses(self):
        for replacement in (h.payload('ip6', 'daddr'), h.payload('udp', 'dport')):
            doc = baseline()
            for part in doc['nftables'][-2]['rule']['expr']:
                if part.get('match', {}).get('left') == h.payload('ip', 'daddr'):
                    part['match']['left'] = replacement
            with self.assertRaises(h.Refused):
                h.inspect_guard(doc)
        doc = baseline()
        for part in doc['nftables'][-2]['rule']['expr']:
            if part.get('match', {}).get('left') == h.payload('ip', 'daddr'):
                part['match']['op'] = '!='
        with self.assertRaises(h.Refused):
            h.inspect_guard(doc)

    def test_ipv4_guard_is_not_erased_without_a_positive_ipv4_address_match(self):
        for right in ('2001:db8::1', 'not-an-address', {'set': []}, {'set': '192.0.2.10'}):
            expression = [h.match(h.meta('nfproto'), 'ipv4'),
                          h.match(h.payload('ip', 'daddr'), right)]
            self.assertIn(h.match(h.meta('nfproto'), 'ipv4'), h.canonical_rule(expression))

    def test_ct_inequality_is_not_normalized_to_membership(self):
        doc = baseline()
        for item in doc['nftables']:
            for part in item.get('rule', {}).get('expr', []):
                if part.get('match', {}).get('left') == {'ct': {'key': 'state'}}:
                    part['match']['op'] = '!='
        with self.assertRaises(h.Refused):
            h.inspect_guard(doc)

    def test_owned_empty_and_active(self):
        self.assertEqual(h.inspect_guard(owned()), (True, False))
        self.assertEqual(h.inspect_guard(owned(True)), (True, True))

    def test_missing_guard_and_extra_table_refused(self):
        for doc in ({'nftables': []}, {'nftables': baseline()['nftables'] + [
                {'table': {'family': 'ip', 'name': 'unrelated'}}]}):
            with self.assertRaises(h.Refused):
                h.inspect_guard(doc)

    def test_added_ipv6_established_and_unconditional_output_bypasses_refused(self):
        for expr in ([h.match(h.meta('nfproto'), 'ipv6'), {'accept': None}],
                     [h.match({'ct': {'key': 'state'}}, 'established'), {'accept': None}],
                     [{'accept': None}]):
            doc = baseline()
            doc['nftables'].append({'rule': {'family': 'inet', 'table': 'vpn_guard', 'chain': 'output', 'expr': expr}})
            with self.assertRaises(h.Refused):
                h.inspect_guard(doc)

    def test_endpoint_uid_and_dhcp_destination_restrictions_required(self):
        # nft may omit redundant nfproto; the positive IPv4 address selector
        # and ownership constraints must remain present.
        for key in ('skuid', 'daddr'):
            doc = baseline()
            rule = doc['nftables'][-1]['rule']
            rule['expr'] = [x for x in rule['expr'] if
                            x.get('match', {}).get('left') not in (h.meta(key), h.payload('ip', key))]
            with self.assertRaises(h.Refused):
                h.inspect_guard(doc)
        doc = baseline()
        rule = doc['nftables'][-2]['rule']
        rule['expr'] = [x for x in rule['expr'] if x.get('match', {}).get('left') != h.meta('skuid')]
        with self.assertRaises(h.Refused):
            h.inspect_guard(doc)

    def test_tampered_set_refused(self):
        for key, value in [('timeout', 60000), ('type', 'ipv4_addr'), ('flags', [])]:
            doc = owned()
            doc['nftables'][-2]['set'][key] = value
            with self.assertRaises(h.Refused):
                h.inspect_guard(doc)

    def test_unknown_element_and_missing_owner_rule(self):
        doc = owned(True)
        doc['nftables'][-2]['set']['elem'][0]['elem']['val'] = 'eth0'
        with self.assertRaises(h.Refused):
            h.inspect_guard(doc)
        doc = owned()
        doc['nftables'].pop()
        with self.assertRaises(h.Refused):
            h.inspect_guard(doc)


class ActionTests(PolicyFixture):
    def setUp(self):
        super().setUp()
        patcher = patch.object(h.os, 'geteuid', return_value=0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_open_is_rejected_before_any_system_command(self):
        for action in ('open', 'unknown'):
            with patch.object(h, 'js') as js, patch.object(h, 'run') as run:
                with self.assertRaises(h.Refused):
                    h.act(action)
                js.assert_not_called()
                run.assert_not_called()

    def test_close_scope_and_readback(self):
        with patch.object(h, 'js', side_effect=[owned(True), owned()]), patch.object(h, 'run') as run:
            self.assertEqual(h.act('close')['state'], 'closed')
        run.assert_called_once_with([h.NFT, '-f', '-'], 'flush set inet vpn_guard portal_window\n')

    def test_close_unverified_is_unknown(self):
        with patch.object(h, 'js', return_value=owned(True)), patch.object(h, 'run'):
            with self.assertRaises(h.MutationUnknown):
                h.act('close')

    def test_close_absent_is_noop(self):
        with patch.object(h, 'js', return_value=baseline()), patch.object(h, 'run') as run:
            h.act('close')
        run.assert_not_called()

    def test_mutation_failure_is_unknown(self):
        with patch.object(h, 'run', side_effect=h.Refused('timeout')):
            with self.assertRaises(h.MutationUnknown):
                h.mutate('flush set inet vpn_guard portal_window\n')

    def test_nonroot_refused(self):
        with patch.object(h.os, 'geteuid', return_value=1000), patch.object(h, 'js') as js:
            with self.assertRaises(h.Refused):
                h.act('close')
        js.assert_not_called()


class NetworkTests(unittest.TestCase):
    def check(self, links=None, routes=None):
        links = links if links is not None else [{'ifname': 'lo'}, {'ifname': 'wlan0', 'flags': ['UP']}]
        routes = routes if routes is not None else [{'dst': 'default', 'dev': 'wlan0', 'gateway': '192.0.2.1'}]
        with patch.object(h, 'load_policy', return_value=POLICY), \
                patch.object(h, 'active_openvpn', return_value=False), \
                patch.object(h, 'js', side_effect=[links, routes, []]):
            h.check_network()

    def test_good_network(self):
        self.check()

    def test_active_vpn(self):
        with patch.object(h, 'load_policy', return_value=POLICY), patch.object(h, 'active_openvpn', return_value=True), patch.object(h, 'js') as js:
            with self.assertRaises(h.Refused):
                h.check_network()
        js.assert_not_called()

    def test_tunnel_and_malformed_state_refused(self):
        for links in ([None], [{'ifname': 'wlan0', 'flags': ['UP']}, {'ifname': 'tun0'}],
                      [{'ifname': 'wlan0', 'flags': ['UP']}, {'ifname': 'other', 'linkinfo': {'info_kind': 'tun'}}]):
            with self.assertRaises(h.Refused):
                self.check(links=links)

    def test_tunnel_route_and_wrong_default_refused(self):
        for routes in ([{'dst': 'default', 'dev': 'tun0', 'gateway': '192.0.2.1'}],
                       [{'dst': 'default', 'dev': 'eth0', 'gateway': '192.0.2.1'}]):
            with self.assertRaises(h.Refused):
                self.check(routes=routes)
