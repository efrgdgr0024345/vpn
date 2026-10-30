import copy
import io
import json
from pathlib import Path
import socket
import struct
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ops'))
import server_diagnostics as diagnostics


def services():
    return '\n\n'.join('Id='+unit+'\nActiveState=active\nSubState=running\nNRestarts=0\nResult=success'
                       for unit in diagnostics.UNITS)+'\n'


def tunnel():
    return [{'ifname': 'tun-lab', 'flags': ['UP'], 'linkinfo': {'info_kind': 'tun'},
             'addr_info': [{'family': 'inet', 'local': '172.27.240.1', 'prefixlen': 24}]}]


def firewall():
    return {'nftables': [
        {'set': {'family': 'inet', 'table': 'vpn_lab', 'name': 'authorized', 'type': 'ipv4_addr',
                 'elem': [{'elem': {'val': '172.27.240.10', 'expires': 17000, 'timeout': 20000}}]}},
        *({'rule': {'family': 'inet', 'table': 'vpn_lab', 'chain': 'input', 'comment': comment,
                    'expr': [{'counter': {'packets': number, 'bytes': number*60}}]}}
          for number, comment in enumerate(diagnostics.COMMENTS, 1))]}


def dns_reply(*, flags=0x8180, identifier=1234, answer=None):
    if answer is None:
        answer = b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 60, 4)+b'abcd'
    return struct.pack('!6H', identifier, flags, 1, int(bool(answer)), 0, 0)+diagnostics.QUESTION+answer


def report():
    authorization, counters = diagnostics.parse_firewall(json.dumps(firewall()))
    return {'version': 1, 'server_utc': '2026-10-30T00:00:00+00:00', 'ntp_synchronized': True,
            'services': diagnostics.parse_services(services()), 'tunnel': diagnostics.parse_tunnel(json.dumps(tunnel())),
            'dns_listeners': [{'protocol': protocol, 'address': '172.27.240.1', 'port': 53}
                              for protocol in ('tcp', 'udp')],
            'authorization': authorization, 'input_counters': counters,
            'dns_probe': {'status': 'ok', 'rcode': 0, 'answer_count': 1, 'elapsed_ms': 1}}


class DiagnosticsParsingTests(unittest.TestCase):
    def test_services_are_fixed_units_and_unknown_values_never_become_free_text(self):
        result = diagnostics.parse_services(services())
        self.assertEqual([item['unit'] for item in result], list(diagnostics.UNITS))
        self.assertTrue(all(item['active_state'] == 'active' for item in result))
        for text in (None, services()[:-15], services()+'Environment=PRIVATE\n',
                     services().replace('Id=unbound.service', 'Id=PRIVATE'),
                     services().replace('ActiveState=active', 'ActiveState=PRIVATE')):
            result = diagnostics.parse_services(text)
            self.assertNotIn('PRIVATE', json.dumps(result))

    def test_tunnel_only_reports_fixed_interface_metadata_and_canonical_ipv4(self):
        data = tunnel()+[{'ifname': 'PRIVATE', 'private_key': 'PRIVATE'}]
        value = diagnostics.parse_tunnel(json.dumps(data))
        self.assertEqual(value, {'present': True, 'kind': 'tun', 'up': True, 'ipv4': ['172.27.240.1/24']})
        for text in ('truncated{', None, '{}', '[1]', json.dumps([{**tunnel()[0], 'addr_info': ['PRIVATE']}])):
            self.assertIsNone(diagnostics.parse_tunnel(text)['present'])
        self.assertFalse(diagnostics.parse_tunnel('[]')['present'])
        data = tunnel()
        data[0]['linkinfo']['info_kind'] = ['PRIVATE']
        self.assertEqual(diagnostics.parse_tunnel(json.dumps(data))['kind'], 'unknown')

    def test_listeners_report_only_dns_addresses_and_never_process_or_other_port_data(self):
        text = ('udp UNCONN 0 0 172.27.240.1:53 0.0.0.0:*\n'
                'tcp LISTEN 0 128 [::1]:53 [::]:*\n'
                'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* PRIVATE\n')
        values = diagnostics.parse_listeners(text)
        self.assertEqual(len(values), 2)
        self.assertEqual({item['address'] for item in values}, {'172.27.240.1', '::1'})
        self.assertNotIn('PRIVATE', json.dumps(values))
        self.assertIsNone(diagnostics.parse_listeners('PRIVATE'))
        self.assertIsNone(diagnostics.parse_listeners('udp UNCONN 0 0 PRIVATE:53 0.0.0.0:*'))
        self.assertEqual(diagnostics.parse_listeners(''), [])

    def test_authorization_expiry_uses_numeric_nft_json_milliseconds_and_fixed_counters(self):
        authorization, counters = diagnostics.parse_firewall(json.dumps(firewall()))
        self.assertEqual(authorization, {'element_count': 1, 'addresses': [{'ipv4': '172.27.240.10', 'expires_ms': 17000}]})
        self.assertEqual(counters['vpn-lab-private-dns'], {'packets': 1, 'bytes': 60})
        data = firewall()
        data['nftables'][0]['set'].pop('elem')
        self.assertEqual(diagnostics.parse_firewall(json.dumps(data))[0], {'element_count': 0, 'addresses': []})

    def test_malformed_or_extra_lease_and_counter_fields_do_not_leak_private_data(self):
        for elem in ([{'elem': {'val': 'PRIVATE', 'expires': 1}}],
                     [{'elem': {'val': '172.27.240.10', 'expires': 'PRIVATE'}}],
                     ['172.27.240.10', '172.27.240.11'], ['10.0.0.1']):
            data = firewall()
            data['nftables'][0]['set']['elem'] = elem
            authorization, counters = diagnostics.parse_firewall(json.dumps(data))
            self.assertIsNone(authorization)
            self.assertNotIn('PRIVATE', json.dumps(counters))
        data = firewall()
        data['nftables'][1]['rule']['expr'][0]['counter']['bytes'] = 'PRIVATE'
        data['nftables'].append({'rule': {'comment': 'PRIVATE', 'expr': [{'PRIVATE': 'PRIVATE'}]}})
        authorization, counters = diagnostics.parse_firewall(json.dumps(data))
        self.assertIsNone(counters['vpn-lab-private-dns'])
        self.assertNotIn('PRIVATE', json.dumps([authorization, counters]))
        self.assertEqual(diagnostics.parse_firewall('{PRIVATE'), (None, {name: None for name in diagnostics.COMMENTS}))


class DNSProbeTests(unittest.TestCase):
    def test_fixed_dns_answer_is_validated_and_errors_are_typed(self):
        self.assertEqual(diagnostics.parse_dns(dns_reply(), 1234), ('ok', 0, 1))
        for flags, status, rcode in ((0x8182, 'servfail', 2), (0x8185, 'refused', 5),
                                     (0x8183, 'rcode_error', 3), (0x8380, 'truncated', 0)):
            self.assertEqual(diagnostics.parse_dns(dns_reply(flags=flags, answer=b''), 1234), (status, rcode, None))
        self.assertEqual(diagnostics.parse_dns(dns_reply(answer=b''), 1234), ('no_answer', 0, 0))
        for packet in (dns_reply()[:-1], dns_reply()+b'PRIVATE', dns_reply(identifier=1),
                       dns_reply(flags=0x0180), dns_reply(flags=0x8980), b'x'*4097,
                       dns_reply(answer=b'\xc0\xff'+struct.pack('!HHIH', 1, 1, 60, 4)+b'abcd')):
            self.assertEqual(diagnostics.parse_dns(packet, 1234), ('invalid', None, None))

    def test_no_local_tunnel_means_no_query_and_no_default_route_fallback(self):
        for value in ({'present': False, 'up': None, 'kind': None, 'ipv4': []},
                      {'present': True, 'up': False, 'kind': 'tun', 'ipv4': ['172.27.240.1/24']},
                      {'present': True, 'up': True, 'kind': 'tun', 'ipv4': ['172.27.240.10/24']}):
            with patch.object(diagnostics.socket, 'socket') as factory:
                self.assertEqual(diagnostics.probe_dns(value)['status'], 'not_attempted')
            factory.assert_not_called()

    def test_local_query_is_bound_to_loopback_and_source_with_no_fallback(self):
        for reply, status in (((dns_reply(), (diagnostics.DNS, 53)), 'ok'),
                               (socket.timeout(), 'timeout'), (OSError(), 'transport_error'),
                               ((b'PRIVATE', ('192.0.2.1', 53)), 'invalid')):
            channel = MagicMock()
            channel.__enter__.return_value = channel
            if isinstance(reply, Exception):
                channel.recvfrom.side_effect = reply
            else:
                channel.recvfrom.return_value = reply
            with patch.object(diagnostics.socket, 'socket', return_value=channel) as factory, \
                    patch.object(diagnostics.socket, 'if_nametoindex', return_value=1) as interface, \
                    patch.object(diagnostics.secrets, 'randbelow', return_value=1234):
                value = diagnostics.probe_dns(diagnostics.parse_tunnel(json.dumps(tunnel())))
            self.assertEqual(value['status'], status)
            self.assertNotIn('PRIVATE', json.dumps(value))
            factory.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
            interface.assert_called_once_with('lo')
            channel.setsockopt.assert_called_once_with(socket.IPPROTO_IP, diagnostics.IP_UNICAST_IF, struct.pack('!I', 1))
            channel.bind.assert_called_once_with((diagnostics.DNS, 0))
            channel.connect.assert_called_once_with((diagnostics.DNS, 53))
            channel.settimeout.assert_called_once_with(3)

    def test_unsupported_output_interface_option_stops_without_unrestricted_retry(self):
        channel = MagicMock()
        channel.__enter__.return_value = channel
        channel.setsockopt.side_effect = OSError('PRIVATE')
        with patch.object(diagnostics.socket, 'socket', return_value=channel) as factory, \
                patch.object(diagnostics.socket, 'if_nametoindex', return_value=1):
            value = diagnostics.probe_dns(diagnostics.parse_tunnel(json.dumps(tunnel())))
        self.assertEqual(value['status'], 'transport_error')
        self.assertNotIn('PRIVATE', json.dumps(value))
        factory.assert_called_once()
        channel.connect.assert_not_called()
        channel.send.assert_not_called()


class DiagnosticsSafetyTests(unittest.TestCase):
    def test_bounded_reader_withholds_nonzero_stderr_truncation_and_timeout(self):
        for program, options in (("import sys;print('PRIVATE');sys.exit(1)", {}),
                                 ("print('PRIVATE'*1000)", {'limit': 64}),
                                 ("import time;time.sleep(2)", {'timeout': .05}),
                                 ("import os;os.write(1,b'\\xff')", {})):
            self.assertIsNone(diagnostics.read_command([sys.executable, '-c', program], **options))
        self.assertEqual(diagnostics.read_command([sys.executable, '-c', "print('ok')"]), 'ok\n')

    def test_nested_public_schema_rejects_unknown_fields_bad_types_and_secret_exception_text(self):
        original = report()
        self.assertIs(diagnostics.validate_report(original), original)
        cases = []
        for key in ('version', 'server_utc', 'ntp_synchronized', 'services', 'tunnel',
                    'dns_listeners', 'authorization', 'input_counters', 'dns_probe'):
            value = copy.deepcopy(original)
            value[key] = 'PRIVATE'
            cases.append(value)
        for section in ('tunnel', 'authorization', 'input_counters', 'dns_probe'):
            value = copy.deepcopy(original)
            value[section]['PRIVATE'] = 'PRIVATE'
            cases.append(value)
        for field in ('unit', 'active_state', 'sub_state', 'restarts', 'result'):
            value = copy.deepcopy(original)
            value['services'][0][field] = 'PRIVATE'
            cases.append(value)
        value = copy.deepcopy(original)
        value['dns_listeners'][0]['address'] = 'PRIVATE'
        cases.append(value)
        value = copy.deepcopy(original)
        value['authorization']['addresses'][0]['ipv4'] = 'PRIVATE'
        cases.append(value)
        for value in cases:
            with self.assertRaises(ValueError) as error:
                diagnostics.validate_report(value)
            self.assertNotIn('PRIVATE', str(error.exception))

    def test_collect_uses_only_fixed_read_only_commands_and_redacts_all_failures(self):
        with patch.object(diagnostics, 'read_command', return_value='PRIVATE') as command, \
                patch.object(diagnostics.socket, 'socket') as factory:
            value = diagnostics.collect()
        self.assertNotIn('PRIVATE', json.dumps(value))
        self.assertEqual(value['dns_probe']['status'], 'not_attempted')
        factory.assert_not_called()
        self.assertEqual(len(command.call_args_list), 5)
        flattened = ' '.join(' '.join(call.args[0]) for call in command.call_args_list)
        for private_source in ('journal', 'passwd', 'login.txt', '.management', 'ConfigQuery'):
            self.assertNotIn(private_source, flattened)
        self.assertIn('list table inet vpn_lab', flattened)

    def test_nonroot_main_exits_without_output_or_collecting_data(self):
        with patch.object(diagnostics.os, 'geteuid', return_value=1000), \
                patch.object(diagnostics.resource, 'setrlimit'), patch.object(diagnostics, 'collect') as collect, \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            with self.assertRaises(SystemExit):
                diagnostics.main()
        collect.assert_not_called()
        self.assertEqual(output.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
