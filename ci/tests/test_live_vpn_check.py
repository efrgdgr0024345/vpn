"""Read-only live checker must never report green from a tunnel IP alone."""
import hashlib
import importlib.util
from pathlib import Path
import types
import unittest
from unittest.mock import Mock

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('live_vpn_checker',ROOT/'ops/live_vpn_check.py')
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)

class LiveCheckTests(unittest.TestCase):
    def setUp(self):
        self.policy={'vpn_server_ipv4':checker.SERVER,'vpn_port':1194,'vpn_protocol':'udp','server_name':'VPNLabServer','wifi_interface':'wlan0'}
        self.session={'state':'tunnel_ready','details':{'tls_version':'TLSv1.3','expected_tls_name':'VPNLabServer'}}
        self.channel=types.SimpleNamespace(request=Mock(side_effect=lambda:self.session),kernel_ipv6_disabled=Mock(return_value=True))
        self.guard=types.SimpleNamespace(NFT='/usr/sbin/nft',js=Mock(return_value={}),inspect_guard=Mock(return_value=({},False)))
        self.network=types.SimpleNamespace(MANAGED_DNS='private DNS',resolver_read=Mock(return_value='private DNS'))
        self.helper=types.SimpleNamespace(private_dns_probe=Mock(return_value=('ok',1)))
        self.modules={'security':types.SimpleNamespace(load_policy=lambda:self.policy),'session_channel':self.channel,
                      'portal_helper':self.guard,'network_setup':self.network,'vpn_session_helper':self.helper}
        def routes(args):
            if args==['address','show','dev','tun0']: return [{'addr_info':[{'family':'inet','local':'172.27.240.10'}]}]
            return [{'dev':'tun0','prefsrc':'172.27.240.10'}] if args[-1]==checker.DNS else [{'dev':'wlan0'}]
        self.command=Mock(side_effect=lambda argv,**kw:('ok',b'200' if argv[0].endswith('curl') else b'93.184.216.34'))
        self.diag=types.SimpleNamespace(load_modules=Mock(return_value=self.modules),ip_json=Mock(side_effect=routes),
            public_tunnel=Mock(return_value=True),tcp_dns=Mock(return_value='ok'),command=self.command)

    def test_complete_checks_pass_with_interface_bound_verified_https(self):
        value=checker.check(self.diag)
        self.assertEqual(value['overall'],'passed')
        curl=next(call.args[0] for call in self.command.call_args_list if call.args[0][0].endswith('curl'))
        self.assertEqual(curl[curl.index('--interface')+1],'tun0')
        self.assertEqual(curl[curl.index('--noproxy')+1],'*')
        self.assertNotIn('--insecure',curl)
        self.assertNotIn('credentials',value)
        self.assertIn('sampled checks',checker.format_report(value))

    def test_an_interface_alone_cannot_trigger_probes_or_green(self):
        for missing in ('session','routes','guard','dns','policy'):
            with self.subTest(missing=missing):
                self.setUp()
                if missing=='session': self.channel.request.side_effect=OSError('PRIVATE')
                if missing=='routes': self.diag.public_tunnel.return_value=False
                if missing=='guard': self.guard.inspect_guard.side_effect=ValueError('PRIVATE')
                if missing=='dns': self.network.resolver_read.return_value='wrong DNS'
                if missing=='policy': self.policy['vpn_server_ipv4']='203.0.113.7'
                result=checker.check(self.diag)
                self.assertNotEqual(result['overall'],'passed')
                self.command.assert_not_called();self.helper.private_dns_probe.assert_not_called()
                self.assertNotIn('PRIVATE',checker.format_report(result))

    def test_bypass_or_wrong_tls_identity_prevents_network_tests(self):
        self.guard.inspect_guard.return_value=({},True)
        self.assertEqual(checker.check(self.diag)['overall'],'failed')
        self.command.assert_not_called()
        self.guard.inspect_guard.return_value=({},False)
        self.session['details']['expected_tls_name']='AnotherServer'
        self.assertEqual(checker.check(self.diag)['overall'],'failed')
        self.command.assert_not_called()

    def test_late_disconnect_or_guard_change_cannot_leave_green(self):
        self.channel.request.side_effect=[self.session,{'state':'stopped'}]
        result=checker.check(self.diag)
        self.assertEqual(result['overall'],'failed')
        self.assertEqual(result['checks']['live_session'],'failed')
        self.channel.request.side_effect=lambda:self.session
        self.guard.inspect_guard.side_effect=[({},False),OSError('PRIVATE')]
        self.assertEqual(checker.check(self.diag)['overall'],'unknown')

    def test_dns_or_https_failure_is_visible(self):
        self.helper.private_dns_probe.return_value=('timeout',3000)
        result=checker.check(self.diag)
        self.assertEqual(result['checks']['private_dns_udp'],'failed')
        self.assertEqual(result['overall'],'failed')
        self.assertNotIn('https://example.com',checker.format_report(result))

    def test_dependency_is_pinned_and_local_baseline_failure_blocks_all_probes(self):
        source=(ROOT/'ops/client_diagnostics.py').read_text()
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),checker.DIAGNOSTICS_SHA256)
        self.assertTrue(callable(checker.load_diagnostics(source).load_modules))
        with self.assertRaises(ValueError): checker.load_diagnostics(source+'\n')
        self.diag.load_modules.side_effect=ValueError('PRIVATE')
        self.assertEqual(checker.check(self.diag)['overall'],'unknown')
        self.command.assert_not_called()

if __name__=='__main__': unittest.main()
