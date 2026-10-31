"""Hotspot policy, radio preflight and private configuration regressions."""
import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import sys
import io
import os
import stat
import tempfile
from contextlib import ExitStack,redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'vpn-dashboard'))
import portal_helper as portal
import firewall_policy
import network_setup
from security import Refused
spec=importlib.util.spec_from_file_location('hotspot_ops_tests',ROOT/'ops/vpn_hotspot.py')
hotspot=importlib.util.module_from_spec(spec);spec.loader.exec_module(hotspot)
POLICY={'wifi_interface':'wlan0','vpn_server_ipv4':'170.64.224.131','vpn_port':1194,
        'vpn_protocol':'udp','dhcp_server_ipv4':'192.0.2.1','server_name':'VPNLabServer'}
PHY='''Supported interface modes:
 * managed
 * AP
 * 2437 MHz [6] (20.0 dBm)
valid interface combinations:
 * #{ managed } <= 1, #{ AP, P2P-GO } <= 1, total <= 3, #channels <= 1
HT Capability overrides:
'''

class HotspotPolicyTests(unittest.TestCase):
    def guard(self):
        return {'nftables':[item['add'] for item in firewall_policy.render_batch(POLICY,995,hotspot=True)['nftables']]}

    def test_complete_gateway_guard_accepts_but_never_a_physical_fallback(self):
        with patch.object(portal,'load_policy',return_value=POLICY),patch.object(portal,'service_account') as account:
            account.return_value.pw_uid=995
            self.assertEqual(portal.inspect_guard(self.guard()),(False,False))
            document=self.guard()
            row=next(item['rule'] for item in document['nftables'] if item.get('rule',{}).get('chain')=='forward')
            row['expr'][2]['match']['right']='wlan0'
            with self.assertRaises(Refused): portal.inspect_guard(document)

    def test_missing_dns_redirect_or_extra_exception_refuses_gateway(self):
        with patch.object(portal,'load_policy',return_value=POLICY),patch.object(portal,'service_account') as account:
            account.return_value.pw_uid=995
            for alter in ('missing','extra'):
                document=self.guard()
                if alter=='missing':
                    document['nftables']=[item for item in document['nftables'] if item.get('rule',{}).get('chain')!='prerouting']
                else:
                    document['nftables'].append({'rule':{'family':'inet','table':'vpn_guard','chain':'forward','expr':[{'accept':None}]}})
                with self.assertRaises(Refused): portal.inspect_guard(document)

    def test_restore_never_releases_guard_with_hotspot_interface_present(self):
        with patch.object(portal,'hotspot_present',return_value=True),patch.object(portal,'mutate') as mutate:
            with self.assertRaisesRegex(Refused,'Stop the VPN hotspot'): network_setup.restore()
            mutate.assert_not_called()

    def test_radio_requires_same_channel_concurrency_and_active_non_dfs_channel(self):
        info='wiphy 0\nchannel 6 (2437 MHz), width: 20 MHz\n'
        self.assertEqual(hotspot.channel(info,PHY),(6,2437))
        for bad in (PHY.replace('2437','2462'),PHY.replace('(20.0 dBm)','(no IR)'),
                    PHY.replace('(20.0 dBm)','(radar detection)'),PHY.replace('AP, P2P-GO','P2P-GO')):
            with self.assertRaises(hotspot.HotspotError): hotspot.channel(info,bad)

    def test_strong_private_ap_is_single_station_and_dhcp_advertises_only_private_dns(self):
        conf=hotspot.hostapd_configuration(6,2437,'A'*32)
        for item in ('wpa=2','rsn_pairwise=CCMP','max_num_sta=1','ap_isolate=1','wps_state=0','channel=6'):
            self.assertIn(item,conf)
        dhcp=hotspot.dhcp_configuration()
        self.assertIn('port=0\n',dhcp);self.assertIn('dhcp-option=6,172.27.240.1\n',dhcp)
        self.assertIn('user=vpn-hotspot\n',dhcp);self.assertIn('leasefile-ro\n',dhcp)
        with self.assertRaises(hotspot.HotspotError): hotspot.hostapd_configuration(6,2437,'password\nadmin=1')

    def runtime_cleanup_case(self,fail_delete=False):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            root=Path(directory);events=[]
            forward=root/'forward';forward.write_text('0\n')
            run=root/'runtime';nm=root/'nm'/'hotspot.conf'
            for key,value in (('RUN',run),('NM',nm),('FORWARD',forward)):
                stack.enter_context(patch.object(hotspot,key,value))
            sources={name:(ROOT/('vpn-dashboard' if name in hotspot.LEGACY else 'ops')/name).read_text() for name in hotspot.SOURCE_SHA256}
            helper=(ROOT/'vpn-dashboard/vpn_session_helper.py').read_bytes()
            updater=SimpleNamespace(read_file=lambda path:helper if path.name=='vpn_session_helper.py' else sources[path.name].encode(),upgrade=Mock())
            portal_fake=SimpleNamespace(hotspot_present=lambda:False,active_openvpn=lambda:False)
            network=SimpleNamespace(verify_during_session=lambda:True,restore=lambda:events.append('restore'))
            modules={'security':SimpleNamespace(load_policy=lambda:POLICY),'session_channel':SimpleNamespace(kernel_ipv6_disabled=lambda:True,request=lambda:{'state':'tunnel_ready'}),
                     'portal_helper':portal_fake,'network_setup':network,
                     'vpn_session_helper':SimpleNamespace(validate_testing_login=lambda:None,private_dns_probe=lambda:('ok',1))}
            diagnostics=SimpleNamespace(load_modules=lambda:modules,ip_json=lambda args:[],public_tunnel=lambda:True)
            vpn=Mock(name='vpn');vpn.poll.return_value=None
            ap=Mock(name='ap');ap.poll.return_value=None
            dhcp=Mock(name='dhcp');dhcp.poll.side_effect=[None,1]
            def command(args,**kwargs):
                if args[-1]=='info' and 'phy' in args:return PHY
                if args[-1]=='info':return 'wiphy 0\nchannel 6 (2437 MHz), width: 20 MHz\n'
                if args[-1]=='status':return 'state=ENABLED\nfreq=2437\n'
                if args[-1]=='del':
                    events.append('ap-removed')
                    if fail_delete: raise hotspot.HotspotError('Fixture deletion failed.')
                return ''
            real_lstat=Path.lstat
            def metadata(path):
                value=real_lstat(path)
                if path in (*nm.parent.parents,nm.parent):
                    values=list(value);values[0]=stat.S_IFDIR|0o755;values[4]=0
                    return os.stat_result(values)
                return value
            stack.enter_context(patch.object(hotspot,'command',side_effect=command))
            stack.enter_context(patch.object(hotspot,'account'))
            stack.enter_context(patch.object(hotspot,'restore_network',side_effect=lambda m:network.restore()))
            stack.enter_context(patch.object(hotspot,'guard_batch',side_effect=lambda m,enabled:events.append('guard-on' if enabled else 'guard-base')))
            stack.enter_context(patch.object(hotspot,'stop_child',side_effect=lambda child:events.append('stop-'+('vpn' if child is vpn else 'ap' if child is ap else 'dhcp'))))
            stack.enter_context(patch.object(hotspot.subprocess,'Popen',side_effect=[vpn,ap,dhcp]))
            stack.enter_context(patch.object(hotspot.os,'access',side_effect=lambda path,mode:str(path)!='/usr/bin/qrencode'))
            stack.enter_context(patch.object(hotspot.Path,'lstat',metadata))
            stack.enter_context(patch.object(hotspot.signal,'signal'))
            stack.enter_context(patch.object(hotspot.time,'sleep'))
            stack.enter_context(patch.object(hotspot.secrets,'token_urlsafe',return_value='A'*32))
            with redirect_stdout(io.StringIO()),self.assertRaisesRegex(hotspot.HotspotError,'service stopped'):
                hotspot.run(1000,sources,diagnostics,updater)
            self.assertEqual(forward.read_text(),'0\n')
            self.assertLess(events.index('stop-ap'),events.index('stop-vpn'))
            if fail_delete:
                self.assertNotIn('restore',events);self.assertNotIn('guard-base',events)
                self.assertTrue(nm.exists());self.assertTrue(run.exists())
            else:
                self.assertLess(events.index('ap-removed'),events.index('restore'))
                self.assertLess(events.index('guard-base'),events.index('restore'))
                self.assertFalse(nm.exists());self.assertFalse(run.exists())

    def test_runtime_failure_stops_ap_before_vpn_and_restores_forwarding_and_dns(self):
        self.runtime_cleanup_case()

    def test_failed_ap_removal_keeps_guard_and_nm_ownership_for_review(self):
        self.runtime_cleanup_case(fail_delete=True)

    def test_source_bundle_is_pinned_and_exact(self):
        for name,digest in hotspot.SOURCE_SHA256.items():
            folder='vpn-dashboard' if name in hotspot.LEGACY else 'ops'
            self.assertEqual(hashlib.sha256((ROOT/folder/name).read_bytes()).hexdigest(),digest)
        with self.assertRaises(hotspot.HotspotError): hotspot.checked_module('client_diagnostics.py','evil code')

if __name__=='__main__':unittest.main()
