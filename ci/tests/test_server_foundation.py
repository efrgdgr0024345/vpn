from pathlib import Path
import copy
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ops'))
import server_foundation as server
import server_selftest as probe


class FoundationTests(unittest.TestCase):
    def test_installed_panel_prevents_foundation_replacement_before_mutation(self):
        with patch.object(server.os, 'geteuid', return_value=0), \
                patch.object(server.os.path, 'lexists', return_value=True), \
                patch.object(server, 'run') as run:
            with self.assertRaisesRegex(server.SetupError, 'private panel'):
                server.install('192.0.2.10', 22)
            run.assert_not_called()

    def test_private_resolver_has_no_public_forwarder_in_production(self):
        configuration=server.resolver_configuration(False)
        self.assertIn('interface: 172.27.240.1',configuration)
        self.assertNotIn('forward-zone',configuration)
        self.assertNotIn('forward-addr',configuration)
        self.assertIn('log-queries: no',configuration)
        self.assertIn('forward-addr: 198.41.0.4',server.resolver_configuration(True))
        firewall=server.firewall('eth0',22)
        self.assertLess(firewall.index('vpn-lab-private-dns'),firewall.index('vpn-lab-block-host'))
    def test_old_runner_unit_symlink_is_removed_without_following_its_target(self):
        with tempfile.TemporaryDirectory() as directory:
            original=Path(directory)/'keep'
            original.write_text('KEEP')
            unit=Path(directory)/'runner.service'
            unit.symlink_to(original)
            server.remove_runner_unit(unit)
            self.assertFalse(unit.is_symlink())
            self.assertEqual(original.read_text(),'KEEP')
            server.remove_runner_unit(unit)
            with self.assertRaises(server.SetupError):
                server.remove_runner_unit(Path(directory))

    def test_ca_common_name_cannot_override_server_or_client_certificate_identity(self):
        with patch.object(server,'run',return_value='') as run:
            server.easyrsa('build-ca','nopass')
            self.assertEqual(run.call_args.kwargs['environment']['EASYRSA_REQ_CN'],'VPNLabCA')
            for role,name in (('build-server-full','VPNLabServer'),('build-client-full','vpn-lab-client')):
                server.easyrsa(role,name,'nopass')
                self.assertNotIn('EASYRSA_REQ_CN',run.call_args.kwargs['environment'])

    def test_invalid_endpoint_port_interface_cannot_enter_firewall_source(self):
        for endpoint,port,interface in (('127.0.0.1',22,'eth0'),('192.0.2.10',0,'eth0'),
                                        ('192.0.2.10',22,'eth0"; accept'),
                                        ('192.0.2.10',22,'lo')):
            with self.assertRaises((ValueError,server.SetupError)):
                server.validate(endpoint,port,interface)

    def test_only_distribution_plugin_paths_are_accepted(self):
        for path in ('/tmp/plugin.so','/usr/lib/openvpn/../../evil.so','plugin; rm -rf /'):
            with self.assertRaises(server.SetupError):
                server.server_configuration(path)
        configuration=server.server_configuration('/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so')
        self.assertIn('verify-client-cert require\n',configuration)
        self.assertIn('max-clients 1\n',configuration)
        self.assertIn('management-client-auth\n',configuration)
        self.assertIn('management-client-user root\n',configuration)
        self.assertNotIn('duplicate-cn',configuration)
        self.assertNotIn('client-cert-not-required',configuration)

    def test_server_tunnel_and_resolver_use_only_ipv4(self):
        configuration=server.server_configuration('/usr/lib/openvpn/openvpn-plugin-auth-pam.so')
        self.assertIn('proto udp4\n',configuration)
        self.assertIn('push "redirect-gateway def1"\n',configuration)
        self.assertNotIn('ipv6',configuration)
        self.assertIn('do-ip6: no',server.resolver_configuration(False))

    def test_ipv6_drop_precedes_all_accept_rules_in_each_firewall_chain(self):
        firewall=server.firewall('eth0',22)
        for name in ('input','forward','output'):
            chain=firewall.split(' chain '+name+' {\n',1)[1].split('\n }',1)[0]
            lines=chain.splitlines()
            self.assertEqual(lines[1].strip(),
                'meta nfproto ipv6 counter drop comment "vpn-lab-block-ipv6-'+name+'"')

    def test_ipv4_tunnel_readback_rejects_ipv6_push_or_live_address(self):
        configuration=server.server_configuration('/usr/lib/openvpn/openvpn-plugin-auth-pam.so')
        log="PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,ifconfig 172.27.240.10 255.255.255.0'\n"
        addresses=[{'ifname':'tun-lab','addr_info':[
            {'family':'inet','local':'172.27.240.1','prefixlen':24}]}]
        probe.verify_ipv4_only_tunnel(configuration,log,addresses)
        for changed in (configuration+'server-ipv6 fd47:27:240::/64\n',
                        configuration+'push "block-ipv6"\n',configuration.replace('proto udp4','proto udp')):
            with self.assertRaises(probe.TestFailure):
                probe.verify_ipv4_only_tunnel(changed,log,addresses)
        for changed in ('',log.replace('redirect-gateway def1','redirect-gateway def1 ipv6')):
            with self.assertRaises(probe.TestFailure):
                probe.verify_ipv4_only_tunnel(configuration,changed,addresses)
        changed=copy.deepcopy(addresses)
        changed[0]['addr_info'].append({'family':'inet6','local':'fe80::1','prefixlen':64})
        with self.assertRaises(probe.TestFailure):
            probe.verify_ipv4_only_tunnel(configuration,log,changed)

    def test_ipv6_firewall_readback_rejects_missing_shadowed_or_scoped_drop(self):
        objects=[]
        for name in ('input','forward','output'):
            objects.append({'chain':{'family':'inet','table':'vpn_lab','name':name,
                                    'type':'filter','hook':name,'prio':0}})
            objects.append({'rule':{'family':'inet','table':'vpn_lab','chain':name,
                'comment':'vpn-lab-block-ipv6-'+name,
                'expr':[{'match':{'op':'==','left':{'meta':{'key':'nfproto'}},'right':'ipv6'}},
                        {'counter':{'packets':0,'bytes':0}},{'drop':None}]}})
        probe.verify_ipv6_firewall_drop_rules(objects)
        for name in ('input','forward','output'):
            changed=copy.deepcopy(objects)
            index=next(i for i,item in enumerate(changed) if item.get('rule',{}).get('chain')==name)
            with self.assertRaises(probe.TestFailure):
                probe.verify_ipv6_firewall_drop_rules(changed[:index]+changed[index+1:])
            changed[index]['rule']['expr'].insert(0,{'match':{'left':{'meta':{'key':'iifname'}},
                                                              'op':'==','right':'tun-lab'}})
            with self.assertRaises(probe.TestFailure):
                probe.verify_ipv6_firewall_drop_rules(changed)
            changed=copy.deepcopy(objects)
            changed.insert(index,{'rule':{'family':'inet','table':'vpn_lab','chain':name,
                                         'expr':[{'accept':None}]}})
            with self.assertRaises(probe.TestFailure):
                probe.verify_ipv6_firewall_drop_rules(changed)

    def test_ipv4_dns_probe_has_valid_lengths_addresses_and_header_checksum(self):
        packet=probe.dns_packet('172.27.240.2','9.9.9.9',35000,1234)
        self.assertEqual(struct.unpack('!H',packet[2:4])[0],len(packet))
        self.assertEqual(probe.checksum(packet[:20]),0)
        self.assertEqual(packet[12:16],socket.inet_aton('172.27.240.2'))
        self.assertEqual(struct.unpack('!HH',packet[20:24]),(35000,53))
        self.assertEqual(struct.unpack('!H',packet[28:30])[0],1234)

    def test_ipv6_dns_probe_has_valid_pseudoheader_checksum(self):
        packet=probe.dns_packet('fd47:27:240::1000','2001:4860:4860::8888',35000,1234,True)
        length=struct.unpack('!H',packet[4:6])[0]
        self.assertEqual(length,len(packet)-40)
        pseudo=packet[8:40]+struct.pack('!I3xB',length,17)
        self.assertEqual(probe.checksum(pseudo+packet[40:]),0)


if __name__=='__main__':
    unittest.main()
