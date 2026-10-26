import ipaddress
from pathlib import Path
import socket
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ops'))
import server_foundation as server
import server_selftest as probe


class FoundationTests(unittest.TestCase):
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
        self.assertIn('verify-x509-name vpn-lab-client name\n',configuration)
        self.assertNotIn('duplicate-cn',configuration)
        self.assertNotIn('client-cert-not-required',configuration)

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
