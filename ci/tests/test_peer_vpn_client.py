import copy
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ops'))
import peer_vpn_client as client


def request():
    profile='\n'.join(('client','dev tun','proto udp','remote 192.0.2.10 1194',
        'remote-cert-tls server','verify-x509-name VPNLabServer name','tls-version-min 1.3',
        'auth-user-pass','<ca>','TEST','</ca>','<cert>','TEST','</cert>',
        '<key>','PRIVATE TEST FIXTURE','</key>','<tls-crypt>','TEST','</tls-crypt>'))+'\n'
    return {'mode':'test','profile':profile,'login':'vpn-lab-client\n'+'S'*43+'\n',
            'server_ipv4':'192.0.2.10','expected_ipv4':'172.27.240.249'}


def answer(identifier=1234,flags=0x8180):
    record=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('93.184.216.34')
    return struct.pack('!6H',identifier,flags,1,1,0,0)+client.QUESTION+record


class RequestTests(unittest.TestCase):
    def test_supported_inline_request_and_prepare_only_are_accepted(self):
        self.assertEqual(client.validate_request(request()),request())
        self.assertEqual(client.validate_request({'mode':'prepare'}),{'mode':'prepare'})

    def test_commands_external_files_endpoint_changes_and_profile_mutation_are_rejected(self):
        for line in ('up /tmp/evil','plugin /tmp/evil','script-security 2',
                     'config /root/private','auth-user-pass /root/private',
                     'remote 192.0.2.11 1194','management /run/control unix'):
            value=request()
            value['profile']+=line+'\n'
            with self.assertRaisesRegex(client.ClientError,'invalid_request'):
                client.validate_request(value)
        for field,value in (('server_ipv4','example.com'),('server_ipv4','127.0.0.1'),
                ('expected_ipv4','172.27.240.10'),('login','root\nPRIVATE\n')):
            value_request=request()
            value_request[field]=value
            with self.assertRaises(client.ClientError):
                client.validate_request(value_request)

    def test_private_files_are_owner_only_and_do_not_follow_existing_links(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'private'
            client.private_file(target,'PRIVATE')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)
            link=Path(folder)/'link'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                client.private_file(link,'CHANGED')
            self.assertEqual(target.read_text(),'PRIVATE')


class DNSAndNetworkTests(unittest.TestCase):
    def test_dns_requires_matching_id_question_and_well_formed_usable_answer(self):
        result,addresses=client.parse_dns(answer(),1234)
        self.assertEqual(result,{'status':'ok','rcode':0,'answers':1})
        self.assertEqual(addresses,['93.184.216.34'])
        for data in (answer(identifier=1235),answer()[:-1],answer()+b'EXTRA',
                     answer().replace(b'example',b'private'),b'x'*4097):
            self.assertEqual(client.parse_dns(data,1234)[0]['status'],'invalid')
        self.assertEqual(client.parse_dns(answer(flags=0x8182),1234)[0]['rcode'],2)

    def test_no_tunnel_route_means_no_socket_and_no_dns_fallback(self):
        with patch.object(client,'command',return_value=(0,'[{"dev":"tap0"}]')), \
                patch.object(client,'tunnel_socket') as network:
            result,_=client.query_dns(client.PRIVATE_DNS)
        self.assertEqual(result['status'],'transport_error')
        network.assert_not_called()

    def test_socket_is_tunnel_bound_with_the_test_source(self):
        sock=MagicMock()
        with patch.object(client.socket,'socket',return_value=sock) as factory:
            self.assertIs(client.tunnel_socket(socket.SOCK_DGRAM),sock)
        factory.assert_called_once_with(socket.AF_INET,socket.SOCK_DGRAM)
        sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'tun-test\0')
        sock.bind.assert_called_once_with(('172.27.240.249',0))

    def test_https_uses_default_ca_and_hostname_verification_over_bound_socket(self):
        sock=MagicMock()
        sock.__enter__.return_value=sock
        tls=MagicMock()
        tls.__enter__.return_value=tls
        tls.recv.return_value=b'HTTP/1.1 200 OK\r\n'
        context=MagicMock()
        context.wrap_socket.return_value=tls
        with patch.object(client,'tunnel_socket',return_value=sock) as network, \
                patch.object(client.ssl,'create_default_context',return_value=context) as trust:
            self.assertEqual(client.https_test(['93.184.216.34']),'ok')
        network.assert_called_once_with(socket.SOCK_STREAM)
        trust.assert_called_once_with()
        context.wrap_socket.assert_called_once_with(sock,server_hostname='example.com')
        tls.sendall.assert_called_once_with(b'HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')

    def test_https_does_not_connect_to_private_or_documentation_answers(self):
        with patch.object(client,'tunnel_socket') as network:
            self.assertEqual(client.https_test(['127.0.0.1','192.168.0.1']),'failed')
        network.assert_not_called()

    def test_https_status_allows_reason_phrase_and_redirect_but_rejects_bad_status(self):
        for line,expected in ((b'HTTP/1.1 200 OK\r\n','ok'),
                              (b'HTTP/1.0 301 Moved Permanently\r\n','ok'),
                              (b'HTTP/1.1 204\r\n','ok'),
                              (b'HTTP/1.1 500 Error\r\n','failed'),
                              (b'HTTP/1.1 2000 OK\r\n','failed')):
            raw=MagicMock()
            raw.__enter__.return_value=raw
            tls=MagicMock()
            tls.__enter__.return_value=tls
            tls.recv.return_value=line
            context=MagicMock()
            context.wrap_socket.return_value=tls
            with patch.object(client,'tunnel_socket',return_value=raw), \
                    patch.object(client.ssl,'create_default_context',return_value=context):
                self.assertEqual(client.https_test(['93.184.216.34']),expected)

    def test_client_uses_only_protected_files_and_ipv4_no_scripts_or_dco(self):
        argv=client.openvpn_command(Path('/run/test/client.ovpn'),Path('/run/test/login.txt'),'2.6.14')
        self.assertIn('--disable-dco',argv)
        self.assertEqual(argv[argv.index('--script-security')+1],'1')
        self.assertEqual(argv[argv.index('--proto')+1],'udp4')
        self.assertEqual(argv[argv.index('--dev')+1],'tun-test')
        self.assertIn('--auth-nocache',argv)
        self.assertEqual(argv[argv.index('--auth-user-pass')+1],'/run/test/login.txt')


class PreparationAndCleanupTests(unittest.TestCase):
    def test_prepare_does_not_install_when_tools_and_trust_exist(self):
        with patch.object(client,'state_fingerprint',return_value=('routes','dns')), \
                patch.object(Path,'is_file',return_value=True), \
                patch.object(client.ssl,'get_default_verify_paths',return_value=MagicMock(cafile='/etc/ssl/certs/ca-certificates.crt')), \
                patch.object(client,'versions',return_value={'client_version':'2.6.14','slirp_version':'1.2.1'}), \
                patch.object(client,'command') as command:
            report=client.prepare()
        self.assertTrue(report['passed'])
        self.assertFalse(report['packages_installed'])
        command.assert_not_called()

    def test_prepare_installs_only_missing_named_packages_without_upgrades_or_removals(self):
        def exists(path):
            return str(path) not in ('/usr/sbin/openvpn','/usr/bin/slirp4netns')
        with patch.object(client,'state_fingerprint',return_value=('routes','dns')), \
                patch.object(Path,'is_file',new=exists), \
                patch.object(client.ssl,'get_default_verify_paths',return_value=MagicMock(cafile='/etc/ssl/certs/ca-certificates.crt')), \
                patch.object(client,'versions',return_value={'client_version':'2.6.14','slirp_version':'1.2.1'}), \
                patch.object(client,'command',return_value=(0,'')) as command:
            report=client.prepare()
        self.assertTrue(report['passed'])
        self.assertEqual(command.call_args_list[0].args[0],['/usr/bin/apt-get','update','-qq'])
        self.assertEqual(command.call_args_list[1].args[0],['/usr/bin/apt-get','install','-y',
            '--no-install-recommends','--no-upgrade','--no-remove','openvpn','slirp4netns'])

    def test_failed_namespace_setup_cleans_private_files_without_starting_slirp(self):
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(client,'RUNTIME',Path(folder)), \
                patch.object(client,'versions',return_value={'client_version':'2.6.14','slirp_version':'1.2.1'}), \
                patch.object(client,'state_fingerprint',return_value=('routes','dns')), \
                patch.object(client.os,'fork',return_value=999999), \
                patch.object(client,'stop_child',return_value=True) as cleanup, \
                patch.object(client.subprocess,'Popen') as process:
            report=client.test(request())
            self.assertEqual(list(Path(folder).iterdir()),[])
        self.assertEqual(report['error'],'namespace_failed')
        self.assertTrue(report['cleanup_confirmed'])
        self.assertTrue(report['host_routes_unchanged'])
        self.assertNotIn('PRIVATE',json.dumps(report))
        process.assert_not_called()
        cleanup.assert_called_with(999999)

    def test_existing_stock_configuration_refuses_installation_before_apt(self):
        with tempfile.TemporaryDirectory() as folder:
            config_dir=Path(folder)/'server'
            config_dir.mkdir()
            configuration=config_dir/'existing.conf'
            configuration.write_text('PRIVATE EXISTING CONFIGURATION\n')
            def exists(path):
                return str(path)!='/usr/sbin/openvpn'
            with patch.object(client,'STOCK_CONFIG_DIRS',(Path(folder),config_dir)), \
                    patch.object(Path,'is_file',new=exists), \
                    patch.object(client,'state_fingerprint',return_value=('routes','dns')), \
                    patch.object(client,'command') as command:
                report=client.prepare()
            self.assertEqual(configuration.read_text(),'PRIVATE EXISTING CONFIGURATION\n')
        command.assert_not_called()
        self.assertFalse(report['passed'])
        self.assertEqual(report['error'],'prepare_failed')
        self.assertFalse(report['packages_installed'])
        self.assertTrue(report['host_routes_unchanged'])
        self.assertTrue(report['host_dns_unchanged'])
        self.assertNotIn('PRIVATE',json.dumps(report))

    def test_public_report_rejects_unknown_fields_free_text_and_false_success(self):
        values=[{**client.empty_report(),'password':'PRIVATE'},
                {**client.empty_report(),'error':'PRIVATE'},
                {**client.empty_report(),'passed':True},
                {**client.empty_report(),'namespace_isolated':'PRIVATE'}]
        for value in values:
            with self.assertRaises(ValueError) as error:
                client.validate_report(value)
            self.assertEqual(str(error.exception),'Unsupported external VPN client report.')
        self.assertEqual(client.validate_report(client.empty_report()),client.empty_report())


if __name__=='__main__':
    unittest.main()
