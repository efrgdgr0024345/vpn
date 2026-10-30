import unittest
import inspect
import os
import stat
from types import SimpleNamespace
from unittest.mock import patch

import portal_helper
import vpn_session_helper as session
from security import PROFILE


class SessionTests(unittest.TestCase):
    def setUp(self):
        patcher=patch.object(session.network_setup,'prepare')
        patcher.start()
        self.addCleanup(patcher.stop)
        history=patch.object(session.session_channel,'save_last')
        history.start()
        self.addCleanup(history.stop)

    def test_startup_deadline_distinguishes_no_reply_handshake_and_credentials(self):
        watch=session.StartupWatch(0)
        self.assertIsNone(watch.expired(179))
        self.assertEqual(watch.expired(180),'startup_timeout')
        watch=session.StartupWatch(0)
        watch.observe('transport_start',10)
        self.assertEqual(watch.expired(70),'server_timeout')
        watch.observe('server_replied',71)
        self.assertEqual(watch.expired(72),'handshake_timeout')
        watch.observe('tunnel_ready',73)
        self.assertIsNone(watch.expired(1000))
        watch.observe('reconnecting',1001)
        self.assertEqual(watch.expired(1061),'server_timeout')

    def test_retries_do_not_reset_the_startup_timeout(self):
        watch=session.StartupWatch(0)
        watch.observe('transport_start',1)
        for now in (10,20,30,40,50):
            watch.observe('reconnecting',now)
            watch.observe('transport_start',now+1)
        self.assertEqual(watch.expired(61),'server_timeout')

    def test_socket_metadata_uses_only_the_owned_process_and_pinned_endpoint(self):
        events=session.session_channel.Events()
        events.set_details({'server_ipv4':'192.0.2.10','server_port':1194,'protocol':'udp4'})
        rows=[('192.0.2.3',45000,'192.0.2.20',1194),('192.0.2.4',50000,'192.0.2.10',1194)]
        with patch.object(session,'owned_socket_rows',return_value=rows) as owned,patch('builtins.print'):
            session.socket_details(events,123)
            owned.assert_called_once_with(123,'udp')
        self.assertEqual(events.snapshot()['details']['local_ipv4'],'192.0.2.4')
        self.assertEqual(events.snapshot()['details']['local_port'],50000)

    def test_proc_socket_parser_rejects_inodes_not_owned_by_the_child(self):
        row='0: 040200C0:C350 0A0200C0:04AA 01 0:0 0:0 0 0 0 10\n'
        rows=session.parse_socket_rows(row+row.replace(' 10\n',' 999\n'),{10})
        self.assertEqual(rows,[('192.0.2.4',50000,'192.0.2.10',1194)])

    def test_unavailable_diagnostics_do_not_change_networking_or_abort_the_session(self):
        events=session.session_channel.Events()
        with patch.object(session,'diagnostic',return_value=None), \
                patch.object(session.network_setup,'resolver_read',side_effect=OSError('fixture')):
            session.socket_details(events,123)
            session.tunnel_details(events)
        self.assertEqual(events.snapshot()['details'],{})

    def test_history_storage_failure_reports_only_the_os_error_number(self):
        events=session.session_channel.Events()
        with patch.object(session.session_channel,'save_last',side_effect=OSError(95,'PRIVATE_ERROR_TEXT')), \
                patch('builtins.print') as output:
            session.retain_last(1000,events,None)
        self.assertIn('OS error 95',output.call_args.args[0])
        self.assertNotIn('PRIVATE_ERROR_TEXT',output.call_args.args[0])

    def test_pidfd_acquisition_failure_cleans_up_the_owned_child(self):
        process=SimpleNamespace(pid=123,stdout=SimpleNamespace(close=lambda:None),
                                poll=lambda:None)
        from unittest.mock import Mock,MagicMock
        process.terminate=Mock()
        process.wait=Mock(return_value=0)
        with patch.object(session.session_channel,'Server',return_value=MagicMock()), \
                patch.object(session.subprocess,'Popen',return_value=process), \
                patch.object(session.os,'pidfd_open',side_effect=OSError('fixture')), \
                patch.object(session.signal,'signal'),patch('builtins.print'):
            self.assertEqual(session.controlled_session(['fixture'],1000),1)
        process.terminate.assert_called_once()
        process.wait.assert_called_once()

    def test_only_protected_profile_reaches_openvpn(self):
        account = SimpleNamespace(pw_uid=995, pw_gid=995)
        with patch.object(session, 'load_policy', return_value={'vpn_protocol': 'udp'}), \
                patch.object(session, 'read_trusted', return_value='profile') as read, \
                patch.object(session, 'validate_profile') as validate, \
                patch.object(session, 'service_account', return_value=account), \
                patch.object(session, 'diagnostic', return_value='OpenVPN 2.7.8 x86_64-pc-linux-gnu\n') as diagnostic, \
                patch.object(session.Path, 'is_file', return_value=True):
            command = session.openvpn_argv()
        read.assert_called_once_with(PROFILE, private=True)
        validate.assert_called_once_with('profile', {'vpn_protocol': 'udp'})
        self.assertEqual(command[:3], ['/usr/sbin/openvpn', '--config', '/etc/vpn-desk/client.ovpn'])
        self.assertEqual(command[command.index('--user') + 1], 'vpn-desk')
        self.assertEqual(command[command.index('--group') + 1], 'vpn-desk')
        self.assertEqual(command[command.index('--script-security') + 1], '1')
        self.assertIn('--auth-nocache', command)
        self.assertNotIn(str(session.TEST_LOGIN), command)
        self.assertNotIn('--auth-retry', command)
        self.assertEqual(command.count('--disable-dco'), 1)
        diagnostic.assert_called_once_with(['/usr/sbin/openvpn', '--version'], as_json=False)
        self.assertEqual(command[command.index('--allow-compression') + 1], 'no')

    def test_saved_login_uses_only_fixed_root_path_and_disables_auth_retry(self):
        with patch.object(session, 'load_policy', return_value={'vpn_protocol': 'udp'}), \
                patch.object(session, 'read_trusted', return_value='profile'), \
                patch.object(session, 'validate_profile'), patch.object(session, 'service_account'), \
                patch.object(session, 'diagnostic', return_value='OpenVPN 2.7.8 x86_64\n'), \
                patch.object(session.Path, 'is_file', return_value=True), \
                patch.object(session, 'validate_testing_login') as login:
            command = session.openvpn_argv(test_credentials=True)
        login.assert_called_once_with()
        self.assertEqual(command[command.index('--auth-user-pass')+1], '/etc/vpn-desk/testing-login.txt')
        self.assertEqual(command[command.index('--auth-retry')+1], 'none')
        self.assertIn('--auth-nocache', command)
        self.assertEqual(command[command.index('--user')+1], 'vpn-desk')

    def test_saved_login_requires_canonical_bounded_credentials_and_returns_no_secret(self):
        metadata=SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1)
        path=SimpleNamespace(lstat=lambda:metadata)
        secret='PRIVATE_PASSWORD_VALUE_1234567890'
        with patch.object(session, 'TEST_LOGIN', path), \
                patch.object(session, 'read_trusted', return_value='vpn-lab-client\n'+secret+'\n') as read:
            self.assertIsNone(session.validate_testing_login())
            read.assert_called_once_with(path,private=True,limit=512)
        invalid=('other\n'+secret+'\n', 'vpn-lab-client\nshort\n',
                 'vpn-lab-client\n'+'A'*257+'\n', 'vpn-lab-client\n'+secret,
                 'vpn-lab-client\r\n'+secret+'\r\n', 'vpn-lab-client\n'+secret+' extra\n',
                 'vpn-lab-client\n'+secret+'\x1b\n', 'vpn-lab-client\n'+secret+'é\n')
        for text in invalid:
            with patch.object(session, 'TEST_LOGIN', path), patch.object(session, 'read_trusted', return_value=text):
                with self.assertRaises(portal_helper.Refused) as error:
                    session.validate_testing_login()
                self.assertNotIn(secret,str(error.exception))

    def test_saved_login_bad_metadata_is_refused_before_reading_contents(self):
        for uid,mode,links in ((1000,stat.S_IFREG|0o600,1),(0,stat.S_IFLNK|0o600,1),
                               (0,stat.S_IFREG|0o400,1),(0,stat.S_IFREG|0o640,1),
                               (0,stat.S_IFREG|0o644,1),(0,stat.S_IFREG|0o600,2)):
            metadata=SimpleNamespace(st_uid=uid,st_mode=mode,st_nlink=links)
            path=SimpleNamespace(lstat=lambda:metadata)
            with patch.object(session, 'TEST_LOGIN', path), patch.object(session, 'read_trusted') as read:
                with self.assertRaises(portal_helper.Refused):
                    session.validate_testing_login()
                read.assert_not_called()

    def test_saved_login_errors_do_not_echo_input_and_precede_network_preparation(self):
        for error in (OSError('PRIVATE_INPUT'), UnicodeError('PRIVATE_INPUT'), portal_helper.Refused('PRIVATE_INPUT')):
            metadata=SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1)
            path=SimpleNamespace(lstat=lambda:metadata)
            with patch.object(session, 'TEST_LOGIN', path), patch.object(session, 'read_trusted', side_effect=error):
                with self.assertRaises(portal_helper.Refused) as refused:
                    session.validate_testing_login()
                self.assertNotIn('PRIVATE_INPUT',str(refused.exception))
        with patch.object(session.os,'geteuid',return_value=0), \
                patch.object(session,'load_policy',return_value={'vpn_protocol':'udp'}), \
                patch.object(session,'read_trusted',return_value='profile'),patch.object(session,'validate_profile'), \
                patch.object(session,'service_account'),patch.object(session.Path,'is_file',return_value=True), \
                patch.object(session,'validate_testing_login',side_effect=portal_helper.Refused('Unsafe login')), \
                patch.object(session.network_setup,'prepare') as prepare, \
                patch.object(session.portal_helper,'check_network') as check,patch.object(session.portal_helper,'act') as act:
            with self.assertRaises(portal_helper.Refused):
                session.prepare_session(test_credentials=True)
            prepare.assert_not_called()
            check.assert_not_called()
            act.assert_not_called()

    def test_one_shot_session_stops_on_auth_failure_or_reconnect_without_restoring_network(self):
        from unittest.mock import MagicMock
        real_close=os.close
        for line in ('AUTH: Received control message: AUTH_FAILED,PRIVATE_ERROR\n',
                     'SIGUSR1[soft,ping-restart] received, process restarting\n'):
            read_fd,write_fd=os.pipe()
            os.write(write_fd,line.encode())
            closed=[]
            process=MagicMock(pid=1234)
            process.stdout=os.fdopen(read_fd,'rb',buffering=0)
            process.returncode=None
            process.poll.side_effect=lambda:process.returncode
            process.wait.return_value=0
            def terminate(*args):
                process.returncode=0
                if not closed:
                    real_close(write_fd)
                    closed.append(True)
            events=session.session_channel.Events()
            with patch.object(session.session_channel,'Server',return_value=MagicMock()), \
                    patch.object(session.subprocess,'Popen',return_value=process) as popen, \
                    patch.object(session.os,'pidfd_open',return_value=1234),patch.object(session.os,'close'), \
                    patch.object(session.signal,'signal'), \
                    patch.object(session.signal,'pidfd_send_signal',side_effect=terminate) as signal_child, \
                    patch.object(session.network_setup,'verify_during_session',return_value=True), \
                    patch.object(session.network_setup,'restore') as restore,patch('builtins.print') as output:
                try:
                    self.assertEqual(session.controlled_session(['fixed'],1000,events=events,one_shot=True),1)
                finally:
                    if not closed:real_close(write_fd)
                    process.stdout.close()
            self.assertEqual(popen.call_args.kwargs['stdin'],session.subprocess.DEVNULL)
            self.assertEqual(events.snapshot()['state'],'error')
            self.assertTrue(signal_child.called)
            restore.assert_not_called()
            self.assertNotIn('PRIVATE_ERROR',str(output.call_args_list))

    def test_userspace_compatibility_options_follow_the_verified_engine_version(self):
        for output, expected in (('OpenVPN 2.5.11 x86_64-linux-gnu\n', []),
                                 ('OpenVPN 2.5\n', []),
                                 ('OpenVPN 2.6.14 x86_64-linux-gnu\n', ['--disable-dco']),
                                 ('OpenVPN 2.6\n', ['--disable-dco']),
                                 ('OpenVPN 2.7.8 x86_64-pc-linux-gnu [DCO]\n', ['--disable-dco'])):
            with patch.object(session, 'diagnostic', return_value=output) as diagnostic:
                self.assertEqual(session.userspace_options('/usr/sbin/openvpn'), expected)
                diagnostic.assert_called_once_with(['/usr/sbin/openvpn', '--version'], as_json=False)

    def test_unknown_or_older_engine_refuses_before_network_changes_without_raw_output(self):
        for output in (None, {}, '', 'PRIVATE VERSION OUTPUT', 'OpenVPN 2.4.12 PRIVATE',
                       'OpenVPN 1.9 PRIVATE', 'OpenVPN 2.7.8_PRIVATE', 'OpenVPN 2.7.8.1 PRIVATE'):
            with patch.object(session, 'load_policy', return_value={'vpn_protocol': 'udp'}), \
                    patch.object(session, 'read_trusted', return_value='profile'), \
                    patch.object(session, 'validate_profile'), patch.object(session, 'service_account'), \
                    patch.object(session.Path, 'is_file', return_value=True), \
                    patch.object(session.os, 'geteuid', return_value=0), \
                    patch.object(session, 'diagnostic', return_value=output), \
                    patch.object(session.network_setup, 'prepare') as prepare, \
                    patch.object(session.portal_helper, 'check_network') as check_network, \
                    patch.object(session.portal_helper, 'act') as act:
                with self.assertRaises(portal_helper.Refused) as error:
                    session.prepare_session()
                self.assertNotIn('PRIVATE', str(error.exception))
                prepare.assert_not_called()
                check_network.assert_not_called()
                act.assert_not_called()

    def test_ipv4_transport_replaces_combined_gateway_push_and_filters_ipv6_configuration(self):
        for protocol, transport in (('udp', 'udp4'), ('tcp-client', 'tcp4-client')):
            options = session.ipv4_options(protocol)
            self.assertEqual(options[:2], ['--proto', transport])
            filters = [options[index:index+3] for index, value in enumerate(options) if value == '--pull-filter']
            self.assertEqual(filters, [['--pull-filter', 'ignore', name] for name in
                                      ('ifconfig-ipv6', 'route-ipv6', 'redirect-gateway', 'block-ipv6')])
            self.assertEqual(options[-2:], ['--redirect-gateway', 'def1'])
        with self.assertRaises(portal_helper.Refused):
            session.ipv4_options('tcp6-client')

    def test_caller_cannot_select_a_home_profile(self):
        with self.assertRaises(TypeError):
            inspect.signature(session.openvpn_argv).bind('/home/user/droplet-vpn.ovpn')
        for value in ('/home/user/login.txt',1,None,{}):
            with self.assertRaises(portal_helper.Refused):
                session.openvpn_argv(test_credentials=value)

    @patch('vpn_session_helper.load_policy', side_effect=portal_helper.Refused('missing protected policy'))
    @patch('vpn_session_helper.subprocess.Popen')
    def test_missing_config_never_starts_a_process(self, popen, policy):
        with self.assertRaises(portal_helper.Refused):
            session.openvpn_argv()
        popen.assert_not_called()

    @patch('vpn_session_helper.os.geteuid', return_value=1000)
    def test_nonroot_refused(self, uid):
        with self.assertRaises(portal_helper.Refused):
            session.prepare_session()

    @patch('vpn_session_helper.os.geteuid', return_value=0)
    @patch('vpn_session_helper.openvpn_argv', return_value=['openvpn'])
    @patch('vpn_session_helper.portal_helper.check_network')
    @patch('vpn_session_helper.portal_helper.act')
    def test_close_verify_before_start(self, act, network, argv, uid):
        act.side_effect = [{'state': 'closed'}, {'state': 'closed'}]
        self.assertEqual(session.prepare_session(), ['openvpn'])
        self.assertEqual([x.args[0] for x in act.call_args_list], ['close', 'status'])
        network.assert_called_once_with()

    @patch('vpn_session_helper.os.geteuid', return_value=0)
    @patch('vpn_session_helper.openvpn_argv', return_value=['openvpn'])
    @patch('vpn_session_helper.portal_helper.check_network')
    @patch('vpn_session_helper.portal_helper.act')
    def test_unknown_close_or_still_open_aborts(self, act, network, argv, uid):
        for failure in (portal_helper.MutationUnknown('unknown'), [{'state': 'closed'}, {'state': 'open'}]):
            act.side_effect = failure
            with self.assertRaises(portal_helper.Refused):
                session.prepare_session()

    @patch('vpn_session_helper.os.geteuid', return_value=0)
    @patch('vpn_session_helper.openvpn_argv', return_value=['openvpn'])
    @patch('vpn_session_helper.portal_helper.check_network', side_effect=portal_helper.Refused('unmanaged tunnel'))
    @patch('vpn_session_helper.portal_helper.act')
    def test_unmanaged_tunnel_aborts_before_firewall(self, act, network, argv, uid):
        with self.assertRaises(portal_helper.Refused):
            session.prepare_session()
        act.assert_not_called()
