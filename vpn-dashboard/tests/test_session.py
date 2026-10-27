import unittest
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
        with patch.object(session, 'load_policy', return_value={'test': 'policy'}), \
                patch.object(session, 'read_trusted', return_value='profile') as read, \
                patch.object(session, 'validate_profile') as validate, \
                patch.object(session, 'service_account', return_value=account), \
                patch.object(session.Path, 'is_file', return_value=True):
            command = session.openvpn_argv()
        read.assert_called_once_with(PROFILE, private=True)
        validate.assert_called_once_with('profile', {'test': 'policy'})
        self.assertEqual(command[:3], ['/usr/sbin/openvpn', '--config', '/etc/vpn-desk/client.ovpn'])
        self.assertEqual(command[command.index('--user') + 1], 'vpn-desk')
        self.assertEqual(command[command.index('--group') + 1], 'vpn-desk')
        self.assertEqual(command[command.index('--script-security') + 1], '1')
        self.assertIn('--auth-nocache', command)
        self.assertEqual(command[command.index('--allow-compression') + 1], 'no')

    def test_caller_cannot_select_a_home_profile(self):
        with self.assertRaises(TypeError):
            session.openvpn_argv('/home/user/droplet-vpn.ovpn')

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
