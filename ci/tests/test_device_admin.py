import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ops'))
import device_admin
import server_foundation as server


class DeviceAdminTests(unittest.TestCase):
    def test_revocation_changes_only_selected_device_and_never_returns_credentials(self):
        devices = {name: {'enabled': True, 'sha256': letter*64}
                   for name, letter in (('kali', 'a'), ('iphone', 'b'), ('android', 'c'))}
        with patch.object(device_admin.os, 'geteuid', return_value=0), \
                patch.object(server, 'read_owned', return_value=json.dumps(devices)), \
                patch.object(server, 'write') as write, patch.object(Path, 'unlink'):
            result = device_admin.administer('revoke-device', 'iphone')
        saved = json.loads(write.call_args.args[1])
        self.assertFalse(saved['iphone']['enabled'])
        self.assertTrue(saved['kali']['enabled'])
        self.assertTrue(saved['android']['enabled'])
        self.assertFalse(result['credential_contents_returned'])
        self.assertFalse(result['session_reset'])
        self.assertEqual(set(result['devices']['iphone']), {'enabled', 'certificate_sha256'})

    def test_independent_reset_removes_forwarding_before_restarting_server(self):
        with patch.object(device_admin.os, 'geteuid', return_value=0), \
                patch.object(server, 'read_owned', return_value='{}'), patch.object(server, 'run') as run:
            result = device_admin.administer('reset-sessions')
        self.assertEqual(run.call_args_list[0].args[0],
                         ['/usr/sbin/nft', 'flush', 'set', 'inet', 'vpn_lab', 'authorized'])
        self.assertEqual(run.call_args_list[1].args[0],
                         ['/usr/bin/systemctl', 'restart', 'openvpn-server@vpn-lab.service'])
        self.assertTrue(result['session_reset'])

    def test_root_only_fixed_names_and_fixed_operations(self):
        for uid, operation, name in ((1000, 'device-status', 'kali'),
                                     (0, 'revoke-device', '../root'), (0, 'shell', 'kali')):
            with patch.object(device_admin.os, 'geteuid', return_value=uid), \
                    patch.object(server, 'read_owned', return_value='{}'), \
                    self.assertRaises(server.SetupError):
                device_admin.administer(operation, name)

    def test_password_rotation_closes_access_then_syncs_private_copies_without_returning_secrets(self):
        original = server.CLIENT+'\n'+'o'*43+'\n'
        fresh = 'n'*43
        actions = []
        def run(argv, **kwargs):
            actions.append(('command', argv, kwargs))
        def write(path, value):
            actions.append(('write', path, value))
        with patch.object(device_admin.os, 'geteuid', return_value=0), \
                patch.object(server, 'read_owned', return_value=original), \
                patch.object(server, 'directory'), patch.object(server, 'run', side_effect=run), \
                patch.object(server, 'write', side_effect=write), patch.object(Path, 'unlink'), \
                patch.object(device_admin.secrets, 'token_urlsafe', return_value=fresh):
            result = device_admin.administer('rotate-password')
        self.assertEqual(actions[0][1], ['/usr/sbin/nft','flush','set','inet','vpn_lab','authorized'])
        self.assertEqual(actions[1][1], ['/usr/bin/systemctl','stop','openvpn-server@vpn-lab.service'])
        self.assertEqual(actions[2][2], {'data': server.CLIENT+':'+fresh+'\n'})
        copies = [row for row in actions if row[0]=='write']
        self.assertEqual(len(copies), 4)
        self.assertTrue(all(row[2]==server.CLIENT+'\n'+fresh+'\n' for row in copies))
        self.assertEqual(actions[-1][1], ['/usr/bin/systemctl','start','openvpn-server@vpn-lab.service'])
        self.assertFalse(result['credential_contents_returned'])
        self.assertNotIn(fresh, json.dumps(result))

    def test_rotation_failure_leaves_server_stopped_and_unknown_copies_preserved(self):
        original = server.CLIENT+'\n'+'o'*43+'\n'
        with patch.object(device_admin.os, 'geteuid', return_value=0), \
                patch.object(server, 'read_owned', return_value=original), \
                patch.object(server, 'directory'), patch.object(server, 'run') as run, \
                patch.object(server, 'write', side_effect=OSError('fixture disk failure')), \
                patch.object(Path, 'unlink'):
            with self.assertRaises(OSError):
                device_admin.administer('rotate-password')
            self.assertNotIn(['/usr/bin/systemctl','start','openvpn-server@vpn-lab.service'],
                             [call.args[0] for call in run.call_args_list])
        with patch.object(device_admin.os, 'geteuid', return_value=0), \
                patch.object(server, 'read_owned', side_effect=[original, 'unknown copy']), \
                patch.object(server, 'directory'), patch.object(server, 'run') as run:
            with self.assertRaises(server.SetupError):
                device_admin.administer('rotate-password')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
