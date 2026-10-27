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


if __name__ == '__main__':
    unittest.main()
