import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ops'))
import configure_download as download
import server_foundation

KEY='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))).decode()


class DownloadTests(unittest.TestCase):
    def test_only_single_valid_ed25519_public_line_is_accepted(self):
        canonical,fingerprint=download.public_key(KEY+' untrusted-comment')
        self.assertEqual(canonical,KEY+' vpn-lab-download')
        self.assertTrue(fingerprint.startswith('SHA256:'))
        for key in ('-----BEGIN OPENSSH PRIVATE KEY-----','ssh-ed25519 invalid',KEY+'\n'+KEY,
                    'command="bad" '+KEY):
            with self.subTest(key=key),self.assertRaises(server_foundation.SetupError):
                download.public_key(key)

    def test_reenrollment_preserves_admin_settings_without_duplicate_match_blocks(self):
        original='Port 22\nPermitRootLogin prohibit-password\n'
        configured=download.ssh_configuration(original)
        repeated=download.ssh_configuration(configured)
        self.assertIn(original,repeated)
        self.assertEqual(repeated.count(download.BEGIN),1)
        self.assertIn('ForceCommand internal-sftp -R -d /files',repeated)
        self.assertIn('Match User vpn-lab-download',repeated)

    def test_malformed_managed_match_block_is_refused(self):
        with self.assertRaises(server_foundation.SetupError):
            download.ssh_configuration(download.BEGIN+'\nMatch User root\n')


if __name__=='__main__':
    unittest.main()
