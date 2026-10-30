import base64
from contextlib import ExitStack, contextmanager
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ops'))
import configure_download as download
import server_foundation

KEY='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))).decode()


class DownloadTests(unittest.TestCase):
    @contextmanager
    def credential_fixture(self,device_login,master_login,*,legacy=False):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            export=Path(directory)/'exports'
            config=Path(directory)/'configuration'
            export.mkdir()
            config.mkdir()
            (export/'login.txt').write_text(master_login,newline='')
            if legacy:
                source=export
            else:
                source=export/'devices/kali'
                source.mkdir(parents=True)
                (source/'login.txt').write_text(device_login,newline='')
            (source/'client.ovpn').write_text('PRIVATE PROFILE FIXTURE')
            for name,value in (('EXPORT',export),('CONFIG',config)):
                stack.enter_context(patch.object(server_foundation,name,value))
            stack.enter_context(patch.object(download.os,'geteuid',return_value=0))
            def read_owned(path):
                with path.open(newline='') as stream:
                    return stream.read()
            stack.enter_context(patch.object(server_foundation,'read_owned',side_effect=read_owned))
            mutations={}
            for name in ('run','write','directory'):
                mutations[name]=stack.enter_context(patch.object(server_foundation,name))
            mutations['export_file']=stack.enter_context(patch.object(download,'export_file'))
            account=stack.enter_context(patch.object(download.pwd,'getpwnam',side_effect=RuntimeError('validation complete')))
            yield export,source,mutations,account

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

    def test_credentials_are_canonical_two_lines_with_a_bounded_printable_ascii_password(self):
        canonical='vpn-lab-client\nTEST password !\n'
        self.assertEqual(download.canonical_login(canonical),canonical)
        self.assertEqual(download.canonical_login(canonical.replace('\n','\r\n')),canonical)
        self.assertEqual(download.canonical_login(canonical[:-1]),canonical)
        for value in ('root\nPRIVATE\n','vpn-lab-client\n\n','vpn-lab-client\nPRIVATE\nEXTRA\n',
                      'vpn-lab-client\nPRIVATE\n\n','vpn-lab-client\nPRIV\tATE\n',
                      'vpn-lab-client\nPRIVATE\x7f\n','vpn-lab-client\nPRIVÁTE\n',
                      'vpn-lab-client\rPRIVATE\r','vpn-lab-client\n'+'x'*257+'\n',None):
            with self.subTest(value=value),self.assertRaises(server_foundation.SetupError) as error:
                download.canonical_login(value)
            self.assertEqual(str(error.exception),'Protected VPN credentials are not ready.')

    def test_stale_device_copy_is_refused_before_account_or_export_mutations(self):
        with self.credential_fixture('vpn-lab-client\n'+'x'*43+'\n',
                                     'vpn-lab-client\n'+'y'*43+'\n') as (export,source,mutations,account):
            before=(source/'login.txt').read_bytes(),(export/'login.txt').read_bytes()
            compare=download.secrets.compare_digest
            with patch.object(download.secrets,'compare_digest',wraps=compare) as checked, \
                    self.assertRaises(server_foundation.SetupError) as error:
                download.configure(KEY)
            checked.assert_called_once()
            account.assert_not_called()
            for method in mutations.values():
                method.assert_not_called()
            self.assertEqual(((source/'login.txt').read_bytes(),(export/'login.txt').read_bytes()),before)
            self.assertEqual(str(error.exception),'Protected VPN credentials are not ready.')

    def test_matching_normalized_device_and_master_pass_without_modifying_credentials(self):
        with self.credential_fixture('vpn-lab-client\r\n'+'x'*43+'\r\n',
                                     'vpn-lab-client\n'+'x'*43+'\n') as (export,source,mutations,account):
            before=(source/'login.txt').read_bytes(),(export/'login.txt').read_bytes()
            with self.assertRaisesRegex(RuntimeError,'validation complete'):
                download.configure(KEY)
            account.assert_called_once_with(download.USER)
            for method in mutations.values():
                method.assert_not_called()
            self.assertEqual(((source/'login.txt').read_bytes(),(export/'login.txt').read_bytes()),before)

    def test_malformed_master_is_refused_before_any_system_change(self):
        with self.credential_fixture('vpn-lab-client\n'+'x'*43+'\n',
                                     'vpn-lab-client\nPRIVATE\nEXTRA\n') as (export,source,mutations,account):
            with self.assertRaises(server_foundation.SetupError) as error:
                download.configure(KEY)
            account.assert_not_called()
            for method in mutations.values():
                method.assert_not_called()
            self.assertEqual(str(error.exception),'Protected VPN credentials are not ready.')

    def test_legacy_kali_uses_its_validated_master_without_a_device_copy(self):
        with self.credential_fixture(None,'vpn-lab-client\n'+'x'*43+'\n',legacy=True) as (export,source,mutations,account):
            with patch.object(download.secrets,'compare_digest') as compare, \
                    self.assertRaisesRegex(RuntimeError,'validation complete'):
                download.configure(KEY)
            compare.assert_not_called()
            account.assert_called_once_with(download.USER)
            for method in mutations.values():
                method.assert_not_called()


if __name__=='__main__':
    unittest.main()
