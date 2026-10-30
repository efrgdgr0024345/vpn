import base64
import fcntl
import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ops'))
import prepare_test_access as access


class TestIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root/access.DIRECTORY_NAME
        self.private = self.directory/access.KEY_NAME
        self.public = self.directory/(access.KEY_NAME+'.pub')
        for target, value in (('trusted_root', self.root),):
            patcher = patch.object(access, target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for target, value in (('ROOT_UID', os.getuid()),):
            patcher = patch.object(access, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(access.os, 'geteuid', return_value=0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_real_key_generation_is_private_public_only_and_idempotent(self):
        first = access.prepare()
        private_before = (self.private.stat().st_ino, self.private.stat().st_mtime_ns,
                          hashlib.sha256(self.private.read_bytes()).digest())
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode), 0o600)
        self.assertEqual(self.private.stat().st_nlink, 1)
        second = access.prepare()
        self.assertEqual(first, second)
        self.assertEqual(private_before, (self.private.stat().st_ino, self.private.stat().st_mtime_ns,
                                         hashlib.sha256(self.private.read_bytes()).digest()))
        self.assertEqual(set(first), access.REPORT_KEYS)
        self.assertTrue(first['private_key_retained_on_server'])
        public, wire = access.canonical_public(first['ssh_public_key'])
        self.assertEqual(len(wire), 51)
        self.assertEqual(first['ssh_public_key_fingerprint'],
                         'SHA256:'+base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip('='))
        self.assertNotIn('PRIVATE', public)

    def test_existing_mismatched_public_key_is_refused_without_replacing_private(self):
        access.prepare()
        private_before = hashlib.sha256(self.private.read_bytes()).digest()
        other = self.root/'other-key'
        access.keygen(['-q', '-t', 'ed25519', '-N', '', '-C', access.COMMENT, '-f', str(other)])
        self.public.write_bytes((self.root/'other-key.pub').read_bytes())
        changed = self.public.read_bytes()
        with self.assertRaises(access.AccessError):
            access.prepare()
        self.assertEqual(hashlib.sha256(self.private.read_bytes()).digest(), private_before)
        self.assertEqual(self.public.read_bytes(), changed)

    def test_private_group_read_or_write_and_public_group_write_are_refused(self):
        access.prepare()
        for path, mode in ((self.private, 0o640), (self.private, 0o660), (self.public, 0o664)):
            before = stat.S_IMODE(path.stat().st_mode)
            path.chmod(mode)
            with self.assertRaises(access.AccessError):
                access.prepare()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
            path.chmod(before)

    def test_private_hardlink_and_symlink_are_refused_without_following(self):
        access.prepare()
        other = self.root/'other'
        os.link(self.private, other)
        with self.assertRaises(access.AccessError):
            access.prepare()
        other.unlink()
        self.private.rename(other)
        self.private.symlink_to(other)
        with self.assertRaises(access.AccessError):
            access.prepare()
        self.assertTrue(self.private.is_symlink())
        self.assertTrue(other.exists())

    def test_directory_permissions_and_owner_are_checked(self):
        access.prepare()
        self.directory.chmod(0o750)
        with self.assertRaises(access.AccessError):
            access.prepare()
        self.directory.chmod(0o700)
        with patch.object(access, 'ROOT_UID', os.getuid()+1), self.assertRaises(access.AccessError):
            access.prepare()

    def test_lock_link_and_unknown_files_are_preserved_and_refused(self):
        access.prepare()
        unknown = self.directory/'unknown'
        unknown.write_text('PRIVATE')
        with patch.object(access, 'keygen') as keygen, self.assertRaises(access.AccessError):
            access.prepare()
        keygen.assert_not_called()
        self.assertEqual(unknown.read_text(), 'PRIVATE')
        unknown.unlink()
        lock = self.directory/'prepare.lock'
        saved = self.root/'saved-lock'
        lock.rename(saved)
        lock.symlink_to(saved)
        with self.assertRaises(access.AccessError):
            access.prepare()
        self.assertTrue(lock.is_symlink())

    def test_existing_partial_files_are_preserved_and_never_regenerated(self):
        self.directory.mkdir(mode=0o700)
        self.private.write_text('PRIVATE EXISTING')
        self.private.chmod(0o600)
        with patch.object(access, 'keygen') as keygen, self.assertRaises(access.AccessError):
            access.prepare()
        keygen.assert_not_called()
        self.assertEqual(self.private.read_text(), 'PRIVATE EXISTING')

    def test_another_lock_holder_prevents_key_operations(self):
        access.prepare()
        with (self.directory/'prepare.lock').open('r+b') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(access, 'keygen') as keygen, self.assertRaises(access.AccessError):
                access.prepare()
            keygen.assert_not_called()

    def test_failed_generation_cleans_only_new_trusted_files_and_next_attempt_can_work(self):
        def failed(argv):
            self.private.write_text('PRIVATE GENERATED')
            self.private.chmod(0o600)
            raise access.AccessError('PRIVATE ERROR')
        with patch.object(access, 'keygen', side_effect=failed), self.assertRaises(access.AccessError) as error:
            access.prepare()
        self.assertNotIn('PRIVATE ERROR', str(error.exception))
        self.assertFalse(self.private.exists())
        self.assertFalse(self.public.exists())
        self.assertTrue((self.directory/'prepare.lock').exists())
        self.assertTrue(access.prepare()['private_key_retained_on_server'])

    def test_generation_command_timeout_also_cleans_new_files(self):
        def timed_out(argv):
            self.private.write_text('PRIVATE GENERATED')
            self.private.chmod(0o600)
            raise subprocess.TimeoutExpired('PRIVATE COMMAND', 10)
        with patch.object(access, 'keygen', side_effect=timed_out), self.assertRaises(access.AccessError) as error:
            access.prepare()
        self.assertFalse(self.private.exists())
        self.assertNotIn('PRIVATE COMMAND', str(error.exception))

    def test_failed_generation_preserves_unexpected_link_instead_of_deleting_target(self):
        target = self.root/'keep'
        target.write_text('PRIVATE KEEP')
        def failed(argv):
            self.private.symlink_to(target)
            raise access.AccessError('failure')
        with patch.object(access, 'keygen', side_effect=failed), self.assertRaises(access.AccessError):
            access.prepare()
        self.assertTrue(self.private.is_symlink())
        self.assertEqual(target.read_text(), 'PRIVATE KEEP')


class PublicReportTests(unittest.TestCase):
    def test_public_report_rejects_injected_comment_wrong_wire_and_fingerprint(self):
        wire = access.WIRE_PREFIX+b'x'*32
        public = 'ssh-ed25519 '+base64.b64encode(wire).decode()
        fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip('=')
        original = {'ssh_public_key': public, 'ssh_public_key_fingerprint': fingerprint,
                    'private_key_retained_on_server': True}
        access.validate_report(original)
        values = []
        for public_value in (public+' PRIVATE', public+'\n', 'PRIVATE', 'ssh-rsa '+public.split()[1],
                             'ssh-ed25519 '+base64.b64encode(b'x'*51).decode(),
                             'ssh-ed25519 '+base64.b64encode(wire[:-1]).decode()):
            values.append({**original, 'ssh_public_key': public_value})
        values.extend(({**original, 'ssh_public_key_fingerprint': 'PRIVATE'},
                       {**original, 'private_key_retained_on_server': False},
                       {**original, 'private_key_retained_on_server': 1},
                       {**original, 'private_key': 'PRIVATE'}))
        for value in values:
            with self.assertRaises(ValueError) as error:
                access.validate_report(value)
            self.assertNotIn('PRIVATE', str(error.exception))

    def test_bounded_command_discards_stderr_nonzero_and_oversized_output(self):
        with patch.object(access, 'KEYGEN', sys.executable):
            for program in ("import sys;print('PRIVATE');sys.exit(1)", "print('PRIVATE'*2000)",
                            "import sys;sys.stderr.write('PRIVATE');sys.exit(1)"):
                with self.assertRaises(access.AccessError) as error:
                    access.keygen(['-c', program])
                self.assertNotIn('PRIVATE', str(error.exception))

    def test_nonroot_main_prints_only_fixed_failure_and_never_reads_identity(self):
        with patch.object(access.os, 'geteuid', return_value=1000), \
                patch.object(access.resource, 'setrlimit'), patch.object(access, 'trusted_root') as root, \
                patch('sys.stdout', new_callable=io.StringIO) as output, \
                patch('sys.stderr', new_callable=io.StringIO) as error:
            with self.assertRaises(SystemExit):
                access.main()
        root.assert_not_called()
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(error.getvalue(), 'Dedicated test access could not be prepared; private contents withheld.\n')


if __name__ == '__main__':
    unittest.main()
