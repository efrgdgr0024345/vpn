"""Installation/entry-point tests use temporary directories and mocked root metadata."""
from contextlib import ExitStack
import io
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import install_helpers as installer
import privileged


class EntryPointTests(unittest.TestCase):
    def metadata(self, path):
        mode = stat.S_IFREG | 0o644 if path.name in privileged.FILES else stat.S_IFDIR | 0o755
        return SimpleNamespace(st_uid=0, st_mode=mode)

    def context(self):
        stack = ExitStack()
        stack.enter_context(patch.object(privileged, '__file__', str(privileged.ROOT / 'privileged.py')))
        stack.enter_context(patch.object(privileged.sys, 'flags', SimpleNamespace(isolated=True)))
        stack.enter_context(patch.object(privileged.os, 'geteuid', return_value=0))
        return stack

    def test_installed_trusted_metadata_is_accepted(self):
        with self.context(), patch.object(Path, 'lstat', lambda path: self.metadata(path)):
            privileged.verify_installation()

    def test_tampered_module_or_writable_parent_refused(self):
        for bad_path, bad_mode, bad_uid in (
                (privileged.ROOT / 'portal_helper.py', stat.S_IFREG | 0o664, 0),
                (privileged.ROOT / 'security.py', stat.S_IFLNK | 0o777, 0),
                (privileged.ROOT / 'safe_io.py', stat.S_IFREG | 0o644, 1000),
                (privileged.ROOT.parent, stat.S_IFDIR | 0o777, 0)):
            def metadata(path):
                return SimpleNamespace(st_mode=bad_mode, st_uid=bad_uid) if path == bad_path else self.metadata(path)
            with self.context(), patch.object(Path, 'lstat', metadata), self.assertRaises(RuntimeError):
                privileged.verify_installation()

    def test_unisolated_and_nonroot_execution_refused(self):
        with self.context(), patch.object(privileged.sys, 'flags', SimpleNamespace(isolated=False)), self.assertRaises(RuntimeError):
            privileged.verify_installation()
        with self.context(), patch.object(Path, 'lstat', lambda path: self.metadata(path)), patch.object(privileged.os, 'geteuid', return_value=1000), self.assertRaises(RuntimeError):
            privileged.verify_installation()


class InstallerTests(unittest.TestCase):
    def test_nonroot_installation_is_refused_before_writing(self):
        with patch.object(installer.os, 'geteuid', return_value=1000), self.assertRaises(RuntimeError):
            installer.main()

    def install_context(self, directory):
        # Exercise real file writes in a disposable directory only. Simulate
        # ownership for the lock; no chmod/chown/write outside that directory.
        stack = ExitStack()
        root = Path(directory)
        stack.callback(os.umask, os.umask(0o077))
        lock = root / 'lock'
        real_open, real_fstat = os.open, os.fstat
        def local_open(path, *args, **kwargs):
            return real_open(lock if str(path) == '/run/vpn-dashboard-portal.lock' else path, *args, **kwargs)
        def root_metadata(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_nlink=info.st_nlink)
        stack.enter_context(patch.object(installer, 'DESTINATION', root / 'libexec' / 'vpn-desk'))
        stack.enter_context(patch.object(installer, 'check_directory'))
        stack.enter_context(patch.object(installer.os, 'geteuid', return_value=0))
        stack.enter_context(patch.object(installer.os, 'open', side_effect=local_open))
        stack.enter_context(patch.object(installer.os, 'fstat', side_effect=root_metadata))
        stack.enter_context(patch('sys.stdout', new_callable=io.StringIO))
        return stack

    def test_real_temp_install_publishes_complete_files_with_safe_modes_and_refuses_overwrite(self):
        previous = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as directory, self.install_context(directory):
                installer.main()
                for name in installer.FILES:
                    installed = installer.DESTINATION / name
                    self.assertEqual(installed.read_bytes(), (Path(installer.__file__).parent / name).read_bytes())
                    self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o644)
                self.assertEqual(stat.S_IMODE(installer.DESTINATION.stat().st_mode), 0o755)
                with self.assertRaises(FileExistsError):
                    installer.main()
                self.assertEqual(set(p.name for p in installer.DESTINATION.iterdir()), set(installer.FILES))
        finally:
            os.umask(previous)

    def test_failed_install_does_not_leave_partial_entry_point(self):
        with tempfile.TemporaryDirectory() as directory, self.install_context(directory), \
                patch.object(installer.os, 'replace', side_effect=OSError('test failure')):
            with self.assertRaises(OSError):
                installer.main()
            self.assertFalse(installer.DESTINATION.exists())
