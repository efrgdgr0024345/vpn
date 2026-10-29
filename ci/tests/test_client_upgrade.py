from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ops'))
import upgrade_client_transport as upgrade

OLD = b'# reviewed old fixture\n'
NEW = b'# reviewed new fixture\n'


class UpgradeTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            base = Path(directory)
            app, helpers = base / 'app', base / 'helpers'
            app.mkdir()
            helpers.mkdir()
            helper, manifest = helpers / 'vpn_session_helper.py', app / 'install-manifest.json'
            exact = {str(base / 'launcher'), str(base / 'menu.desktop')}
            files = {str(helper): upgrade.digest(OLD)}
            helper.write_bytes(OLD)
            for path in [*(Path(p) for p in exact), *(app / ('public'+str(i)+'.py') for i in range(7))]:
                path.write_bytes(b'# public fixture\n')
                files[str(path)] = upgrade.digest(path.read_bytes())
            manifest.write_text(json.dumps({'version': 1, 'files': files}))
            private = base / 'client.ovpn'
            private.write_bytes(b'private fixture must remain unchanged')
            real_fstat = os.fstat
            def root_metadata(fd):
                info = real_fstat(fd)
                return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink)
            for name, value in {'HELPER': helper, 'MANIFEST': manifest, 'LOCK': base/'lock',
                                'ROOTS': (app, helpers), 'EXACT': exact,
                                'OLD_SHA256': upgrade.digest(OLD)}.items():
                stack.enter_context(patch.object(upgrade, name, value))
            stack.enter_context(patch.object(upgrade.os, 'fstat', side_effect=root_metadata))
            stack.enter_context(patch.object(upgrade, 'read_file', side_effect=lambda p: p.read_bytes()))
            stack.enter_context(patch.object(upgrade.subprocess, 'run', return_value=
                                            subprocess.CompletedProcess([], 1, '', '')))
            yield base, private
            self.assertEqual(private.read_bytes(), b'private fixture must remain unchanged')

    def test_checked_update_and_same_version_rerun_preserve_private_settings(self):
        with self.fixture():
            for _ in range(2):
                upgrade.upgrade(NEW, upgrade.digest(NEW))
                self.assertEqual(upgrade.HELPER.read_bytes(), NEW)
                self.assertEqual(json.loads(upgrade.MANIFEST.read_text())['files'][str(upgrade.HELPER)],
                                 upgrade.digest(NEW))
                self.assertEqual(stat.S_IMODE(upgrade.HELPER.stat().st_mode), 0o644)

    def test_unknown_transport_or_other_installed_changes_are_preserved(self):
        for target in ('transport', 'other'):
            with self.subTest(target=target), self.fixture():
                path = upgrade.HELPER if target == 'transport' else next(upgrade.ROOTS[0].glob('public*.py'))
                path.write_bytes(b'unknown change\n')
                before = upgrade.MANIFEST.read_bytes()
                with self.assertRaises(upgrade.UpgradeError):
                    upgrade.upgrade(NEW, upgrade.digest(NEW))
                self.assertEqual(path.read_bytes(), b'unknown change\n')
                self.assertEqual(upgrade.MANIFEST.read_bytes(), before)

    def test_unexpected_shadow_module_is_refused(self):
        with self.fixture():
            (upgrade.ROOTS[1] / 'unexpected.py').write_bytes(b'pass\n')
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(upgrade.HELPER.read_bytes(), OLD)

    def test_bad_candidate_hash_or_syntax_is_refused_before_lock_or_writes(self):
        for value, expected in ((NEW, '0'*64), (b'invalid (\n', upgrade.digest(b'invalid (\n'))):
            with self.fixture():
                with self.assertRaises(upgrade.UpgradeError):
                    upgrade.upgrade(value, expected)
                self.assertFalse(upgrade.LOCK.exists())
                self.assertEqual(upgrade.HELPER.read_bytes(), OLD)

    def test_inventory_cannot_redirect_writes_or_read_private_material(self):
        with self.fixture() as (_, private):
            document = json.loads(upgrade.MANIFEST.read_text())
            document['files'][str(private)] = upgrade.digest(private.read_bytes())
            upgrade.MANIFEST.write_text(json.dumps(document))
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(upgrade.HELPER.read_bytes(), OLD)

    def test_active_process_and_held_action_lock_refuse_upgrade(self):
        with self.fixture(), patch.object(upgrade.subprocess, 'run', return_value=
                                          subprocess.CompletedProcess([], 0, '123\n', '')):
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(upgrade.HELPER.read_bytes(), OLD)
        with self.fixture(), patch.object(upgrade.fcntl, 'flock', side_effect=BlockingIOError):
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(upgrade.HELPER.read_bytes(), OLD)

    def test_known_interrupted_pair_can_finish_without_blessing_other_changes(self):
        with self.fixture():
            publish = upgrade.publish
            def interrupt(path, value):
                if path == upgrade.MANIFEST:
                    raise OSError('fixture power loss')
                publish(path, value)
            with patch.object(upgrade, 'publish', side_effect=interrupt):
                with self.assertRaises(OSError):
                    upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(upgrade.HELPER.read_bytes(), NEW)
            upgrade.upgrade(NEW, upgrade.digest(NEW))
            self.assertEqual(json.loads(upgrade.MANIFEST.read_text())['files'][str(upgrade.HELPER)],
                             upgrade.digest(NEW))

    def test_source_metadata_still_rejects_writes_symlinks_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'SUDO_UID': str(os.getuid())}):
            source = Path(directory) / 'source.py'
            source.write_bytes(NEW)
            source.chmod(0o644)
            self.assertEqual(upgrade.read_file(source, source=True), NEW)
            source.chmod(0o666)
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.read_file(source, source=True)
            source.chmod(0o644)
            link = source.with_name('link.py')
            link.symlink_to(source)
            with self.assertRaises(OSError):
                upgrade.read_file(link, source=True)
            link.unlink()
            os.link(source, link)
            with self.assertRaises(upgrade.UpgradeError):
                upgrade.read_file(source, source=True)
