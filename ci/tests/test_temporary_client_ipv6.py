import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ops'))
import temporary_client_ipv6 as temporary


class TemporaryIPv6Tests(unittest.TestCase):
    def fixture(self, directory, *, schedule_failure=False):
        root = Path(directory)
        base = root/'conf'
        original = {'all': '0', 'default': '0', 'lo': '1', 'wlan0': '0'}
        for name, value in original.items():
            (base/name).mkdir(parents=True)
            (base/name/'disable_ipv6').write_text(value+'\n')
        module = root/'module'
        module.write_text('N\n')
        original_path = Path
        calls = []
        def path(value):
            return module if str(value) == '/sys/module/ipv6/parameters/disable' else original_path(value)
        def run(argv):
            calls.append(argv)
            if argv[0] == '/usr/sbin/nft':
                return '{"nftables": []}'
            if argv[0] == '/usr/sbin/ip':
                return '[{"ifname":"wlan0"},{"ifname":"lo"}]'
            if argv[0] == '/usr/bin/systemd-run':
                self.assertEqual({n: (base/n/'disable_ipv6').read_text().strip() for n in original}, original)
                self.assertEqual(json.loads(argv[-1]), original)
                self.assertIn('--on-active=90s', argv)
                if schedule_failure:
                    raise subprocess.CalledProcessError(1, argv)
            if argv[:2] == ['/usr/bin/systemctl', 'start']:
                scope = {'__name__': 'restore_fixture'}
                with patch.object(sys, 'argv', ['restore', json.dumps(original)]):
                    exec(temporary.RESTORE.replace('/proc/sys/net/ipv6/conf', str(base)), scope)
            return ''
        return base, original, calls, path, run

    def test_restore_is_armed_before_changes_and_snapshot_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            base, original, calls, path, run = self.fixture(directory)
            with patch.object(temporary, 'BASE', base), patch.object(temporary, 'Path', side_effect=path), \
                 patch.object(temporary.os, 'geteuid', return_value=0), \
                 patch.object(temporary.os.path, 'lexists', return_value=False), \
                 patch.object(temporary, 'run', side_effect=run):
                temporary.test()
            self.assertTrue(all((base/name/'disable_ipv6').read_text().strip()=='1' for name in original))
            self.assertEqual(calls[-1], ['/usr/bin/systemctl', 'is-active', '--quiet', temporary.UNIT+'.timer'])

    def test_scheduler_failure_leaves_original_settings_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            base, original, _, path, run = self.fixture(directory, schedule_failure=True)
            with patch.object(temporary, 'BASE', base), patch.object(temporary, 'Path', side_effect=path), \
                 patch.object(temporary.os, 'geteuid', return_value=0), \
                 patch.object(temporary.os.path, 'lexists', return_value=False), \
                 patch.object(temporary, 'run', side_effect=run), \
                 self.assertRaises(subprocess.CalledProcessError):
                temporary.test()
            self.assertEqual({n: (base/n/'disable_ipv6').read_text().strip() for n in original}, original)

    def test_timer_verification_failure_requests_immediate_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            base, original, calls, path, command = self.fixture(directory)
            def run(argv):
                if argv[1:3] == ['is-active', '--quiet']:
                    raise subprocess.CalledProcessError(1, argv)
                return command(argv)
            with patch.object(temporary, 'BASE', base), patch.object(temporary, 'Path', side_effect=path), \
                 patch.object(temporary.os, 'geteuid', return_value=0), \
                 patch.object(temporary.os.path, 'lexists', return_value=False), \
                 patch.object(temporary, 'run', side_effect=run), \
                 self.assertRaises(subprocess.CalledProcessError):
                temporary.test()
            self.assertIn(['/usr/bin/systemctl', 'start', temporary.UNIT+'.service'], calls)
            self.assertEqual({n: (base/n/'disable_ipv6').read_text().strip() for n in original}, original)

    def test_restore_handles_new_and_disappeared_interfaces(self):
        with tempfile.TemporaryDirectory() as directory:
            base, original, _, _, _ = self.fixture(directory)
            for p in base.iterdir():
                (p/'disable_ipv6').write_text('1\n')
            (base/'wlan0'/'disable_ipv6').unlink()
            (base/'wlan0').rmdir()
            (base/'new0').mkdir()
            (base/'new0'/'disable_ipv6').write_text('1\n')
            with patch.object(sys, 'argv', ['restore', json.dumps(original)]):
                exec(temporary.RESTORE.replace('/proc/sys/net/ipv6/conf', str(base)), {'__name__': 'restore_fixture'})
            self.assertEqual((base/'lo'/'disable_ipv6').read_text().strip(), '1')
            self.assertEqual((base/'new0'/'disable_ipv6').read_text().strip(), '0')
            self.assertEqual((base/'all'/'disable_ipv6').read_text().strip(), '0')
