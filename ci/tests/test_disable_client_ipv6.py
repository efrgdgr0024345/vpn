from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ops'))
import disable_client_ipv6 as disable


class DisableClientIPv6Tests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            sysctl = root/'sysctl.d'/'90-vpn-desk-ipv4-only.conf'
            grub = root/'default'/'grub.d'/'99-vpn-desk-ipv4-only.cfg'
            for path in (sysctl.parent, grub.parent, root/'proc', root/'conf'/'all', root/'conf'/'default'):
                path.mkdir(parents=True, exist_ok=True)
            base = root/'default'/'grub'
            base.write_text('GRUB_CMDLINE_LINUX="existing=preserved"\n')
            output = root/'boot'/'grub'/'grub.cfg'
            output.parent.mkdir(parents=True)
            output.write_text('linux /vmlinuz root=/dev/fixture quiet\n')
            program = root/'update-grub'
            program.write_text('#!/bin/sh\nexit 0\n')
            program.chmod(0o755)
            helper = root/'helper.py'
            helper.write_bytes(b'# reviewed IPv4-capable fixture\n')
            (root/'proc'/'cmdline').write_text('root=/dev/vda1 quiet\n')
            for name in ('all', 'default'):
                (root/'conf'/name/'disable_ipv6').write_text('0\n')
            values = {'SYSCTL': sysctl, 'GRUB': grub, 'GRUB_BASE': base,
                'UPDATE_GRUB': program, 'GRUB_OUTPUT': output,
                'STATE': root/'network-state.json', 'LOCK': root/'action.lock',
                'PROC': root/'proc', 'IPV6_CONF': root/'conf', 'MODULE_DISABLED': root/'module-disable',
                'HELPER': helper, 'IPV4_CAPABLE_HELPER': hashlib.sha256(helper.read_bytes()).hexdigest()}
            for name, value in values.items():
                stack.enter_context(patch.object(disable, name, value))
            # Security metadata gets separate real-file tests below. This fixture
            # exercises the transition/commands without requiring uid zero.
            stack.enter_context(patch.object(disable, 'trusted_directory'))
            stack.enter_context(patch.object(disable, 'read_owned', side_effect=lambda p, **kw: p.read_bytes()))
            stack.enter_context(patch.object(disable.os, 'geteuid', return_value=0))
            calls = []
            def command(argv, timeout=10):
                calls.append(argv)
                if argv[:3] == ['/usr/sbin/nft', '-j', 'list']:
                    return b'{"nftables": []}'
                if argv[:4] == ['/usr/sbin/ip', '-j', '-d', 'link']:
                    return b'[{"ifname":"lo"},{"ifname":"wlan0","flags":["UP"]}]'
                if argv[:5] == ['/usr/sbin/ip', '-j', '-4', 'route', 'show']:
                    return b'[{"dst":"default","gateway":"10.0.0.1","dev":"wlan0"}]'
                if argv[:4] == ['/usr/sbin/ip', '-j', '-6', 'address']:
                    return b'[]'
                if argv == [str(program)]:
                    output.write_text('linux /vmlinuz root=/dev/fixture quiet ipv6.disable=1\n')
                if argv[:2] == ['/usr/sbin/sysctl', '-p']:
                    for name in ('all', 'default'):
                        (root/'conf'/name/'disable_ipv6').write_text('1\n')
                return b''
            stack.enter_context(patch.object(disable, 'run', side_effect=command))
            # fstat remains real: synthetic root metadata only for this lock.
            original_fstat = os.fstat
            def metadata(fd):
                info = original_fstat(fd)
                values = list(info)
                values[4] = 0
                return os.stat_result(values)
            stack.enter_context(patch.object(disable.os, 'fstat', side_effect=metadata))
            yield root, calls

    def test_contents_match_prepared_deployment_files(self):
        root = Path(__file__).resolve().parents[2]/'deployments'/'kali'
        self.assertEqual((root/disable.SYSCTL.name).read_bytes(), disable.SYSCTL_CONTENT)
        self.assertEqual((root/disable.GRUB.name).read_bytes(), disable.GRUB_CONTENT)

    def test_apply_preserves_base_settings_and_waits_for_reboot(self):
        with self.fixture() as (_, calls):
            original = disable.GRUB_BASE.read_bytes()
            result = disable.apply()
            self.assertEqual(disable.GRUB_BASE.read_bytes(), original)
            self.assertEqual(disable.SYSCTL.read_bytes(), disable.SYSCTL_CONTENT)
            self.assertEqual(disable.GRUB.read_bytes(), disable.GRUB_CONTENT)
            self.assertTrue(result['interface_ipv6_disabled'])
            self.assertTrue(result['boot_argument_configured'])
            self.assertTrue(result['reboot_required'])
            self.assertFalse(result['kernel_ipv6_disabled'])
            self.assertEqual(stat.S_IMODE(disable.GRUB.stat().st_mode), 0o644)
            self.assertLess(calls.index([str(disable.UPDATE_GRUB)]),
                            calls.index(['/usr/sbin/sysctl', '-p', str(disable.SYSCTL)]))

    def test_exact_partial_install_resumes_and_rerun_is_idempotent(self):
        with self.fixture():
            disable.SYSCTL.write_bytes(disable.SYSCTL_CONTENT)
            for _ in range(2):
                self.assertTrue(disable.apply()['persistence_installed'])
                self.assertEqual(disable.GRUB.read_bytes(), disable.GRUB_CONTENT)

    def test_conflicting_second_destination_prevents_first_write(self):
        with self.fixture() as (_, calls):
            disable.GRUB.write_bytes(b'operator configuration\n')
            with self.assertRaises(disable.DisableError):
                disable.apply()
            self.assertFalse(disable.SYSCTL.exists())
            self.assertEqual(disable.GRUB.read_bytes(), b'operator configuration\n')
            self.assertNotIn([str(disable.UPDATE_GRUB)], calls)

    def test_saved_guard_state_prevents_configuration_changes(self):
        with self.fixture():
            disable.STATE.write_text('{}')
            with self.assertRaises(disable.DisableError):
                disable.apply()
            self.assertFalse(disable.SYSCTL.exists())
            self.assertFalse(disable.GRUB.exists())

    def test_guard_tunnel_and_missing_ipv4_default_each_refused(self):
        cases = [({'nftables': [{'table': {'name': 'vpn_guard'}}]}, None, None),
                 (None, [{'ifname': 'tun0', 'linkinfo': {'info_kind': 'tun'}}], None),
                 (None, None, [])]
        for firewall, links, routes in cases:
            with self.subTest((firewall, links, routes)), self.fixture():
                original = disable.document
                def docs(argv):
                    if firewall is not None and argv[0] == '/usr/sbin/nft':
                        return firewall
                    if links is not None and argv[:3] == ['/usr/sbin/ip', '-j', '-d']:
                        return links
                    if routes is not None and argv[:3] == ['/usr/sbin/ip', '-j', '-4']:
                        return routes
                    return original(argv)
                with patch.object(disable, 'document', side_effect=docs):
                    with self.assertRaises(disable.DisableError):
                        disable.apply()
                self.assertFalse(disable.SYSCTL.exists())

    def test_running_openvpn_is_detected_without_reading_arguments(self):
        with self.fixture() as (root, _):
            process = root/'proc'/'123'
            process.mkdir()
            (process/'exe').symlink_to('/usr/sbin/openvpn')
            with self.assertRaises(disable.DisableError):
                disable.apply()
            self.assertFalse(disable.SYSCTL.exists())

    def test_busy_action_lock_prevents_configuration_writes(self):
        with self.fixture():
            fd = os.open(disable.LOCK, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(disable.DisableError, 'VPN action is running'):
                    disable.apply()
                self.assertFalse(disable.SYSCTL.exists())
            finally:
                os.close(fd)

    def test_remaining_ipv6_address_is_not_reported_as_success(self):
        with self.fixture():
            original = disable.document
            def docs(argv):
                if argv[:4] == ['/usr/sbin/ip', '-j', '-6', 'address']:
                    return [{'ifname': 'wlan0', 'addr_info': [{'family': 'inet6'}]}]
                return original(argv)
            with patch.object(disable, 'document', side_effect=docs):
                with self.assertRaisesRegex(disable.DisableError, 'immediate disablement'):
                    disable.apply()

    def test_unknown_helper_is_refused_before_writes(self):
        with self.fixture():
            disable.HELPER.write_bytes(b'# unreviewed helper\n')
            with self.assertRaises(disable.DisableError):
                disable.apply()
            self.assertFalse(disable.SYSCTL.exists())

    def test_grub_command_failure_leaves_owned_files_for_safe_resume(self):
        with self.fixture():
            original = disable.run
            def command(argv, timeout=10):
                if argv == [str(disable.UPDATE_GRUB)]:
                    raise disable.DisableError('failed fixture')
                return original(argv, timeout=timeout)
            with patch.object(disable, 'run', side_effect=command):
                with self.assertRaises(disable.DisableError):
                    disable.apply()
            self.assertEqual(disable.SYSCTL.read_bytes(), disable.SYSCTL_CONTENT)
            self.assertFalse(disable.status()['interface_ipv6_disabled'])
            self.assertTrue(disable.apply()['interface_ipv6_disabled'])

    def test_generated_grub_requires_every_linux_entry_to_disable_ipv6(self):
        cases = [
            ('linux /vmlinuz root=/dev/fixture ipv6.disable=1\n', True),
            ('\tlinuxefi /vmlinuz root=/dev/fixture "ipv6.disable=1"\n', True),
            ('linux /one ipv6.disable=1\n linuxefi /two ipv6.disable=1\n', True),
            ('# linux /not-an-entry ipv6.disable=0\nlinux /vmlinuz ipv6.disable=1\n', True),
            ('linux /one ipv6.disable=1\nlinux /two quiet\n', False),
            ('linux /vmlinuz ipv6.disable=1 ipv6.disable=0\n', False),
            ('linux /vmlinuz ipv6.disable=0 ipv6.disable=1\n', False),
            ('linux /vmlinuz ipv6.disable=1 ipv6.disable=1\n', False),
            ('linux /vmlinuz ipv6.disable=yes\n', False),
            ('linux /vmlinuz other="ipv6.disable=1"\n', False),
            ('linux /vmlinuz "unterminated\n', False),
            ('# no Linux boot entries\n', False),
        ]
        with self.fixture():
            for value, expected in cases:
                with self.subTest(value=value):
                    disable.GRUB_OUTPUT.write_text(value)
                    self.assertEqual(disable.generated_boot_argument(), expected)
            disable.GRUB_OUTPUT.unlink()
            self.assertFalse(disable.generated_boot_argument())

    def test_missing_or_overridden_generated_boot_argument_stops_before_sysctl(self):
        for generated in (None, 'linux /vmlinuz quiet\n',
                          'linux /vmlinuz ipv6.disable=1 ipv6.disable=0\n'):
            with self.subTest(generated=generated), self.fixture() as (_, calls):
                original = disable.run
                def command(argv, timeout=10):
                    if argv == [str(disable.UPDATE_GRUB)]:
                        if generated is None:
                            disable.GRUB_OUTPUT.unlink()
                        else:
                            disable.GRUB_OUTPUT.write_text(generated)
                        return b''
                    return original(argv, timeout=timeout)
                with patch.object(disable, 'run', side_effect=command):
                    with self.assertRaisesRegex(disable.DisableError, 'Generated GRUB'):
                        disable.apply()
                self.assertNotIn(['/usr/sbin/sysctl', '-p', str(disable.SYSCTL)], calls)
                self.assertFalse(disable.status()['boot_argument_configured'])

    def test_saved_dropins_do_not_replace_generated_boot_proof(self):
        with self.fixture():
            disable.SYSCTL.write_bytes(disable.SYSCTL_CONTENT)
            disable.GRUB.write_bytes(disable.GRUB_CONTENT)
            result = disable.status()
            self.assertTrue(result['persistence_installed'])
            self.assertFalse(result['boot_argument_configured'])

    def test_post_reboot_check_requires_boot_argument_and_module_disable(self):
        with self.fixture() as (root, _):
            disable.apply()
            (root/'module-disable').write_text('Y\n')
            result = disable.status()
            self.assertTrue(result['kernel_ipv6_disabled'])
            self.assertTrue(result['reboot_required'])
            (root/'proc'/'cmdline').write_text('root=/dev/vda1 ipv6.disable=1 quiet\n')
            self.assertFalse(disable.status()['reboot_required'])

    def test_read_owned_refuses_symlinks_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(disable, 'trusted_directory'):
            path = Path(directory)/'public'
            path.write_bytes(b'value')
            link = Path(directory)/'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                disable.read_owned(link)
            link.unlink()
            os.link(path, link)
            with self.assertRaises(disable.DisableError):
                disable.read_owned(path)

    def test_root_process_exceptions_do_not_print_command_output(self):
        with patch.object(disable.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), \
                self.assertRaisesRegex(disable.DisableError, 'required system check'):
            disable.run(['/usr/bin/false'])


if __name__ == '__main__':
    unittest.main()
