from contextlib import ExitStack, contextmanager, nullcontext
import copy
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'ops'))
import client_diagnostics as diagnostics


LOGIN = b'vpn-lab-client\nSECRET_DIAGNOSTIC_FIXTURE_password_1234567890\n'


class CredentialTests(unittest.TestCase):
    @contextmanager
    def fixture(self, value=LOGIN):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'login.txt'
            path.write_bytes(value)
            path.chmod(0o600)
            yield path

    def assert_safe_failure(self, function, *args):
        with self.assertRaises(diagnostics.DiagnosticError) as error:
            function(*args)
        self.assertNotIn('SECRET', str(error.exception))
        self.assertNotIn('password_1234567890', str(error.exception))

    def test_private_two_line_owner_credentials_are_accepted_without_modification(self):
        with self.fixture() as path:
            self.assertEqual(diagnostics.credentials(path, os.getuid()), LOGIN)
            self.assertEqual(path.read_bytes(), LOGIN)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_wrong_owner_and_public_or_group_writable_credentials_are_refused(self):
        with self.fixture() as path:
            real_fstat = os.fstat
            def foreign_owner(fd):
                values = list(real_fstat(fd))
                values[4] = os.getuid()+2
                return os.stat_result(values)
            with patch.object(diagnostics.os, 'fstat', side_effect=foreign_owner):
                self.assert_safe_failure(diagnostics.credentials, path, os.getuid())
            for mode in (0o644, 0o640, 0o660, 0o400):
                path.chmod(mode)
                self.assert_safe_failure(diagnostics.credentials, path, os.getuid())

    def test_symlinks_hardlinks_and_fifo_inputs_are_refused_without_changing_targets(self):
        with self.fixture() as original:
            linked = original.parent/'linked'
            linked.symlink_to(original)
            self.assert_safe_failure(diagnostics.credentials, linked, os.getuid())
            linked.unlink()
            os.link(original, linked)
            self.assert_safe_failure(diagnostics.credentials, linked, os.getuid())
            self.assert_safe_failure(diagnostics.credentials, original, os.getuid())
            linked.unlink()
            fifo = original.parent/'fifo'
            os.mkfifo(fifo, 0o600)
            program = ('import sys;sys.path.insert(0,'+repr(str(ROOT/'ops'))+');'
                       'import client_diagnostics as d\n'
                       'try:d.credentials('+repr(str(fifo))+','+str(os.getuid())+')\n'
                       'except d.DiagnosticError:print("refused")\n'
                       'else:raise SystemExit(1)\n')
            result = subprocess.run([sys.executable, '-I', '-B', '-c', program],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual((result.returncode, result.stdout.strip()), (0, 'refused'))
            self.assertEqual(original.read_bytes(), LOGIN)

    def test_credentials_require_exact_username_two_lf_lines_and_printable_ascii(self):
        for value in (LOGIN.rstrip(b'\n'), LOGIN+b'\n', LOGIN+b'extra\n',
                      LOGIN.replace(b'vpn-lab-client', b'root'),
                      LOGIN.replace(b'\n', b'\r\n'),
                      b'vpn-lab-client\nshort\n',
                      b'vpn-lab-client\n'+b'x'*19+b'\n',
                      b'vpn-lab-client\nSECRET password_with_space_12345\n',
                      b'vpn-lab-client\nSECRET\x00password\n',
                      b'vpn-lab-client\nSECRET\tpassword\n',
                      b'vpn-lab-client\nSECRET\x7fpassword_1234567890\n',
                      b'vpn-lab-client\nSECRET\xffpassword\n',
                      b'vpn-lab-client\n'+b'SECRET'+b'x'*520+b'\n'):
            with self.subTest(length=len(value)), self.fixture(value) as path:
                self.assert_safe_failure(diagnostics.credentials, path, os.getuid())
                self.assertEqual(path.read_bytes(), value)


class BaselineTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            base = Path(temporary)
            app, helpers = base/'app', base/'helpers'
            app.mkdir()
            helpers.mkdir()
            manifest = app/'install-manifest.json'
            exact = {str(base/'launcher'), str(base/'menu.desktop')}
            files = {}
            helper_names = ('privileged.py', 'security.py', 'safe_io.py', 'portal_helper.py',
                            'vpn_session_helper.py', 'session_channel.py', 'network_setup.py', 'firewall_policy.py')
            paths = [*(helpers/name for name in helper_names),
                     *(app/name for name in ('app.py', 'install_audit.py', 'session_ui.py', 'session_channel.py')),
                     *(Path(name) for name in exact)]
            for path in paths:
                # A baseline verifier must hash these files without importing
                # them. Executing any fixture module would fail this test.
                value = b'raise RuntimeError("public fixture must not execute")\n'
                path.write_bytes(value)
                path.chmod(0o644)
                files[str(path)] = hashlib.sha256(value).hexdigest()
            manifest.write_text(json.dumps({'version': 1, 'files': files}))
            manifest.chmod(0o644)
            for name, value in {'APP': app, 'HELPERS': helpers, 'ROOTS': (app, helpers),
                                'MANIFEST': manifest, 'EXACT': exact, 'ROOT_UID': os.getuid()}.items():
                stack.enter_context(patch.object(diagnostics, name, value))
            # The temporary directory's parent is /tmp. Only ancestor trust is
            # substituted; file owner/modes/links/content hashes remain real.
            stack.enter_context(patch.object(diagnostics, 'trusted_parents'))
            yield base, app, helpers, manifest, files

    def assert_safe_failure(self, function, *args):
        with self.assertRaises(diagnostics.DiagnosticError) as error:
            function(*args)
        self.assertNotIn('SECRET', str(error.exception))

    def test_verified_root_baseline_is_hashed_before_any_protected_import(self):
        with self.fixture():
            diagnostics.verify_installation()

    def test_modified_module_or_unrecorded_shadow_module_is_refused(self):
        for change in ('changed', 'shadow'):
            with self.subTest(change=change), self.fixture() as (_, _, helpers, _, _):
                target = helpers/('security.py' if change == 'changed' else 'json.py')
                target.write_bytes(b'# SECRET unexpected public code\n')
                target.chmod(0o644)
                self.assert_safe_failure(diagnostics.verify_installation)

    def test_inventory_cannot_add_private_or_outside_paths(self):
        with self.fixture() as (base, _, _, manifest, files):
            outside = base/'private'
            outside.write_bytes(b'SECRET private fixture')
            outside.chmod(0o600)
            files[str(outside)] = hashlib.sha256(outside.read_bytes()).hexdigest()
            manifest.write_text(json.dumps({'version': 1, 'files': files}))
            self.assert_safe_failure(diagnostics.verify_installation)
            self.assertEqual(outside.read_bytes(), b'SECRET private fixture')

    def test_group_writable_code_or_manifest_and_linked_modules_are_refused(self):
        for change in ('code_mode', 'manifest_mode', 'symlink', 'hardlink'):
            with self.subTest(change=change), self.fixture() as (base, _, helpers, manifest, _):
                target = helpers/'security.py'
                if change == 'code_mode':
                    target.chmod(0o664)
                elif change == 'manifest_mode':
                    manifest.chmod(0o664)
                elif change == 'symlink':
                    held = base/'held.py'
                    target.rename(held)
                    target.symlink_to(held)
                else:
                    os.link(target, base/'held.py')
                self.assert_safe_failure(diagnostics.verify_installation)

    def test_missing_required_helper_is_refused_even_if_removed_from_manifest(self):
        with self.fixture() as (_, _, helpers, manifest, files):
            missing = helpers/'network_setup.py'
            missing.unlink()
            del files[str(missing)]
            manifest.write_text(json.dumps({'version': 1, 'files': files}))
            self.assert_safe_failure(diagnostics.verify_installation)


class LifecycleTests(unittest.TestCase):
    def test_timed_out_owned_child_is_signalled_only_by_pidfd_and_is_not_killed(self):
        process = Mock(pid=4321)
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired('controlled fixture', 15)
        with patch.object(diagnostics, 'child_status') as status, \
                patch.object(diagnostics.signal, 'pidfd_send_signal') as send:
            stopped = diagnostics.stop_owned(process, 99, 1000, ('old',), {})
        self.assertFalse(stopped)
        status.assert_called_once_with(4321, 1000, ('old',), {}, 'stop')
        send.assert_called_once_with(99, diagnostics.signal.SIGTERM)
        process.wait.assert_called_once_with(timeout=15)
        process.kill.assert_not_called()
        process.terminate.assert_not_called()

    def test_restore_is_withheld_when_child_or_state_ownership_is_unproven(self):
        portal = SimpleNamespace(active_openvpn=Mock(return_value=False))
        network = SimpleNamespace(restore=Mock())
        modules = {'portal_helper': portal, 'network_setup': network}
        for proof, stopped, expected in ((True, False, 'child_running'), (False, True, 'ownership_unproven')):
            recovery = diagnostics.new_report()['recovery']
            with patch.object(diagnostics, 'locked') as lock:
                diagnostics.restore_owned(modules, proof, stopped, recovery)
            self.assertEqual(recovery['restore_withheld'], expected)
            self.assertFalse(recovery['restored'])
            lock.assert_not_called()
            network.restore.assert_not_called()
            portal.active_openvpn.assert_not_called()

    def test_active_openvpn_saved_state_and_lock_failures_cannot_release_guard(self):
        for active, state, lock_failure, expected in (
                (True, True, False, 'active_openvpn'),
                (False, False, False, 'state_missing'),
                (False, True, True, 'lock_busy')):
            network = SimpleNamespace(restore=Mock())
            portal = SimpleNamespace(active_openvpn=Mock(return_value=active))
            modules = {'portal_helper': portal, 'network_setup': network}
            recovery = diagnostics.new_report()['recovery']
            with patch.object(diagnostics, 'locked', side_effect=(
                    diagnostics.DiagnosticError('lock_busy') if lock_failure else lambda path:nullcontext())), \
                    patch.object(diagnostics.os.path, 'lexists', return_value=state):
                diagnostics.restore_owned(modules, True, True, recovery)
            self.assertEqual(recovery['restore_withheld'], expected)
            self.assertFalse(recovery['restored'])
            network.restore.assert_not_called()

    def test_restore_refusal_does_not_expose_exception_or_report_recovery_success(self):
        network = SimpleNamespace(restore=Mock(side_effect=RuntimeError('SECRET failure details')))
        modules = {'portal_helper': SimpleNamespace(active_openvpn=lambda:False), 'network_setup': network}
        recovery = diagnostics.new_report()['recovery']
        with patch.object(diagnostics, 'locked', side_effect=lambda path:nullcontext()), \
                patch.object(diagnostics.os.path, 'lexists', return_value=True):
            diagnostics.restore_owned(modules, True, True, recovery)
        self.assertTrue(recovery['restore_attempted'])
        self.assertFalse(recovery['restored'])
        self.assertEqual(recovery['restore_withheld'], 'restore_refused')
        self.assertNotIn('SECRET', json.dumps(recovery))

    def test_stale_or_wrong_pid_socket_is_not_trusted_or_sent_control_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'session.sock'
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(path))
                path.chmod(0o600)
                server.listen(1)
                server.settimeout(.1)
                validator = Mock()
                modules = {'session_channel': SimpleNamespace(validate_snapshot=validator)}
                with patch.object(diagnostics, 'SOCKET', path), \
                        patch.object(diagnostics, 'ROOT_UID', os.getuid()), \
                        patch.object(diagnostics, 'trusted_parents'):
                    stamp = diagnostics.socket_stamp()
                    self.assertIsNone(diagnostics.child_status(os.getpid(), os.getuid(), stamp, modules, 'stop'))
                    with self.assertRaises(socket.timeout):
                        server.accept()
                    received = []
                    def listen():
                        connection, _ = server.accept()
                        with connection:
                            connection.settimeout(1)
                            received.append(connection.recv(128))
                    listener = threading.Thread(target=listen, daemon=True)
                    listener.start()
                    self.assertIsNone(diagnostics.child_status(os.getpid()+1, os.getuid(), None, modules, 'stop'))
                    listener.join(2)
                    self.assertFalse(listener.is_alive())
                    self.assertEqual(received, [b''])
                    validator.assert_not_called()

    def test_child_launch_has_no_interactive_stdio_or_credentials_in_arguments(self):
        process = Mock(pid=1234)
        with patch.object(diagnostics.os, 'pipe2', return_value=(11, 12)), \
                patch.object(diagnostics.subprocess, 'Popen', return_value=process) as popen, \
                patch.object(diagnostics.os, 'pidfd_open', return_value=13), \
                patch.object(diagnostics.os, 'write', return_value=1), \
                patch.object(diagnostics.os, 'close'):
            self.assertEqual(diagnostics.launch(1000), (process, 13))
        argv = popen.call_args.args[0]
        options = popen.call_args.kwargs
        self.assertEqual(argv[:4], ['/usr/bin/python3', '-I', '-B', '-c'])
        self.assertIn('test_credentials=True', argv[4])
        self.assertNotIn('SECRET', repr(argv))
        for stream in ('stdin', 'stdout', 'stderr'):
            self.assertEqual(options[stream], subprocess.DEVNULL)

    def test_restore_flag_is_required_before_any_attempt_or_credential_read(self):
        with patch.object(diagnostics, 'load_modules') as loader, \
                patch.object(diagnostics, 'credentials') as login:
            report = diagnostics.run_test(1000)
        self.assertEqual(report['outcome'], 'restore_not_authorized')
        loader.assert_not_called()
        login.assert_not_called()
        with patch.object(sys, 'argv', ['client-diagnostics', '--credentials', '/private/SECRET']), \
                patch.object(diagnostics, 'run_test') as run, patch('sys.stderr', io.StringIO()), \
                self.assertRaises(SystemExit) as error:
            diagnostics.main()
        self.assertEqual(error.exception.code, 2)
        run.assert_not_called()

    def test_attempt_timeout_auth_failure_and_interruption_clean_up_under_test_mutex(self):
        modules = {'security': SimpleNamespace(load_policy=lambda:{'wifi_interface':'wlan0'}),
                   'portal_helper': SimpleNamespace(check_network=lambda:None, js=lambda argv:{'nftables':[]}),
                   'network_setup': SimpleNamespace(resolver_read=lambda:'nameserver 192.0.2.1\n'),
                   'session_channel': SimpleNamespace()}
        before = {'guard_present':False, 'state_present':False, 'tun_present':False,
                  'routes':[{'destination':'default', 'interface':'wlan0', 'gateway':'192.0.2.1'}],
                  'physical_route':{'interface':'wlan0'}}
        for failure in ('attempt_timeout', 'auth_failed', 'interrupted'):
            with self.subTest(failure=failure), ExitStack() as stack:
                held = set()
                @contextmanager
                def lock(path):
                    held.add(path)
                    try:
                        yield
                    finally:
                        held.remove(path)
                events = [{'code':code} for code in ('guard_checked','dns_configured','credentials')]
                if failure == 'auth_failed':
                    events.append({'code':'auth_failed'})
                snapshot = {'state':'error' if failure == 'auth_failed' else 'connecting', 'events':events}
                process = SimpleNamespace(pid=1234, returncode=None, poll=lambda:None)
                def finish(report, *args):
                    self.assertIn(diagnostics.TEST_LOCK, held)
                    report['recovery'].update(child_stopped=True, restored=True, confirmed=True)
                clock = itertools.count(0, 5)
                for name, value in {
                        'load_modules': lambda:modules, 'locked': lock,
                        'network_snapshot': lambda *args:before, 'credentials': lambda *args:LOGIN,
                        'socket_stamp': lambda:None, 'launch': lambda owner:(process, 999),
                        'child_status': lambda *args:snapshot, 'finish_test': finish}.items():
                    stack.enter_context(patch.object(diagnostics, name, side_effect=value))
                stack.enter_context(patch.object(diagnostics.time, 'monotonic', side_effect=lambda:next(clock)))
                stack.enter_context(patch.object(diagnostics.time, 'sleep'))
                stack.enter_context(patch.object(diagnostics.os, 'close'))
                stack.enter_context(patch.object(diagnostics, '_INTERRUPTED', failure == 'interrupted'))
                stack.enter_context(patch.object(diagnostics, '_REPORT_CHANNEL', None))
                report = diagnostics.run_test(1000, restore_after_test=True)
                self.assertEqual(report['outcome'], failure)
                self.assertTrue(report['recovery']['confirmed'])
                self.assertNotIn('SECRET', json.dumps(report))


class ReportTests(unittest.TestCase):
    def test_only_typed_structural_data_can_be_emitted(self):
        report = diagnostics.new_report()
        diagnostics.validate_report(report)
        variants = []
        for section, key in ((None, 'password'), ('recovery', 'raw_output')):
            value = copy.deepcopy(report)
            (value if section is None else value[section])[key] = 'SECRET'
            variants.append(value)
        for key, value in (('kernel', 'SECRET\nRAW OUTPUT'), ('outcome', 'SECRET'), ('credentials', 'SECRET')):
            variants.append({**report, key:value})
        variants.append({**report, 'before':{'password':'SECRET'}})
        for value in variants:
            with self.assertRaises(diagnostics.DiagnosticError) as error:
                diagnostics.validate_report(value)
            self.assertNotIn('SECRET', str(error.exception))


if __name__ == '__main__':
    unittest.main()
