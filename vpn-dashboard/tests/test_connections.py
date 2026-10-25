import subprocess
import unittest
from unittest.mock import patch
import connections as c

class ConnectionTests(unittest.TestCase):
    def rows(self):
        return c.parse_ss('tcp ESTAB 0 0 10.1.2.3:43100 1.1.1.1:443 users:(("browser",pid=123,fd=9))\nudp UNCONN 0 0 [::1]:4321 [::1]:53\n')
    def test_parse_and_process(self):
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['process'], 'browser (PID 123)')
        self.assertEqual(rows[0]['direction'], 'UNKNOWN')
        self.assertEqual(rows[1]['scope'], 'loopback')
    def test_exclude_listeners_and_no_peer(self):
        raw = 'tcp LISTEN 0 100 0.0.0.0:80 0.0.0.0:*\nudp UNCONN 0 0 [::]:5353 [::]:*\nudp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\n'
        self.assertEqual(c.parse_ss(raw), [])
    def test_malformed_fails_not_empty(self):
        with self.assertRaises(c.ConnectionError):
            c.parse_ss('unexpected text')
    def test_excessive_count_refused(self):
        with self.assertRaises(c.ConnectionError):
            c.parse_ss('tcp ESTAB 0 0 1.1.1.1:2 2.2.2.2:3\n' * 2001)
    def test_no_arbitrary_process_output(self):
        self.assertEqual(c.parse_ss('tcp ESTAB 0 0 1.1.1.1:2 2.2.2.2:3 secret=DO_NOT_EXPORT')[0]['process'], 'unavailable')
    def test_history_bounded_and_delta(self):
        tracker = c.Tracker(2)
        added, removed = tracker.update(self.rows())
        self.assertEqual(len(added), 2)
        self.assertEqual(removed, [])
        self.assertEqual(tracker.update(self.rows()), ([], []))
        tracker.update([])
        self.assertEqual(len(tracker.events), 2)
        self.assertTrue(all(x['action'] == 'no longer observed' for x in tracker.events))
    def test_redacted_default_raw_explicit(self):
        rows = self.rows()
        tracker = c.Tracker()
        tracker.update(rows)
        text = c.format_export(rows, tracker.events)
        for secret in ('10.1.2.3', '1.1.1.1', 'browser', '123', '::1'):
            self.assertNotIn(secret, text)
        raw = c.format_export(rows, tracker.events, redacted=False)
        self.assertIn('10.1.2.3', raw)
        self.assertIn('browser', raw)
    @patch('connections.bounded_run')
    def test_fixed_command_timeout_no_shell(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, '', '')
        self.assertEqual(c.collect_connections(), [])
        self.assertEqual(run.call_args.args[0], c.SS_ARGV)
        self.assertEqual(run.call_args.kwargs['timeout'], 5)
        self.assertNotIn('shell', run.call_args.kwargs)
    @patch('connections.bounded_run')
    def test_failure_does_not_leak_stderr(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, '', 'private metadata')
        with self.assertRaises(c.ConnectionError) as context:
            c.collect_connections()
        self.assertNotIn('private', str(context.exception))
    @patch('connections.bounded_run', side_effect=subprocess.TimeoutExpired('ss', 5))
    def test_timeout(self, run):
        with self.assertRaises(c.ConnectionError):
            c.collect_connections()

    @patch('connections.bounded_run')
    def test_stderr_warning_refuses_partial_snapshot(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, '', 'some process metadata denied')
        with self.assertRaises(c.ConnectionError):
            c.collect_connections()
    def test_unknown_state_refused(self):
        with self.assertRaises(c.ConnectionError):
            c.parse_ss('tcp SECRET 0 0 1.1.1.1:2 2.2.2.2:3')
    def test_export_snapshot_timestamp_distinct(self):
        text = c.format_export([], [], snapshot_at='2000-01-01T00:00:00+00:00')
        self.assertIn('Last successful snapshot UTC: 2000-01-01T00:00:00+00:00', text)
        self.assertIn('Export generated UTC:', text)
