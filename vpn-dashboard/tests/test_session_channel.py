import copy
import unittest
from unittest.mock import patch
import session_channel as channel


class SessionEventsTests(unittest.TestCase):
    def test_secrets_and_unstructured_lines_never_become_log_text(self):
        secrets=(
            'PUSH_REPLY,auth-token SESS_ID_AT_SECRET,Initialization Sequence Completed',
            'password=SECRET Initialization Sequence Completed',
            'private key SECRET Control Channel: TLSv1.3',
            'ECHO: Initialization Sequence Completed',
            'unrecognized server text SECRET',
            'x'*8193,
        )
        for line in secrets:
            self.assertIsNone(channel.classify(line))
        events=channel.Events()
        for line in ('2026-10-27 10:00:00 VERIFY OK: depth=0, CN=SECRETNAME',
                     '2026-10-27 10:00:01 Control Channel: TLSv1.3, cipher SECRET',
                     '2026-10-27 10:00:02 Initialization Sequence Completed'):
            events.add(channel.classify(line))
        text=channel.format_events(events.snapshot())
        self.assertNotIn('SECRET',text)
        self.assertEqual(events.snapshot()['state'],'tunnel_ready')
        self.assertIn('still require validation',text)

    def test_auth_failure_and_reconnect_are_not_reported_ready(self):
        events=channel.Events()
        events.add('tunnel_ready')
        events.add(channel.classify('AUTH: Received control message: AUTH_FAILED,SECRET'))
        self.assertEqual(events.snapshot()['state'],'error')
        events.add(channel.classify('SIGUSR1[soft,tls-error] received, process restarting'))
        self.assertEqual(events.snapshot()['state'],'reconnecting')

    def test_history_is_bounded_and_order_is_checked(self):
        events=channel.Events()
        for _ in range(500):
            events.add('rekey')
        snapshot=events.snapshot()
        self.assertEqual(len(snapshot['events']),300)
        channel.validate_snapshot(snapshot)
        snapshot['events'][1]['sequence']=1
        with self.assertRaises(channel.ChannelError):
            channel.validate_snapshot(snapshot)

    def test_unknown_schema_free_text_and_duplicate_sequence_fail(self):
        events=channel.Events()
        events.add('starting')
        original=events.snapshot()
        cases=[{**original,'password':'SECRET'},{**original,'state':['bad']},
               {**original,'version':True}]
        for key,value in (('code','SECRET'),('code',[]),('utc','not a timestamp'),
                          ('utc','2026-10-29\n01:00:00+00:00'),('sequence',True)):
            snapshot=copy.deepcopy(original)
            snapshot['events'][0][key]=value
            cases.append(snapshot)
        for snapshot in cases:
            with self.assertRaises(channel.ChannelError):
                channel.validate_snapshot(snapshot)

    def test_stop_is_not_available_to_unprivileged_client(self):
        with patch.object(channel.os,'geteuid',return_value=1000),self.assertRaises(channel.ChannelError):
            channel.request('stop')
        with self.assertRaises(channel.ChannelError):
            channel.request('run-command')
