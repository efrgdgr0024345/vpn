import socket
import struct
import threading
import os
import unittest
from unittest.mock import MagicMock, patch

import session_channel
import vpn_session_helper as session


IDENTIFIER = 1234
SOURCE = '172.27.240.10'
PEER = ('172.27.240.1', 53)


def reply(*, flags=0x8180, question=None, answer=None, identifier=IDENTIFIER):
    if question is None:
        question = session.DNS_QUESTION
    if answer is None:
        answer = b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 30, 4)+b'\x5d\xb8\xd8\x22'
    return struct.pack('!6H', identifier, flags, 1, int(bool(answer)), 0, 0)+question+answer


class DNSReplyTests(unittest.TestCase):
    def test_only_a_complete_matching_a_answer_is_healthy(self):
        self.assertEqual(session.dns_reply_status(reply(), IDENTIFIER), 'ok')
        self.assertEqual(session.dns_reply_status(reply(answer=b''), IDENTIFIER), 'no_answer')
        unrelated = b'\x05other\x03com\x00'+struct.pack('!HHIH', 1, 1, 30, 4)+b'\x01\x02\x03\x04'
        self.assertEqual(session.dns_reply_status(reply(answer=unrelated), IDENTIFIER), 'no_answer')

    def test_dns_errors_and_truncation_are_distinguished(self):
        for flags, status in ((0x8182, 'servfail'), (0x8185, 'refused'),
                              (0x8183, 'rcode_error'), (0x8380, 'truncated')):
            self.assertEqual(session.dns_reply_status(reply(flags=flags, answer=b''), IDENTIFIER), status)

    def test_wrong_transaction_question_opcode_and_query_are_rejected(self):
        for packet in (reply(identifier=1235), reply(flags=0x0180), reply(flags=0x8980), reply(flags=0x81c0),
                       reply(question=b'\x05other\x03com\x00'+struct.pack('!HH', 1, 1)),
                       reply(question=session.DNS_QUESTION[:-4]+struct.pack('!HH', 28, 1))):
            self.assertEqual(session.dns_reply_status(packet, IDENTIFIER), 'invalid')

    def test_incomplete_oversized_looping_and_structurally_bad_records_are_rejected(self):
        for packet in (b'', reply()[:-1], reply()+b'extra', b'x'*4097,
                       reply(answer=b'\xc0\xff'+struct.pack('!HHIH', 1, 1, 30, 4)+b'abcd'),
                       reply(answer=b'\xc0\x1d'+struct.pack('!HHIH', 1, 1, 30, 4)+b'abcd'),
                       reply(answer=b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 30, 3)+b'abc')):
            self.assertEqual(session.dns_reply_status(packet, IDENTIFIER), 'invalid')

    def test_a_bounded_cname_chain_is_supported_without_accepting_additional_records(self):
        target = b'\x03www\x07example\x03com\x00'
        cname = b'\xc0\x0c'+struct.pack('!HHIH', 5, 1, 30, len(target))+target
        address = target+struct.pack('!HHIH', 1, 1, 30, 4)+b'abcd'
        packet = struct.pack('!6H', IDENTIFIER, 0x8180, 1, 2, 0, 0)+session.DNS_QUESTION+cname+address
        self.assertEqual(session.dns_reply_status(packet, IDENTIFIER), 'ok')
        packet = struct.pack('!6H', IDENTIFIER, 0x8180, 1, 1, 0, 1)+session.DNS_QUESTION+cname+address
        self.assertEqual(session.dns_reply_status(packet, IDENTIFIER), 'no_answer')


class DNSRouteTests(unittest.TestCase):
    def test_route_and_matching_up_tunnel_address_are_required(self):
        route = [{'dev': 'tun0', 'prefsrc': SOURCE}]
        link = [{'ifname': 'tun0', 'flags': ['UP'], 'addr_info': [{'family': 'inet', 'local': SOURCE}]}]
        with patch.object(session, 'diagnostic', side_effect=[route, link]) as diagnostic:
            self.assertEqual(session.dns_tunnel_source(), SOURCE)
        self.assertEqual(diagnostic.call_args_list[0].args[0][-1], PEER[0])
        for routes, links in ((None, link), ([], link), ([{'dev': 'wlan0', 'prefsrc': SOURCE}], link),
                              ([{'dev': 'tun0', 'prefsrc': '127.0.0.1'}], link),
                              ([{'dev': 'tun0', 'prefsrc': '0.0.0.0'}], link),
                              ([{'dev': 'tun0', 'prefsrc': SOURCE, 'type': 'blackhole'}], link),
                              (route, []), (route, [{**link[0], 'flags': []}]),
                              (route, [{**link[0], 'addr_info': [{'family': 'inet', 'local': '172.27.240.11'}]}])):
            with patch.object(session, 'diagnostic', side_effect=[routes, links]), \
                    patch.object(session.socket, 'socket') as socket_factory:
                self.assertEqual(session.private_dns_probe(), ('route_unavailable', 0))
            socket_factory.assert_not_called()

    def test_socket_is_bound_to_verified_tunnel_source_and_private_dns_only(self):
        channel = MagicMock()
        channel.recvfrom.return_value = (reply(), PEER)
        channel.__enter__.return_value = channel
        with patch.object(session, 'dns_tunnel_source', return_value=SOURCE), \
                patch.object(session.socket, 'socket', return_value=channel) as factory, \
                patch.object(session.secrets, 'randbelow', return_value=IDENTIFIER):
            status, elapsed = session.private_dns_probe()
        self.assertEqual(status, 'ok')
        self.assertGreaterEqual(elapsed, 0)
        factory.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        channel.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'tun0\0')
        channel.bind.assert_called_once_with((SOURCE, 0))
        channel.connect.assert_called_once_with(PEER)
        channel.settimeout.assert_called_once_with(3)
        channel.send.assert_called_once_with(struct.pack('!6H', IDENTIFIER, 0x0100, 1, 0, 0, 0)+session.DNS_QUESTION)

    def test_timeout_transport_failure_and_wrong_peer_never_use_another_socket(self):
        for outcome, expected in ((socket.timeout(), 'timeout'), (OSError(), 'transport_failed'),
                                  ((reply(), ('192.0.2.1', 53)), 'invalid')):
            channel = MagicMock()
            channel.__enter__.return_value = channel
            if isinstance(outcome, Exception):
                channel.recvfrom.side_effect = outcome
            else:
                channel.recvfrom.return_value = outcome
            with patch.object(session, 'dns_tunnel_source', return_value=SOURCE), \
                    patch.object(session.socket, 'socket', return_value=channel) as factory:
                self.assertEqual(session.private_dns_probe()[0], expected)
            self.assertEqual(factory.call_count, 1)
            channel.connect.assert_called_once_with(PEER)

    def test_untrusted_reply_bytes_are_never_retained_or_formatted(self):
        channel = MagicMock()
        channel.__enter__.return_value = channel
        channel.recvfrom.return_value = (reply()+b'PRIVATE_DNS_REPLY_TEXT', PEER)
        with patch.object(session, 'dns_tunnel_source', return_value=SOURCE), \
                patch.object(session.socket, 'socket', return_value=channel), \
                patch.object(session.secrets, 'randbelow', return_value=IDENTIFIER):
            status, elapsed = session.private_dns_probe()
        events = session_channel.Events()
        events.add('tunnel_ready')
        events.set_details({'dns_health': status, 'dns_latency_ms': elapsed})
        events.add('dns_'+status)
        report = session_channel.format_events(events.snapshot())
        self.assertNotIn('PRIVATE_DNS_REPLY_TEXT', report)
        self.assertIn('Ctrl+C', report)
        self.assertIn('Restore normal networking', report)


class DNSHealthWatchTests(unittest.TestCase):
    def test_sigterm_request_during_health_publication_does_not_reenter_the_lock(self):
        read_fd, write_fd = os.pipe()
        real_close = os.close
        os.write(write_fd, b'Initialization Sequence Completed\n')
        process = MagicMock()
        process.pid = 1234
        process.stdout = os.fdopen(read_fd, 'rb', buffering=0)
        process.returncode = None
        process.poll.side_effect = lambda: process.returncode
        process.wait.return_value = 0
        handlers = {}
        sent = threading.Event()
        closed = threading.Event()
        def register(number, handler):
            handlers[number] = handler
        def terminate(*args):
            process.returncode = 0
            if not closed.is_set():
                real_close(write_fd)
                closed.set()
        def poll(watch, now):
            if watch.active and not sent.is_set():
                sent.set()
                handlers[session.signal.SIGTERM](session.signal.SIGTERM, None)
            return []
        results = []
        with patch.object(session.session_channel, 'Server', return_value=MagicMock()), \
                patch.object(session.subprocess, 'Popen', return_value=process), \
                patch.object(session.os, 'pidfd_open', return_value=1234), \
                patch.object(session.os, 'close'), patch.object(session.signal, 'signal', side_effect=register), \
                patch.object(session.signal, 'pidfd_send_signal', side_effect=terminate), \
                patch.object(session.network_setup, 'verify_during_session', return_value=True), \
                patch.object(session, 'tunnel_details'), patch.object(session, 'retain_last'), \
                patch.object(session.DNSHealthWatch, 'poll', poll), patch('builtins.print'):
            runner = threading.Thread(target=lambda: results.append(session.controlled_session(['fixture'], 1000)), daemon=True)
            try:
                runner.start()
                runner.join(3)
                self.assertFalse(runner.is_alive(), 'SIGTERM handling deadlocked during DNS status publication.')
                self.assertTrue(sent.is_set())
                self.assertEqual(results, [0])
            finally:
                if not closed.is_set():
                    real_close(write_fd)
                process.stdout.close()

    def test_probe_is_nonblocking_and_single_outstanding_then_rechecks_after_30_seconds(self):
        entered = threading.Event()
        release = threading.Event()
        def probe():
            entered.set()
            release.wait(2)
            return 'ok', 7
        watch = session.DNSHealthWatch()
        self.assertEqual(watch.poll(0), [])
        watch.observe('tunnel_ready')
        with patch.object(session, 'private_dns_probe', side_effect=probe) as call:
            try:
                self.assertEqual(watch.poll(0), [('dns_checking', {'dns_health': 'checking', 'dns_latency_ms': 0})])
                self.assertTrue(entered.wait(1))
                self.assertEqual(watch.poll(1), [])
                self.assertEqual(watch.poll(29), [])
                self.assertEqual(call.call_count, 1)
            finally:
                release.set()
                watch.worker.join(1)
            self.assertEqual(watch.poll(29), [('dns_ok', {'dns_health': 'ok', 'dns_latency_ms': 7})])
            self.assertEqual(watch.poll(30)[-1][0], 'dns_checking')
            watch.worker.join(1)

    def test_old_probe_cannot_mark_reconnected_or_stopping_session_healthy(self):
        entered = threading.Event()
        release = threading.Event()
        def probe():
            entered.set()
            release.wait(2)
            return 'ok', 7
        for next_event in ('reconnecting', 'stopping'):
            watch = session.DNSHealthWatch()
            watch.observe('tunnel_ready')
            with patch.object(session, 'private_dns_probe', side_effect=probe):
                try:
                    watch.poll(0)
                    self.assertTrue(entered.wait(1))
                    self.assertEqual(watch.observe(next_event)['dns_health'], 'unchecked')
                finally:
                    release.set()
                    watch.worker.join(1)
            self.assertEqual(watch.poll(1), [])
            if next_event == 'reconnecting':
                watch.observe('tunnel_ready')
                with patch.object(session, 'private_dns_probe', return_value=('servfail', 1)):
                    watch.poll(2)
                    watch.worker.join(1)
                self.assertEqual(watch.poll(3), [('dns_servfail', {'dns_health': 'servfail', 'dns_latency_ms': 1})])
            entered.clear()
            release.clear()

    def test_dns_failure_does_not_fail_or_stop_the_openvpn_session(self):
        events = session_channel.Events()
        events.add('tunnel_ready')
        for status in session_channel.DNS_HEALTH:
            events.set_details({'dns_health': status, 'dns_latency_ms': 0})
            if status not in ('unchecked', 'checking'):
                events.add('dns_'+status)
        self.assertEqual(events.snapshot()['state'], 'tunnel_ready')
        self.assertFalse(events.failed)
        for value in ({'dns_health': 'RAW DNS RESPONSE'}, {'dns_latency_ms': -1}, {'dns_latency_ms': True}):
            with self.assertRaises(session_channel.ChannelError):
                session_channel.validate_details(value)
