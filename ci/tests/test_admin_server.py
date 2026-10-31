"""Private panel HTTP/auth boundaries and an actual isolated TLS exchange."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load_module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT/'vpn-admin'/file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


panel = load_module('panel_web_server_tests', 'server.py')
schema = load_module('panel_web_schema_tests', 'schema.py')
PASSWORD = 'fixture-only-administrator-password-123456'
PEER = '172.27.240.10'
STAMP = '2026-10-31T10:11:12+00:00'
SALT = b'fixture-salt-123'
DIGEST = hashlib.scrypt(PASSWORD.encode(), salt=SALT, n=32768, r=8, p=1,
                        dklen=32, maxmem=64*1024*1024)
VERIFIER = {'version': 1, 'salt': base64.b64encode(SALT).decode(),
            'hash': base64.b64encode(DIGEST).decode(), 'n': 32768, 'r': 8, 'p': 1}


def snapshot():
    return {'version': 1, 'generated_at': STAMP, 'monotonic': 100.0,
        'services': [{'unit': unit, 'active_state': 'active', 'sub_state': 'running',
                      'restarts': 0, 'result': 'success'} for unit in schema.SERVICE_UNITS],
        'tunnel': {'present': True, 'kind': 'tun', 'up': True, 'ipv4': ['172.27.240.1/24']},
        'authorization': {'element_count': 1, 'addresses': [{'ipv4': PEER, 'expires_ms': 17000}]},
        'devices': [{'name': name, 'enabled': True, 'address': '172.27.240.'+str(index+10),
                     'certificate_sha256': str(index+1)*64} for index, name in enumerate(schema.DEVICE_NAMES)],
        'ipv6': {'kernel_disabled': True, 'boot_argument_active': True}, 'events': [],
        'dns_probe': {'status': 'ok', 'rcode': 0, 'answer_count': 2, 'elapsed_ms': 1}}


class BytesChannel:
    def __init__(self, value, chunk=8192):
        self.value, self.chunk = value, chunk

    def recv(self, count):
        length = min(count, self.chunk)
        value, self.value = self.value[:length], self.value[length:]
        return value


class RequestTests(unittest.TestCase):
    def parse(self, value, chunk=8192):
        return panel.read_request(BytesChannel(value, chunk))

    def rejected(self, value, code=None):
        with self.assertRaises(panel.HTTPError) as error:
            self.parse(value)
        if code is not None:
            self.assertEqual(error.exception.status, code)

    def test_split_transport_reads_are_reassembled_with_exact_body(self):
        body = b'{"password":"fixture"}'
        raw = b'POST /api/login HTTP/1.1\r\nHost: 172.27.240.1:8443\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        for chunk in (1, 7, 8192):
            method, target, headers, value = self.parse(raw, chunk)
            self.assertEqual((method, target, value), ('POST', '/api/login', body))
            self.assertEqual(headers['host'], '172.27.240.1:8443')

    def test_duplicate_and_conflicting_framing_headers_are_refused(self):
        examples = [b'Host: one\r\nHost: two', b'Content-Length: 0\r\ncontent-length: 2',
                    b'Transfer-Encoding: chunked\r\nContent-Length: 0',
                    b'Expect: 100-continue', b'Content-Length: -1', b'Content-Length: 00',
                    b'Content-Length: +0', b'Host : example', b' folded: header',
                    b'Host: one\x00two']
        for headers in examples:
            with self.subTest(headers=headers):
                self.rejected(b'GET / HTTP/1.1\r\n'+headers+b'\r\n\r\n', 400)

    def test_pipeline_and_get_payload_are_not_accepted(self):
        self.rejected(b'GET / HTTP/1.1\r\nHost: host\r\n\r\nGET /api/status HTTP/1.1\r\n\r\n', 400)
        self.rejected(b'GET / HTTP/1.1\r\nContent-Length: 1\r\n\r\nx', 413)

    def test_oversized_headers_body_and_many_headers_are_refused(self):
        self.rejected(b'GET / HTTP/1.1\r\nX: '+b'x'*(panel.MAX_HEADERS+1), 431)
        self.rejected(b'POST /api/login HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 1025\r\n\r\n', 413)
        headers = b'\r\n'.join(('X-'+str(i)+': value').encode() for i in range(65))
        self.rejected(b'GET / HTTP/1.1\r\n'+headers+b'\r\n\r\n', 431)

    def test_unsupported_protocol_queries_methods_and_media_type_refused(self):
        for raw, code in ((b'GET / HTTP/1.0\r\n\r\n', 400),
                          (b'GET /?token=private HTTP/1.1\r\n\r\n', 400),
                          (b'GET /%2e%2e/etc/shadow HTTP/1.1\r\n\r\n', 400),
                          (b'DELETE /api/status HTTP/1.1\r\n\r\n', 405),
                          (b'POST /api/login HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n', 415),
                          (b'GET / HTTP/1.1\r\nX: \xff\r\n\r\n', 400)):
            with self.subTest(raw=raw):
                self.rejected(raw, code)

    def test_truncated_header_and_body_refused(self):
        self.rejected(b'GET / HTTP/1.1\r\nHost: one', 400)
        self.rejected(b'POST /api/login HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\nx', 400)


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.auth = panel.Authentication(copy.deepcopy(VERIFIER), clock=lambda: self.now)

    def assert_http(self, code, function, *args):
        with self.assertRaises(panel.HTTPError) as error:
            function(*args)
        self.assertEqual(error.exception.status, code)

    def login(self):
        return self.auth.login(PASSWORD, PEER)

    def test_verifier_parameters_types_and_lengths_are_strict(self):
        values = [{**VERIFIER, 'password': 'PRIVATE'}, {**VERIFIER, 'version': True},
                  {**VERIFIER, 'n': 2**22}, {**VERIFIER, 'r': True},
                  {**VERIFIER, 'salt': '!bad!'}, {**VERIFIER, 'salt': base64.b64encode(b'short').decode()},
                  {**VERIFIER, 'hash': base64.b64encode(b'short').decode()}]
        for value in values:
            with self.subTest(value=value), self.assertRaises(panel.Refused):
                panel.Authentication(value)

    def test_wrong_password_and_invalid_formats_are_unauthorized(self):
        for value in ('wrong-password-but-long-enough', '', None, 3, 'x'*257, 'é'*25):
            with self.subTest(value=value):
                self.assert_http(401, self.auth.login, value, PEER)

    def test_session_bound_to_peer_and_login_rotates_previous_session(self):
        token, csrf = self.login()
        cookie = panel.COOKIE+'='+token
        self.assertEqual(self.auth.session(cookie, PEER), (token, csrf))
        self.assert_http(401, self.auth.session, cookie, '172.27.240.11')
        self.assertEqual(self.auth.session(cookie, PEER), (token, csrf))
        second, _ = self.login()
        self.assertNotEqual(token, second)
        self.assert_http(401, self.auth.session, cookie, PEER)
        self.assertEqual(len(self.auth.sessions), 1)

    def test_idle_session_expires_and_logout_removes_it(self):
        token, _ = self.login()
        cookie = panel.COOKIE+'='+token
        self.now += 900
        self.assert_http(401, self.auth.session, cookie, PEER)
        token, _ = self.login()
        self.auth.logout(token)
        self.assert_http(401, self.auth.session, panel.COOKIE+'='+token, PEER)

    def test_absolute_expiry_cannot_be_extended_by_polling(self):
        token, _ = self.login()
        cookie = panel.COOKIE+'='+token
        for age in (899, 1798, 2697, 3596):
            self.now = 100+age
            self.auth.session(cookie, PEER)
        self.now = 3700
        self.assert_http(401, self.auth.session, cookie, PEER)

    def test_duplicate_invalid_or_missing_session_cookies_refused(self):
        token, _ = self.login()
        for cookie in ('', panel.COOKIE+'=bad', panel.COOKIE+'='+token+'; '+panel.COOKIE+'='+token):
            self.assert_http(401, self.auth.session, cookie, PEER)

    def test_global_attempt_budget_and_concurrent_derivation_bound(self):
        with patch.object(panel.hashlib, 'scrypt', return_value=b'x'*32):
            for _ in range(8):
                self.assert_http(401, self.auth.login, PASSWORD, PEER)
            self.assert_http(429, self.auth.login, PASSWORD, '172.27.240.11')
            self.now += 60
            self.assert_http(401, self.auth.login, PASSWORD, PEER)
        self.auth.derivations.acquire()
        try:
            self.assert_http(429, self.auth.login, PASSWORD, PEER)
        finally:
            self.auth.derivations.release()


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.auth = panel.Authentication(copy.deepcopy(VERIFIER), clock=lambda: self.now)
        self.value = snapshot()
        self.reads = []
        self.unavailable = False
        def reader(path, **kwargs):
            self.reads.append(Path(path))
            if path == Path(panel.EXPECTED_CONFIG['snapshot']):
                if self.unavailable:
                    raise FileNotFoundError()
                return json.dumps(self.value).encode()
            return b'public static fixture'
        self.app = panel.Application(copy.deepcopy(panel.EXPECTED_CONFIG), self.auth,
                                     schema.validate_snapshot, reader=reader, clock=lambda: self.now)

    def request(self, method, path, body=None, headers=None, peer=PEER):
        defaults = {'host': '172.27.240.1:8443'}
        if method == 'POST':
            defaults['origin'] = panel.EXPECTED_CONFIG['origin']
        defaults.update(headers or {})
        raw = json.dumps(body).encode() if body is not None else b''
        return self.app.dispatch((method, path, defaults, raw), peer)

    def login(self):
        status, body, headers = self.request('POST', '/api/login', {'password': PASSWORD})
        self.assertEqual(status, 200)
        return headers['Set-Cookie'].split(';', 1)[0], json.loads(body)['csrf_token'], headers

    def test_history_requires_auth_and_rejects_duplicate_filters(self):
        calls=[]
        self.app.history_reader=lambda parameters: calls.append(parameters) or {'version':1,'available':True,'records':[]}
        with self.assertRaises(panel.HTTPError) as error:
            self.request('GET','/api/history')
        self.assertEqual(error.exception.status,401)
        self.assertEqual(calls,[])
        cookie,_,_=self.login()
        headers={'cookie':cookie}
        status,body,_=self.request('GET','/api/history?device=kali&search=example.com',headers=headers)
        self.assertEqual(status,200)
        self.assertEqual(calls,[{'device':'kali','search':'example.com'}])
        with self.assertRaises(panel.HTTPError) as error:
            self.request('GET','/api/history?device=kali&device=android',headers=headers)
        self.assertEqual(error.exception.status,400)

    def test_history_storage_failure_does_not_disclose_sql_or_private_paths(self):
        cookie,_,_=self.login()
        def unavailable(parameters): raise RuntimeError('PRIVATE SQL failure')
        self.app.history_reader=unavailable
        status,body,_=self.request('GET','/api/history',headers={'cookie':cookie})
        self.assertEqual(json.loads(body),{'version':1,'available':False})
        self.assertEqual(status,200)

    def test_cookie_flags_and_success_response_do_not_disclose_verifier(self):
        cookie, csrf, headers = self.login()
        for flag in ('Path=/', 'Secure', 'HttpOnly', 'SameSite=Strict', 'Max-Age=3600'):
            self.assertIn(flag, headers['Set-Cookie'])
        self.assertTrue(cookie.startswith('__Host-'))
        self.assertRegex(csrf, r'\A[A-Za-z0-9_-]{43}\Z')
        self.assertNotIn(PASSWORD, json.dumps(headers))

    def test_private_api_requires_authentication(self):
        with self.assertRaises(panel.HTTPError) as error:
            self.request('GET', '/api/status')
        self.assertEqual(error.exception.status, 401)

    def test_origin_host_source_and_fetch_metadata_checked_before_auth(self):
        examples = [({'host': 'attacker.example'}, PEER), ({'host': '172.27.240.1'}, PEER),
                    ({'origin': 'https://attacker.example'}, PEER), ({'origin': 'null'}, PEER),
                    ({'sec-fetch-site': 'cross-site'}, PEER), ({}, '127.0.0.1'),
                    ({}, '192.0.2.1'), ({}, '172.27.240.1'), ({}, '172.27.240.255')]
        for headers, peer in examples:
            with self.subTest(headers=headers, peer=peer), self.assertRaises(panel.HTTPError) as error:
                self.request('POST', '/api/login', {'password': PASSWORD}, headers, peer)
            self.assertEqual(error.exception.status, 403)

    def test_login_strict_json_rejects_extra_fields_and_duplicate_password(self):
        for value in ({'password': PASSWORD, 'operation': 'reboot'}, [], {'password': PASSWORD, 'username': 'root'}):
            with self.subTest(value=value), self.assertRaises(panel.HTTPError) as error:
                self.request('POST', '/api/login', value)
            self.assertEqual(error.exception.status, 400)
        headers = {'host': '172.27.240.1:8443', 'origin': panel.EXPECTED_CONFIG['origin']}
        with self.assertRaises(panel.HTTPError) as error:
            self.app.dispatch(('POST', '/api/login', headers, b'{"password":"a","password":"b"}'), PEER)
        self.assertEqual(error.exception.status, 400)

    def test_status_current_stale_future_missing_and_secret_injection(self):
        cookie, csrf, _ = self.login()
        headers = {'cookie': cookie}
        status, raw, _ = self.request('GET', '/api/status', headers=headers)
        value = json.loads(raw)
        self.assertEqual(status, 200)
        self.assertFalse(value['stale'])
        self.assertEqual(value['csrf_token'], csrf)
        for tick in (self.now-91, self.now+1):
            self.value['monotonic'] = tick
            self.assertTrue(json.loads(self.request('GET', '/api/status', headers=headers)[1])['stale'])
        self.unavailable = True
        result = json.loads(self.request('GET', '/api/status', headers=headers)[1])
        self.assertFalse(result['available'])
        self.assertIsNone(result['snapshot'])
        self.unavailable = False
        self.value['password'] = 'PRIVATE_SENTINEL'
        raw = self.request('GET', '/api/status', headers=headers)[1]
        self.assertNotIn(b'PRIVATE_SENTINEL', raw)
        self.assertFalse(json.loads(raw)['available'])

    def test_logout_requires_csrf_and_origin_then_invalidates_cookie(self):
        cookie, csrf, _ = self.login()
        for headers in ({'cookie': cookie}, {'cookie': cookie, 'x-csrf-token': 'wrong'},
                        {'cookie': cookie, 'x-csrf-token': csrf, 'origin': 'https://attacker.example'}):
            with self.subTest(headers=headers), self.assertRaises(panel.HTTPError) as error:
                self.request('POST', '/api/logout', {}, headers)
            self.assertEqual(error.exception.status, 403)
        _, _, headers = self.request('POST', '/api/logout', {}, {'cookie': cookie, 'x-csrf-token': csrf})
        self.assertIn('Max-Age=0', headers['Set-Cookie'])
        with self.assertRaises(panel.HTTPError) as error:
            self.request('GET', '/api/status', headers={'cookie': cookie})
        self.assertEqual(error.exception.status, 401)

    def test_static_route_allowlist_never_turns_urls_into_file_paths(self):
        before = self.reads.copy()
        for target in ('/etc/shadow', '/../../etc/shadow', '/static/../server.py', '/static/server.key'):
            with self.subTest(target=target), self.assertRaises(panel.HTTPError) as error:
                self.request('GET', target)
            self.assertEqual(error.exception.status, 404)
        self.assertEqual(self.reads, before)
        for target in ('/', '/static/app.js', '/static/style.css', '/ca.crt'):
            self.assertEqual(self.request('GET', target)[0], 200)

    def test_wire_security_headers_close_connections_and_never_reflect_requests(self):
        raw = panel.wire_response(429, b'{"error":"Request refused."}')
        self.assertIn(b'Connection: close\r\n', raw)
        self.assertIn(b'Retry-After: 60\r\n', raw)
        self.assertIn(b'Cache-Control: no-store\r\n', raw)
        self.assertIn(b'frame-ancestors \'none\'', raw)
        self.assertNotIn(b'Server:', raw)


class ProtectedFileTests(unittest.TestCase):
    def test_links_permissions_and_size_limits_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = root/'data'
            value.write_bytes(b'public fixture')
            value.chmod(0o640)
            real_fstat = os.fstat
            def root_metadata(fd):
                data = list(real_fstat(fd))
                data[4] = 0
                return os.stat_result(data)
            parent = os.stat_result((stat.S_IFDIR|0o755, 1, 1, 1, 0, 0, 0, 0, 0, 0))
            with patch.object(panel.Path, 'lstat', return_value=parent), \
                 patch.object(panel.os, 'fstat', side_effect=root_metadata):
                self.assertEqual(panel.read_protected(value, secret=True), b'public fixture')
                value.chmod(0o644)
                with self.assertRaises(panel.Refused):
                    panel.read_protected(value, secret=True)
                value.chmod(0o660)
                with self.assertRaises(panel.Refused):
                    panel.read_protected(value)
                value.chmod(0o640)
                with self.assertRaises(panel.Refused):
                    panel.read_protected(value, limit=3)
                link = root/'link'
                link.symlink_to(value)
                with self.assertRaises(OSError):
                    panel.read_protected(link)
                link.unlink()
                os.link(value, link)
                with self.assertRaises(panel.Refused):
                    panel.read_protected(value)


class RealTLSPanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        root = Path(cls.temporary.name)
        cls.key, cls.cert = root/'key.pem', root/'cert.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(cls.key), '-out', str(cls.cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True, timeout=20)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def exchange(self, context, address, request):
        with socket.create_connection(address, timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname='localhost') as connection:
                self.assertEqual(connection.version(), 'TLSv1.3')
                connection.sendall(request)
                data = bytearray()
                while True:
                    part = connection.recv(8192)
                    if not part:
                        return bytes(data)
                    data.extend(part)
                    self.assertLess(len(data), 300000)

    def contexts(self):
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.minimum_version = ssl.TLSVersion.TLSv1_3
        server.load_cert_chain(self.cert, self.key)
        client = ssl.create_default_context(cafile=str(self.cert))
        client.minimum_version = ssl.TLSVersion.TLSv1_3
        return server, client

    def test_absolute_deadline_closes_a_nonidle_slow_request(self):
        server_context, client_context = self.contexts()
        original_timer = threading.Timer
        def deadline(interval, callback):
            self.assertEqual(interval, 15)
            return original_timer(.2, callback)
        class NeverDispatch:
            def dispatch(self, request, peer):
                raise AssertionError('Incomplete request reached application.')
        with patch.object(panel.threading, 'Timer', side_effect=deadline), \
             panel.Server(('127.0.0.1', 0), server_context, NeverDispatch()) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=2) as raw:
                    with client_context.wrap_socket(raw, server_hostname='localhost') as connection:
                        connection.sendall(b'POST /api/login HTTP/1.1\r\nHost: 172.27.240.1:8443\r\nContent-Type: application/json\r\nContent-Length: 512\r\n\r\n')
                        started = time.monotonic()
                        # Bytes keep arriving well inside the socket's inactivity
                        # timeout. Only the separate absolute deadline ends this.
                        while time.monotonic()-started < .9:
                            try:
                                connection.sendall(b'x')
                            except OSError:
                                break
                            time.sleep(.025)
                        else:
                            self.fail('Trickled request bypassed the absolute connection deadline.')
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_saturated_admission_rejects_tls_without_dispatching(self):
        server_context, client_context = self.contexts()
        calls = []
        class NeverDispatch:
            def dispatch(self, request, peer):
                calls.append(request)
                return 200, b'{}', {}
        with panel.Server(('127.0.0.1', 0), server_context, NeverDispatch()) as server:
            for _ in range(16):
                self.assertTrue(server.capacity.acquire(blocking=False))
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=2) as raw:
                    with self.assertRaises((ssl.SSLError, ConnectionResetError)):
                        client_context.wrap_socket(raw, server_hostname='localhost')
                self.assertEqual(calls, [])
            finally:
                for _ in range(16):
                    server.capacity.release()
                server.shutdown()
                thread.join(timeout=5)

    def test_real_tls_login_status_cookie_logout_and_generic_errors(self):
        authentication = panel.Authentication(copy.deepcopy(VERIFIER))
        value = snapshot()
        value['monotonic'] = panel.time.monotonic()
        def reader(path, **kwargs):
            return json.dumps(value).encode() if Path(path) == Path(panel.EXPECTED_CONFIG['snapshot']) else b'public fixture'
        app = panel.Application(copy.deepcopy(panel.EXPECTED_CONFIG), authentication,
                                schema.validate_snapshot, reader=reader)
        # Loopback is used only by this isolated test harness. Production keeps
        # the real VPN peer and rejects localhost at the application boundary.
        class VPNPeerFixture:
            def dispatch(self, request, peer):
                return app.dispatch(request, PEER)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = ssl.TLSVersion.TLSv1_3
        server_context.load_cert_chain(self.cert, self.key)
        client_context = ssl.create_default_context(cafile=str(self.cert))
        client_context.minimum_version = ssl.TLSVersion.TLSv1_3
        log = io.StringIO()
        with panel.Server(('127.0.0.1', 0), server_context, VPNPeerFixture()) as server, \
             redirect_stdout(log), redirect_stderr(log):
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
            thread.start()
            try:
                def request(method, target, body=b'', extra=b''):
                    headers = (method+' '+target+' HTTP/1.1\r\nHost: 172.27.240.1:8443\r\n').encode()
                    if method == 'POST':
                        headers += b'Origin: https://172.27.240.1:8443\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n'
                    return headers+extra+b'\r\n'+body
                body = json.dumps({'password': PASSWORD}).encode()
                response = self.exchange(client_context, server.server_address, request('POST', '/api/login', body))
                head, raw = response.split(b'\r\n\r\n', 1)
                self.assertTrue(head.startswith(b'HTTP/1.1 200'))
                cookie = next(line.split(b': ', 1)[1].split(b';', 1)[0] for line in head.split(b'\r\n') if line.startswith(b'Set-Cookie:'))
                csrf = json.loads(raw)['csrf_token']
                response = self.exchange(client_context, server.server_address,
                                         request('GET', '/api/status', extra=b'Cookie: '+cookie+b'\r\n'))
                self.assertTrue(response.startswith(b'HTTP/1.1 200'))
                self.assertFalse(json.loads(response.split(b'\r\n\r\n', 1)[1])['stale'])
                response = self.exchange(client_context, server.server_address,
                                         request('POST', '/api/logout', b'{}', b'Cookie: '+cookie+b'\r\nX-CSRF-Token: '+csrf.encode()+b'\r\n'))
                self.assertTrue(response.startswith(b'HTTP/1.1 200'))
                response = self.exchange(client_context, server.server_address,
                                         request('GET', '/api/status', extra=b'Cookie: '+cookie+b'\r\n'))
                self.assertTrue(response.startswith(b'HTTP/1.1 401'))
                response = self.exchange(client_context, server.server_address,
                                         request('POST', '/api/login', b'PRIVATE_SENTINEL_NOT_JSON'))
                self.assertTrue(response.startswith(b'HTTP/1.1 400'))
                self.assertNotIn(b'PRIVATE_SENTINEL', response)
                legacy_context = ssl.create_default_context(cafile=str(self.cert))
                legacy_context.maximum_version = ssl.TLSVersion.TLSv1_2
                with socket.create_connection(server.server_address, timeout=5) as raw_socket:
                    with self.assertRaises(ssl.SSLError):
                        legacy_context.wrap_socket(raw_socket, server_hostname='localhost')
            finally:
                server.shutdown()
                thread.join(timeout=5)
        self.assertEqual(log.getvalue(), '')
