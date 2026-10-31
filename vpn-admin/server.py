"""Private HTTPS status panel. No privileged commands or VPN control socket."""
import base64
from collections import deque
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import secrets
import socket
import socketserver
import ssl
import stat
import sys
import threading
import time

CODE = Path('/opt/vpn-lab-admin')
CONFIG = Path('/etc/vpn-lab-admin/config.json')
PUBLIC_CA = Path('/etc/vpn-lab-admin/ca.crt')
COOKIE = '__Host-vpn-admin'
MAX_HEADERS = 16384
MAX_BODY = 1024
EXPECTED_CONFIG = {'version': 1, 'bind': '172.27.240.1', 'port': 8443,
    'origin': 'https://172.27.240.1:8443', 'snapshot': '/run/vpn-lab-admin/status.json',
    'auth': '/etc/vpn-lab-admin/auth.json', 'certificate': '/etc/vpn-lab-admin/server.crt',
    'private_key': '/etc/vpn-lab-admin/server.key', 'static': str(CODE/'static')}
SECURITY_HEADERS = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"}


class Refused(ValueError):
    pass


class HTTPError(ValueError):
    def __init__(self, status):
        self.status = status


def read_protected(path, *, limit=262144, secret=False):
    path = Path(path)
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused('Unprotected panel directory.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & (0o027 if secret else 0o022)):
            raise Refused('Unprotected panel file.')
        value = stream.read(limit+1)
    if len(value) > limit:
        raise Refused('Panel file exceeds its limit.')
    return value


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError('Duplicate JSON field.')
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs)


def read_request(channel):
    """One bounded HTTP/1.1 request; connection reuse and transfer coding refused."""
    data = bytearray()
    while b'\r\n\r\n' not in data:
        part = channel.recv(1024)
        if not part:
            raise HTTPError(400)
        data.extend(part)
        if len(data) > MAX_HEADERS+MAX_BODY:
            raise HTTPError(431)
        marker = data.find(b'\r\n\r\n')
        if marker < 0 and len(data) > MAX_HEADERS or marker > MAX_HEADERS:
            raise HTTPError(431)
    head, body = bytes(data).split(b'\r\n\r\n', 1)
    if len(head) > MAX_HEADERS:
        raise HTTPError(431)
    try:
        lines = head.decode('ascii').split('\r\n')
        method, target, version = lines[0].split(' ')
    except (ValueError, UnicodeError):
        raise HTTPError(400) from None
    if version != 'HTTP/1.1' or not re.fullmatch(r'/[A-Za-z0-9/._-]*', target):
        raise HTTPError(400)
    if method not in ('GET', 'POST'):
        raise HTTPError(405)
    if len(lines) > 65:
        raise HTTPError(431)
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(':')
        key = key.lower()
        if (not sep or not re.fullmatch(r'[a-z0-9-]{1,64}', key) or key in headers
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise HTTPError(400)
        headers[key] = value.strip()
    if 'transfer-encoding' in headers or 'expect' in headers:
        raise HTTPError(400)
    length = headers.get('content-length', '0')
    if not re.fullmatch(r'0|[1-9][0-9]{0,3}', length):
        raise HTTPError(400)
    length = int(length)
    if length > MAX_BODY or method == 'GET' and length:
        raise HTTPError(413)
    if method == 'POST' and headers.get('content-type', '').lower() != 'application/json':
        raise HTTPError(415)
    if len(body) > length:
        raise HTTPError(400)
    while len(body) < length:
        part = channel.recv(length-len(body))
        if not part:
            raise HTTPError(400)
        body += part
    return method, target, headers, body


class Authentication:
    def __init__(self, verifier, *, clock=time.monotonic):
        if (not isinstance(verifier, dict) or set(verifier) != {'version', 'salt', 'hash', 'n', 'r', 'p'}
                or type(verifier['version']) is not int or verifier['version'] != 1
                or any(type(verifier[name]) is not int for name in ('n', 'r', 'p'))
                or (verifier['n'], verifier['r'], verifier['p']) != (32768, 8, 1)):
            raise Refused('Unsupported administrator verifier.')
        try:
            self.salt = base64.b64decode(verifier['salt'], validate=True)
            self.digest = base64.b64decode(verifier['hash'], validate=True)
        except (ValueError, TypeError):
            raise Refused('Unsupported administrator verifier.') from None
        if len(self.salt) != 16 or len(self.digest) != 32:
            raise Refused('Unsupported administrator verifier.')
        self.clock = clock
        self.attempts = deque()
        self.sessions = {}
        self.lock = threading.RLock()
        self.derivations = threading.BoundedSemaphore(1)

    def login(self, password, peer):
        with self.lock:
            now = self.clock()
            while self.attempts and now-self.attempts[0] >= 60:
                self.attempts.popleft()
            if len(self.attempts) >= 8:
                raise HTTPError(429)
            self.attempts.append(now)
        if not self.derivations.acquire(blocking=False):
            raise HTTPError(429)
        try:
            good_format = isinstance(password, str) and re.fullmatch(r'[!-~]{20,256}', password) is not None
            candidate = password.encode('ascii') if good_format else b''
            derived = hashlib.scrypt(candidate, salt=self.salt, n=32768, r=8, p=1,
                                     dklen=32, maxmem=64*1024*1024)
            if not hmac.compare_digest(derived, self.digest) or not good_format:
                raise HTTPError(401)
        finally:
            self.derivations.release()
        with self.lock:
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            # One administrator identity: a fresh login retires older sessions.
            self.sessions.clear()
            self.sessions[token] = {'csrf': csrf, 'peer': peer, 'created': self.clock(), 'seen': self.clock()}
            return token, csrf

    def session(self, cookie, peer):
        token = None
        for pair in cookie.split(';'):
            key, sep, value = pair.strip().partition('=')
            if key == COOKIE and sep:
                if token is not None or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
                    raise HTTPError(401)
                token = value
        with self.lock:
            now = self.clock()
            for old, value in list(self.sessions.items()):
                if now-value['seen'] >= 900 or now-value['created'] >= 3600:
                    self.sessions.pop(old)
            value = self.sessions.get(token)
            if value is None or value['peer'] != peer:
                raise HTTPError(401)
            value['seen'] = now
            return token, value['csrf']

    def logout(self, token):
        with self.lock:
            self.sessions.pop(token, None)


class Application:
    def __init__(self, config, authentication, validator, *, reader=read_protected, clock=time.monotonic):
        if config != EXPECTED_CONFIG:
            raise Refused('Unexpected panel configuration.')
        self.config, self.auth, self.validate = config, authentication, validator
        self.reader, self.clock = reader, clock
        self.assets = {}
        for route, name, mime in (('/', 'index.html', 'text/html; charset=utf-8'),
                                  ('/static/app.js', 'app.js', 'application/javascript; charset=utf-8'),
                                  ('/static/style.css', 'style.css', 'text/css; charset=utf-8')):
            self.assets[route] = (self.reader(Path(config['static'])/name), mime)
        self.ca = self.reader(PUBLIC_CA, limit=65536)

    def dispatch(self, request, peer):
        method, target, headers, body = request
        try:
            address = ipaddress.IPv4Address(peer)
        except ValueError:
            raise HTTPError(403) from None
        if address not in ipaddress.IPv4Network('172.27.240.0/24') or int(address) & 255 in (0, 1, 255):
            raise HTTPError(403)
        if headers.get('host') != '172.27.240.1:8443':
            raise HTTPError(403)
        if headers.get('sec-fetch-site') not in (None, 'same-origin', 'none'):
            raise HTTPError(403)
        if method == 'POST' and headers.get('origin') != self.config['origin']:
            raise HTTPError(403)
        if method == 'GET' and target in self.assets:
            content, mime = self.assets[target]
            return 200, content, {'Content-Type': mime}
        if method == 'GET' and target == '/ca.crt':
            return 200, self.ca, {'Content-Type': 'application/x-pem-file'}
        if method == 'POST' and target == '/api/login':
            try:
                value = strict_json(body)
                if not isinstance(value, dict) or set(value) != {'password'}:
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise HTTPError(400) from None
            token, csrf = self.auth.login(value['password'], peer)
            cookie = COOKIE+'='+token+'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600'
            return self.json_response({'authenticated': True, 'csrf_token': csrf}, {'Set-Cookie': cookie})
        if method == 'GET' and target == '/api/status':
            _, csrf = self.auth.session(headers.get('cookie', ''), peer)
            try:
                value = self.validate(strict_json(self.reader(Path(self.config['snapshot']))))
                age = self.clock()-value['monotonic']
                if not 0 <= age <= 90:
                    return self.json_response({'version': 1, 'available': True, 'stale': True,
                                               'snapshot': value, 'age_ms': max(0, int(age*1000)), 'csrf_token': csrf})
            except (OSError, ValueError, TypeError):
                return self.json_response({'version': 1, 'available': False, 'stale': True,
                                           'snapshot': None, 'age_ms': None, 'csrf_token': csrf})
            return self.json_response({'version': 1, 'available': True, 'stale': False,
                                       'snapshot': value, 'age_ms': int(age*1000), 'csrf_token': csrf})
        if method == 'POST' and target == '/api/logout':
            token, csrf = self.auth.session(headers.get('cookie', ''), peer)
            supplied = headers.get('x-csrf-token', '')
            if not hmac.compare_digest(supplied.encode('utf-8'), csrf.encode('ascii')):
                raise HTTPError(403)
            try:
                if strict_json(body) != {}:
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise HTTPError(400) from None
            self.auth.logout(token)
            return self.json_response({'authenticated': False}, {'Set-Cookie': COOKIE+'=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'})
        raise HTTPError(404)

    @staticmethod
    def json_response(value, headers=None):
        return 200, json.dumps(value, separators=(',', ':')).encode(), {'Content-Type': 'application/json', **(headers or {})}


def wire_response(status, body, headers=None):
    phrases = {200: 'OK', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
               404: 'Not Found', 405: 'Method Not Allowed', 413: 'Content Too Large',
               415: 'Unsupported Media Type', 429: 'Too Many Requests',
               431: 'Request Header Fields Too Large', 500: 'Internal Server Error'}
    fields = {**SECURITY_HEADERS, 'Content-Type': 'application/json', **(headers or {}),
              'Content-Length': str(len(body)), 'Connection': 'close'}
    if status == 429:
        fields['Retry-After'] = '60'
    head = 'HTTP/1.1 '+str(status)+' '+phrases[status]+'\r\n'
    head += ''.join(key+': '+value+'\r\n' for key, value in fields.items())+'\r\n'
    return head.encode('ascii')+body


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        def abort():
            try:
                self.request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = threading.Timer(15, abort)
        deadline.daemon = True
        deadline.start()
        try:
            self.request.settimeout(10)
            self.request.do_handshake()
            try:
                result = self.server.application.dispatch(read_request(self.request), self.client_address[0])
            except HTTPError as error:
                result = error.status, b'{"error":"Request refused."}', {}
            except (OSError, ValueError, TypeError, RuntimeError):
                result = 500, b'{"error":"Panel data unavailable."}', {}
            self.request.sendall(wire_response(*result))
        except (OSError, ssl.SSLError):
            pass  # No request lines, cookies, credentials or TLS errors in logs.
        finally:
            deadline.cancel()


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, context, application):
        self.context, self.application = context, application
        self.capacity = threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def get_request(self):
        raw, address = self.socket.accept()
        try:
            channel = self.context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            return channel, address
        except BaseException:
            raw.close()
            raise

    def process_request(self, request, client_address):
        if not self.capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.capacity.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.capacity.release()

    def handle_error(self, request, client_address):
        pass  # Fixed, secret-free failures only; no generic traceback logger.


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    if os.geteuid() == 0 or not sys.flags.isolated or Path(__file__) != CODE/'server.py':
        raise Refused('Start the installed unprivileged panel service.')
    for name in ('server.py', 'schema.py'):
        read_protected(CODE/name)
    sys.path.insert(0, str(CODE))
    import schema
    config = strict_json(read_protected(CONFIG, limit=16384))
    if config != EXPECTED_CONFIG:
        raise Refused('Unexpected panel configuration.')
    auth = Authentication(strict_json(read_protected(Path(config['auth']), limit=16384, secret=True)))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION
    read_protected(Path(config['certificate']), limit=65536)
    read_protected(Path(config['private_key']), limit=65536, secret=True)
    context.load_cert_chain(config['certificate'], config['private_key'])
    application = Application(config, auth, schema.validate_snapshot)
    with Server((config['bind'], config['port']), context, application) as server:
        server.serve_forever(poll_interval=.5)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError):
        raise SystemExit('Private administration panel startup failed; inspect its protected installation.') from None
