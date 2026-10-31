"""Loopback-only, SYNTHETIC HTTP API for the optional admin UI browser smoke test.

This is not an admin server or an authentication implementation. It never reads
VPN state, keys, credentials, journals or service configuration. Do not deploy it.
Run through ci/admin_browser_smoke.js; --port 0 chooses an available local port.
"""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import threading
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1] / 'vpn-admin' / 'static'
PASSWORD = 'fixture-only'
CSRF_TOKEN = 'fixture-csrf'
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
ASSETS = {'/': ('index.html', 'text/html; charset=utf-8'),
          '/static/style.css': ('style.css', 'text/css; charset=utf-8'),
          '/static/app.js': ('app.js', 'application/javascript; charset=utf-8')}


def utc():
    return datetime.now(timezone.utc).isoformat()


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, control_token):
        super().__init__(('127.0.0.1', port), FixtureHandler)
        self.control_token = control_token
        self.state_lock = threading.Lock()
        self.state = {'authenticated': False, 'stale': False,
                      'logout_failure': False, 'expires_ms': 15000, 'age_ms': 0}
        self.events = [{'utc': utc(), 'code': 'authorization_granted', 'address': '192.0.2.10'}]

    def status(self):
        with self.state_lock:
            state = deepcopy(self.state)
        if not state['authenticated']:
            return 401, {'error': 'authentication_required'}
        snapshot = {
            'generated_at': utc(),
            'services': [{'unit': unit, 'active_state': 'active', 'sub_state': 'running',
                          'restarts': 0, 'result': 'success'} for unit in
                         ('openvpn-server@vpn-lab.service', 'vpn-lab-broker.service', 'unbound.service')],
            'tunnel': {'present': True, 'up': True, 'ipv4': ['192.0.2.1/24']},
            'authorization': {'element_count': 1, 'addresses': [
                {'ipv4': '192.0.2.10', 'expires_ms': state['expires_ms']}]},
            'devices': [{'name': name, 'enabled': name != 'android', 'address': address,
                         'certificate_sha256': letter * 64} for name, address, letter in
                        (('kali', '192.0.2.10', 'a'), ('iphone', '192.0.2.11', 'b'),
                         ('android', '192.0.2.12', 'c'))],
            'ipv6': {'kernel_disabled': True, 'boot_argument_active': True},
            'dns_probe': {'status': 'ok', 'rcode': 0, 'answer_count': 1, 'elapsed_ms': 4},
            'events': deepcopy(self.events)}
        return 200, {'version': 1, 'available': True, 'stale': state['stale'],
                     'age_ms': state['age_ms'], 'snapshot': snapshot, 'csrf_token': CSRF_TOKEN}


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, status, body, content_type='application/json; charset=utf-8'):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', CSP)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-VPN-Admin-Fixture', 'synthetic-only')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = urlsplit(self.path).path
        if route == '/api/status':
            self.respond(*self.server.status())
            return
        asset = ASSETS.get(route)
        if asset is None:
            self.respond(404, {'error': 'fixture_route_not_found'})
            return
        filename, content_type = asset
        body = (ROOT / filename).read_bytes()
        if filename == 'index.html':
            # Screenshots must remain visibly distinguishable from live evidence.
            note = ('<p class="noscript" role="note">Synthetic browser test '
                    '— no live VPN or real credentials.</p>').encode('utf-8')
            body = body.replace(b'<body>', b'<body>' + note, 1)
        self.respond(200, body, content_type)

    def read_json(self):
        length = self.headers.get('Content-Length', '')
        if not length.isdecimal() or not 0 < int(length) <= 4096:
            return None
        self.connection.settimeout(5)
        try:
            body = json.loads(self.rfile.read(int(length)))
            return body if isinstance(body, dict) else None
        except (OSError, ValueError):
            return None

    def do_POST(self):
        route = urlsplit(self.path).path
        if route == '/__fixture/control':
            token = self.headers.get('X-Fixture-Control', '')
            if not secrets.compare_digest(token, self.server.control_token):
                self.respond(403, {'error': 'fixture_control_denied'})
                return
            values = self.read_json()
            if values is None or not values or set(values) - {'stale', 'logout_failure', 'expires_ms', 'age_ms'}:
                self.respond(400, {'error': 'fixture_control_invalid'})
                return
            if (any(type(values[key]) is not bool for key in ('stale', 'logout_failure') if key in values)
                    or any(values[key] is not None and
                           (type(values[key]) is not int or not 0 <= values[key] <= 3600000)
                           for key in ('expires_ms', 'age_ms') if key in values)):
                self.respond(400, {'error': 'fixture_control_invalid'})
                return
            with self.server.state_lock:
                self.server.state.update(values)
            self.respond(200, {'fixture': 'synthetic', 'updated': True})
            return
        if route == '/api/login':
            body = self.read_json()
            if body != {'password': PASSWORD}:
                self.respond(401, {'error': 'authentication_required'})
                return
            with self.server.state_lock:
                self.server.state['authenticated'] = True
            self.respond(200, {'authenticated': True, 'csrf_token': CSRF_TOKEN})
            return
        if route == '/api/logout':
            if self.headers.get('X-CSRF-Token') != CSRF_TOKEN:
                self.respond(403, {'error': 'fixture_csrf_denied'})
                return
            with self.server.state_lock:
                failed = self.server.state['logout_failure']
                if not failed:
                    self.server.state['authenticated'] = False
            self.respond(503 if failed else 200,
                         {'error': 'fixture_unavailable'} if failed else {'authenticated': False})
            return
        self.respond(404, {'error': 'fixture_route_not_found'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    token = os.environ.get('VPN_ADMIN_FIXTURE_CONTROL_TOKEN', '')
    if not 0 <= args.port <= 65535 or len(token) < 32 or not token.isascii():
        raise SystemExit('Use a valid local port and a synthetic fixture control token.')
    with FixtureServer(args.port, token) as server:
        print(json.dumps({'fixture': 'synthetic', 'port': server.server_port}), flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()
