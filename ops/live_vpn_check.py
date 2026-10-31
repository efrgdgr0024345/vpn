#!/usr/bin/python3
"""Read-only checks of an existing VPN session; never connects or restores it."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import resource
import sys
import time
import types

DIAGNOSTICS_SHA256 = '2fd2c9bbec1aaed5f422d86c1ab4769fa0a795cc919b596906220e0e28104dbf'
SERVER = '170.64.224.131'
DNS = '172.27.240.1'
CHECKS = ('installation', 'server_policy', 'live_session', 'server_tls', 'tunnel_address',
          'internet_routes', 'dns_route', 'endpoint_route', 'firewall', 'portal_closed',
          'dns_configuration', 'ipv6_disabled', 'private_dns_udp', 'private_dns_tcp',
          'system_dns', 'internet_https')
LABELS = ('Protected installation baseline', 'Pinned VPN server policy', 'Live root-owned VPN session',
          'OpenVPN TLS negotiation', 'Kali tunnel address', 'Full-tunnel IPv4 routes',
          'Private DNS route', 'VPN endpoint route', 'Exact kill-switch policy',
          'Direct-network bypass closed', 'Private DNS configuration', 'Kernel IPv6 disabled',
          'Private DNS UDP answer', 'Private DNS TCP answer', 'System name resolution',
          'Verified HTTPS through tun0')


def load_diagnostics(source):
    if (not isinstance(source, str) or len(source.encode()) > 2_000_000
            or hashlib.sha256(source.encode()).hexdigest() != DIAGNOSTICS_SHA256):
        raise ValueError('Diagnostic dependency checksum mismatch.')
    module = types.ModuleType('vpn_live_checked_diagnostics')
    exec(compile(source, 'checked-diagnostics', 'exec'), module.__dict__)
    return module


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def check(diagnostics):
    started = time.monotonic()
    result = {'version': 1, 'started_utc': now(), 'finished_utc': None,
              'checks': {name: 'unknown' for name in CHECKS}, 'overall': 'unknown',
              'endpoint': SERVER, 'dns': DNS, 'tunnel': 'tun0', 'elapsed_ms': 0}
    checks = result['checks']
    def observed(name, passed):
        checks[name] = 'passed' if passed else 'failed'
    def finish():
        result['finished_utc'] = now()
        result['elapsed_ms'] = int((time.monotonic()-started)*1000)
        result['overall'] = ('failed' if 'failed' in checks.values() else
                             'passed' if all(value == 'passed' for value in checks.values()) else 'unknown')
        return result
    try:
        modules = diagnostics.load_modules()
        checks['installation'] = 'passed'
    except Exception:
        return finish()
    try:
        policy = modules['security'].load_policy()
        observed('server_policy', policy['vpn_server_ipv4'] == SERVER and policy['vpn_port'] == 1194
                 and policy['vpn_protocol'] == 'udp' and policy['server_name'] == 'VPNLabServer')
    except Exception:
        return finish()
    try:
        session = modules['session_channel'].request()
        details = session['details']
        observed('live_session', session['state'] == 'tunnel_ready')
        observed('server_tls', session['state'] == 'tunnel_ready'
                 and details.get('tls_version') in ('TLSv1.2', 'TLSv1.3')
                 and details.get('expected_tls_name') == policy['server_name'])
    except Exception:
        pass
    try:
        links = diagnostics.ip_json(['address', 'show', 'dev', 'tun0'])
        addresses = [row.get('local') for link in links for row in link.get('addr_info', []) if row.get('family') == 'inet']
        observed('tunnel_address', addresses == ['172.27.240.10'])
        observed('internet_routes', diagnostics.public_tunnel())
        dns_route = diagnostics.ip_json(['route', 'get', DNS])
        observed('dns_route', len(dns_route) == 1 and dns_route[0].get('dev') == 'tun0'
                 and dns_route[0].get('prefsrc', dns_route[0].get('src')) == '172.27.240.10')
        endpoint = diagnostics.ip_json(['route', 'get', SERVER])
        observed('endpoint_route', len(endpoint) == 1 and endpoint[0].get('dev') == policy['wifi_interface'])
    except Exception:
        pass
    try:
        portal = modules['portal_helper']
        _, bypass = portal.inspect_guard(portal.js([portal.NFT, '-j', 'list', 'ruleset']))
        checks['firewall'] = 'passed'
        observed('portal_closed', not bypass)
    except Exception:
        pass
    try:
        network = modules['network_setup']
        observed('dns_configuration', network.resolver_read() == network.MANAGED_DNS)
    except Exception:
        pass
    try:
        observed('ipv6_disabled', modules['session_channel'].kernel_ipv6_disabled())
    except Exception:
        pass
    # Never resolve a test name or contact a remote host unless the expected
    # tunnel, private resolver route and complete local guard were verified.
    required = ('server_policy','live_session','server_tls','tunnel_address','internet_routes',
                'dns_route','endpoint_route','firewall','portal_closed','dns_configuration')
    if any(checks[name] != 'passed' for name in required):
        return finish()
    try:
        observed('private_dns_udp', modules['vpn_session_helper'].private_dns_probe()[0] == 'ok')
    except Exception:
        pass
    try:
        observed('private_dns_tcp', diagnostics.tcp_dns(modules['vpn_session_helper']) == 'ok')
    except Exception:
        pass
    try:
        status, output = diagnostics.command(['/usr/bin/getent', 'ahostsv4', 'example.com'], timeout=3, limit=8192)
        observed('system_dns', status == 'ok' and bool(output.strip()))
    except Exception:
        pass
    try:
        status, output = diagnostics.command(['/usr/bin/curl', '-q', '-4', '--interface', 'tun0', '--noproxy', '*',
            '--proto', '=https', '--connect-timeout', '3', '--max-time', '5', '--silent', '--show-error',
            '--output', '/dev/null', '--write-out', '%{http_code}', 'https://example.com/'], timeout=6, limit=16)
        observed('internet_https', status == 'ok' and output.strip() in (b'200', b'301', b'302', b'303', b'307', b'308'))
    except Exception:
        pass
    # End with a second local snapshot; do not leave an earlier healthy result
    # visible when the session or guard changed while network probes ran.
    try:
        latest = modules['session_channel'].request()
        if latest['state'] != 'tunnel_ready': checks['live_session'] = 'failed'
        _, bypass = portal.inspect_guard(portal.js([portal.NFT, '-j', 'list', 'ruleset']))
        observed('portal_closed', not bypass)
        observed('dns_configuration', network.resolver_read() == network.MANAGED_DNS)
        if not diagnostics.public_tunnel(): checks['internet_routes'] = 'failed'
    except Exception:
        checks['live_session'] = 'unknown'
        checks['firewall'] = 'unknown'
    return finish()


def format_report(result):
    heading = {'passed':'CHECKS PASSED', 'failed':'ATTENTION', 'unknown':'UNVERIFIED'}[result['overall']]
    lines = ['VPN Desk — '+heading+' — '+result['finished_utc'],
             'Server '+SERVER+':1194/UDP | tun0 172.27.240.10 | private DNS '+DNS]
    for key, label in zip(CHECKS, LABELS):
        lines.append(f"  {result['checks'][key].upper():7s}  {label}")
    lines += ['These are sampled checks, not a security certification. Browser encrypted DNS/proxies are not inspected.',
              'No settings changed. The existing VPN helper continues enforcing its guard.']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--watch', action='store_true', help='Repeat checks every 30 seconds after each result.')
    parser.add_argument('--json', action='store_true', help='Emit one bounded JSON object per check.')
    args = parser.parse_args()
    if os.geteuid() != 0 or not sys.flags.isolated:
        raise SystemExit('Run the verified check with sudo and Python -I -B.')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    os.chdir('/')
    diagnostics = load_diagnostics(globals().get('DIAGNOSTICS_SOURCE'))
    try:
        while True:
            result = check(diagnostics)
            print(json.dumps(result, sort_keys=True) if args.json else format_report(result), flush=True)
            if not args.watch:
                return 0 if result['overall'] == 'passed' else 1
            time.sleep(30)
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
