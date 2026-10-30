#!/usr/bin/python3
"""Fixed read-only VPN diagnostics. No credentials, journals or management IPC."""
from datetime import datetime, timezone
import ipaddress
import json
import os
import re
import resource
import secrets
import selectors
import socket
import struct
import subprocess
import time

UNITS = ('openvpn-server@vpn-lab.service', 'vpn-lab-broker.service', 'unbound.service')
ACTIVE = {'active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading', 'maintenance', 'refreshing', 'unknown'}
SUB = {'running', 'dead', 'failed', 'exited', 'start-pre', 'start', 'start-post',
       'stop', 'stop-watchdog', 'stop-sigterm', 'stop-sigkill', 'stop-post',
       'final-watchdog', 'final-sigterm', 'final-sigkill', 'auto-restart', 'auto-restart-queued',
       'condition', 'cleaning', 'unknown'}
RESULTS = {'success', 'resources', 'protocol', 'timeout', 'exit-code', 'signal', 'core-dump',
           'watchdog', 'start-limit-hit', 'oom-kill', 'exec-condition', 'unknown'}
KINDS = {'tun', 'ovpn', 'ovpn-dco', 'ovpn-dco-v2', 'unknown'}
COMMENTS = ('vpn-lab-private-dns', 'vpn-lab-block-host')
DNS_STATUS = {'not_attempted', 'ok', 'timeout', 'servfail', 'refused', 'rcode_error',
              'invalid', 'no_answer', 'truncated', 'transport_error'}
TOP_KEYS = {'version', 'server_utc', 'ntp_synchronized', 'services', 'tunnel',
            'dns_listeners', 'authorization', 'input_counters', 'dns_probe'}
DNS = '172.27.240.1'
QUESTION = b'\x07example\x03com\x00'+struct.pack('!HH', 1, 1)
ENVIRONMENT = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def read_command(argv, *, timeout=8, limit=65536):
    """Bound output while reading it; never retain or expose command stderr."""
    process = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=ENVIRONMENT)
        output = bytearray()
        deadline = time.monotonic()+timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    return None
                ready = selector.select(remaining)
                if not ready:
                    return None
                part = os.read(process.stdout.fileno(), min(8192, limit+1-len(output)))
                if not part:
                    break
                output.extend(part)
                if len(output) > limit:
                    return None
        if process.wait(timeout=max(.001, deadline-time.monotonic())):
            return None
        return output.decode('utf-8')
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return None
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            process.stdout.close()


def parse_json(text):
    try:
        return json.loads(text) if isinstance(text, str) else None
    except ValueError:
        return None


def empty_services():
    return [{'unit': unit, 'active_state': None, 'sub_state': None, 'restarts': None, 'result': None}
            for unit in UNITS]


def parse_services(text):
    defaults = empty_services()
    if not isinstance(text, str):
        return defaults
    blocks = text.strip().split('\n\n')
    records = {}
    for block in blocks:
        fields = {}
        for line in block.splitlines():
            key, sep, value = line.partition('=')
            if not sep or key not in {'Id', 'ActiveState', 'SubState', 'NRestarts', 'Result'} or key in fields:
                return defaults
            fields[key] = value
        if set(fields) != {'Id', 'ActiveState', 'SubState', 'NRestarts', 'Result'}:
            return defaults
        unit = fields['Id']
        if unit not in UNITS or unit in records:
            return defaults
        number = fields['NRestarts']
        records[unit] = {'unit': unit,
                         'active_state': fields['ActiveState'] if fields['ActiveState'] in ACTIVE else 'unknown',
                         'sub_state': fields['SubState'] if fields['SubState'] in SUB else 'unknown',
                         'restarts': int(number) if re.fullmatch(r'[0-9]{1,10}', number) else None,
                         'result': fields['Result'] if fields['Result'] in RESULTS else 'unknown'}
    return [records.get(item['unit'], item) for item in defaults]


def parse_tunnel(text):
    unknown = {'present': None, 'kind': None, 'up': None, 'ipv4': []}
    document = parse_json(text)
    if not isinstance(document, list) or not all(isinstance(item, dict) for item in document):
        return unknown
    rows = [item for item in document if item.get('ifname') == 'tun-lab']
    if not rows:
        return {'present': False, 'kind': None, 'up': None, 'ipv4': []}
    if len(rows) != 1:
        return unknown
    row = rows[0]
    if not isinstance(row.get('flags'), list) or not isinstance(row.get('addr_info'), list):
        return unknown
    info = row.get('linkinfo', {})
    if not isinstance(info, dict):
        return unknown
    kind = info.get('info_kind')
    addresses = set()
    try:
        for item in row['addr_info']:
            if not isinstance(item, dict):
                return unknown
            if item.get('family') != 'inet':
                continue
            prefix = item.get('prefixlen')
            if type(prefix) is not int or not 0 <= prefix <= 32:
                return unknown
            addresses.add(str(ipaddress.IPv4Interface(str(item.get('local'))+'/'+str(prefix))))
        if len(addresses) > 8:
            return unknown
    except ValueError:
        return unknown
    return {'present': True, 'kind': kind if isinstance(kind, str) and kind in KINDS else 'unknown',
            'up': 'UP' in row['flags'], 'ipv4': sorted(addresses)}


def parse_listeners(text):
    if not isinstance(text, str):
        return None
    listeners = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ('tcp', 'udp'):
            return None
        address, sep, port = fields[4].rpartition(':')
        if not sep or not port.isdigit() or not 0 <= int(port) <= 65535:
            return None
        if int(port) != 53:
            continue
        address = address.strip('[]')
        try:
            if address != '*':
                address = str(ipaddress.ip_address(address.split('%', 1)[0]))
        except ValueError:
            return None
        listeners.add((fields[0], address))
    if len(listeners) > 32:
        return None
    return [{'protocol': protocol, 'address': address, 'port': 53}
            for protocol, address in sorted(listeners)]


def bounded_integer(value, maximum=2**63-1):
    return type(value) is int and 0 <= value <= maximum


def parse_firewall(text):
    counters = {name: None for name in COMMENTS}
    document = parse_json(text)
    if not isinstance(document, dict) or not isinstance(document.get('nftables'), list):
        return None, counters
    sets = []
    matches = {name: [] for name in COMMENTS}
    for obj in document['nftables']:
        if not isinstance(obj, dict):
            return None, counters
        item = obj.get('set')
        if (isinstance(item, dict) and item.get('family') == 'inet'
                and item.get('table') == 'vpn_lab' and item.get('name') == 'authorized'):
            sets.append(item)
        rule = obj.get('rule')
        if (not isinstance(rule, dict) or rule.get('family') != 'inet'
                or rule.get('table') != 'vpn_lab' or rule.get('chain') != 'input'):
            continue
        comment = rule.get('comment')
        if not isinstance(comment, str) or comment not in COMMENTS:
            continue
        if not isinstance(rule.get('expr'), list):
            continue
        values = [expr['counter'] for expr in rule['expr'] if isinstance(expr, dict) and 'counter' in expr]
        if len(values) == 1 and isinstance(values[0], dict):
            value = values[0]
            if bounded_integer(value.get('packets')) and bounded_integer(value.get('bytes')):
                matches[comment].append({'packets': value['packets'], 'bytes': value['bytes']})
    for name, values in matches.items():
        if len(values) == 1:
            counters[name] = values[0]
    if len(sets) != 1 or sets[0].get('type') != 'ipv4_addr':
        return None, counters
    elements = sets[0].get('elem', [])
    if not isinstance(elements, list) or len(elements) > 1:
        return None, counters
    addresses = []
    for item in elements:
        expires = None
        if isinstance(item, str):
            address = item
        elif isinstance(item, dict) and isinstance(item.get('elem'), dict):
            address = item['elem'].get('val')
            expires = item['elem'].get('expires')
        else:
            return None, counters
        try:
            parsed = ipaddress.IPv4Address(address)
            if not isinstance(address, str) or str(parsed) != address or parsed not in ipaddress.ip_network('172.27.240.0/24'):
                return None, counters
        except (ValueError, TypeError):
            return None, counters
        if expires is not None and not bounded_integer(expires):
            return None, counters
        addresses.append({'ipv4': address, 'expires_ms': expires})
    return {'element_count': len(addresses), 'addresses': addresses}, counters


def dns_name(packet, offset):
    labels, visited, end, size = [], set(), None, 1
    while True:
        if offset >= len(packet) or offset in visited or len(visited) >= 128:
            raise ValueError('Invalid DNS name.')
        visited.add(offset)
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset+1 >= len(packet):
                raise ValueError('Invalid DNS pointer.')
            pointer = ((length & 63) << 8) | packet[offset+1]
            if not 12 <= pointer < offset:
                raise ValueError('Invalid DNS pointer.')
            end = offset+2 if end is None else end
            offset = pointer
            continue
        if length & 0xc0 or offset+1+length > len(packet):
            raise ValueError('Invalid DNS label.')
        offset += 1
        if not length:
            return tuple(labels), end if end is not None else offset
        labels.append(packet[offset:offset+length].lower())
        size += length+1
        if size > 255:
            raise ValueError('Oversized DNS name.')
        offset += length


def parse_dns(packet, identifier):
    invalid = ('invalid', None, None)
    try:
        if not 12 <= len(packet) <= 4096:
            return invalid
        ident, flags, questions, answers, authority, additional = struct.unpack('!6H', packet[:12])
        if ident != identifier or flags & 0xf800 != 0x8000 or flags & 0x0040 or questions != 1:
            return invalid
        name, offset = dns_name(packet, 12)
        if name != (b'example', b'com') or packet[offset:offset+4] != struct.pack('!HH', 1, 1):
            return invalid
        offset += 4
        rcode = flags & 15
        if flags & 0x0200:
            return 'truncated', rcode, None
        if rcode:
            return {2: 'servfail', 5: 'refused'}.get(rcode, 'rcode_error'), rcode, None
        if answers+authority+additional > 128:
            return invalid
        usable = 0
        for index in range(answers+authority+additional):
            owner, offset = dns_name(packet, offset)
            if offset+10 > len(packet):
                return invalid
            kind, family, _, length = struct.unpack('!HHIH', packet[offset:offset+10])
            offset += 10
            if offset+length > len(packet) or kind == 1 and length != 4:
                return invalid
            if index < answers and owner == (b'example', b'com') and kind == 1 and family == 1:
                usable += 1
            offset += length
        if offset != len(packet):
            return invalid
        return ('ok' if usable else 'no_answer'), 0, usable
    except (ValueError, struct.error):
        return invalid


def probe_dns(tunnel):
    result = {'status': 'not_attempted', 'rcode': None, 'answer_count': None, 'elapsed_ms': 0}
    # Verify this is a local server address, then bind to loopback as an
    # additional boundary: a missing VPN interface must never route this test
    # through the server's public/default interface.
    if (tunnel['present'] is not True or tunnel['up'] is not True
            or not any(ipaddress.IPv4Interface(value).ip == ipaddress.IPv4Address(DNS) for value in tunnel['ipv4'])):
        return result
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lo\0')
            channel.bind((DNS, 0))
            channel.settimeout(3)
            channel.connect((DNS, 53))
            identifier = secrets.randbelow(65536)
            channel.send(struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0)+QUESTION)
            packet, peer = channel.recvfrom(4097)
            status, rcode, count = parse_dns(packet, identifier) if peer == (DNS, 53) else ('invalid', None, None)
            result.update(status=status, rcode=rcode, answer_count=count)
    except socket.timeout:
        result['status'] = 'timeout'
    except OSError:
        result['status'] = 'transport_error'
    result['elapsed_ms'] = min(10000, int(max(0, time.monotonic()-started)*1000))
    return result


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('Unsupported diagnostic report.')


def _validate_report(value):
    """Validate every public field before any controller prints remote JSON."""
    def require(condition):
        if not condition:
            raise ValueError('Unsupported diagnostic report.')
    exact(value, TOP_KEYS)
    require(type(value['version']) is int and value['version'] == 1)
    stamp = value['server_utc']
    require(isinstance(stamp, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00', stamp) is not None)
    datetime.fromisoformat(stamp)
    require(value['ntp_synchronized'] is None or type(value['ntp_synchronized']) is bool)
    require(isinstance(value['services'], list) and len(value['services']) == len(UNITS))
    for unit, item in zip(UNITS, value['services']):
        exact(item, {'unit', 'active_state', 'sub_state', 'restarts', 'result'})
        require(item['unit'] == unit)
        for field, choices in (('active_state', ACTIVE), ('sub_state', SUB), ('result', RESULTS)):
            require(item[field] is None or isinstance(item[field], str) and item[field] in choices)
        require(item['restarts'] is None or bounded_integer(item['restarts']))
    tunnel = value['tunnel']
    exact(tunnel, {'present', 'kind', 'up', 'ipv4'})
    for key in ('present', 'up'):
        require(tunnel[key] is None or type(tunnel[key]) is bool)
    require(tunnel['kind'] is None or isinstance(tunnel['kind'], str) and tunnel['kind'] in KINDS)
    require(isinstance(tunnel['ipv4'], list) and len(tunnel['ipv4']) <= 8)
    for address in tunnel['ipv4']:
        require(isinstance(address, str) and str(ipaddress.IPv4Interface(address)) == address)
    listeners = value['dns_listeners']
    require(listeners is None or isinstance(listeners, list) and len(listeners) <= 32)
    for item in listeners or []:
        exact(item, {'protocol', 'address', 'port'})
        require(isinstance(item['protocol'], str) and item['protocol'] in ('udp', 'tcp'))
        require(type(item['port']) is int and item['port'] == 53)
        address = item['address']
        require(isinstance(address, str) and (address == '*' or str(ipaddress.ip_address(address)) == address))
    authorization = value['authorization']
    if authorization is not None:
        exact(authorization, {'element_count', 'addresses'})
        require(bounded_integer(authorization['element_count'], 1))
        require(isinstance(authorization['addresses'], list) and len(authorization['addresses']) == authorization['element_count'])
        for item in authorization['addresses']:
            exact(item, {'ipv4', 'expires_ms'})
            address = item['ipv4']
            require(isinstance(address, str) and str(ipaddress.IPv4Address(address)) == address
                    and ipaddress.IPv4Address(address) in ipaddress.ip_network('172.27.240.0/24'))
            require(item['expires_ms'] is None or bounded_integer(item['expires_ms']))
    exact(value['input_counters'], COMMENTS)
    for item in value['input_counters'].values():
        if item is not None:
            exact(item, {'packets', 'bytes'})
            require(bounded_integer(item['packets']) and bounded_integer(item['bytes']))
    probe = value['dns_probe']
    exact(probe, {'status', 'rcode', 'answer_count', 'elapsed_ms'})
    require(isinstance(probe['status'], str) and probe['status'] in DNS_STATUS)
    require(probe['rcode'] is None or bounded_integer(probe['rcode'], 15))
    require(probe['answer_count'] is None or bounded_integer(probe['answer_count'], 128))
    require(bounded_integer(probe['elapsed_ms'], 10000))
    require(probe['status'] != 'ok' or probe['rcode'] == 0 and bounded_integer(probe['answer_count'], 128) and probe['answer_count'] > 0)
    return value


def validate_report(value):
    try:
        return _validate_report(value)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ValueError('Unsupported diagnostic report.') from None


def collect():
    services = parse_services(read_command(['/usr/bin/systemctl', 'show', *UNITS,
        '--property=Id,ActiveState,SubState,NRestarts,Result', '--no-pager']))
    tunnel = parse_tunnel(read_command(['/usr/sbin/ip', '-j', '-d', '-4', 'address', 'show']))
    listeners = parse_listeners(read_command(['/usr/bin/ss', '-H', '-lntu']))
    authorization, counters = parse_firewall(read_command(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'vpn_lab']))
    ntp = read_command(['/usr/bin/timedatectl', 'show', '--property=NTPSynchronized', '--value'])
    ntp = {'yes': True, 'no': False}.get(ntp.strip()) if isinstance(ntp, str) else None
    report = {'version': 1, 'server_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
              'ntp_synchronized': ntp, 'services': services, 'tunnel': tunnel,
              'dns_listeners': listeners, 'authorization': authorization,
              'input_counters': counters, 'dns_probe': probe_dns(tunnel)}
    return validate_report(report)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if os.geteuid() != 0:
        raise SystemExit(1)
    print(json.dumps(collect(), sort_keys=True))


if __name__ == '__main__':
    main()
