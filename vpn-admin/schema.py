"""Strict public snapshot format for the private VPN administration panel."""
from datetime import datetime, timezone
import ipaddress
import math
import re

MAX_BYTES = 262144
MAX_EVENTS = 128
DEVICE_NAMES = ('kali', 'iphone', 'android')
SERVICE_UNITS = ('openvpn-server@vpn-lab.service', 'vpn-lab-broker.service', 'unbound.service')
ACTIVE_STATES = frozenset(('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading',
                          'maintenance', 'refreshing', 'unknown'))
SUB_STATES = frozenset(('running', 'dead', 'failed', 'exited', 'start-pre', 'start', 'start-post',
    'stop', 'stop-watchdog', 'stop-sigterm', 'stop-sigkill', 'stop-post', 'final-watchdog',
    'final-sigterm', 'final-sigkill', 'auto-restart', 'auto-restart-queued', 'condition', 'cleaning', 'unknown'))
RESULT_STATES = frozenset(('success', 'resources', 'protocol', 'timeout', 'exit-code', 'signal',
    'core-dump', 'watchdog', 'start-limit-hit', 'oom-kill', 'exec-condition', 'unknown'))
DNS_STATES = frozenset(('not_attempted', 'ok', 'timeout', 'servfail', 'refused', 'rcode_error',
                        'invalid', 'no_answer', 'truncated', 'transport_error'))
EVENT_CODES = frozenset(('snapshot_ready', 'service_state_changed', 'authorization_granted',
                        'authorization_released', 'ipv6_state_changed', 'collector_error'))
SNAPSHOT_KEYS = frozenset(('version', 'generated_at', 'monotonic', 'services', 'tunnel',
    'authorization', 'devices', 'ipv6', 'events', 'dns_probe'))


def require(condition):
    if not condition:
        raise ValueError('Unsupported panel snapshot.')


def exact(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys))


def number(value, maximum=2**63-1):
    return type(value) is int and 0 <= value <= maximum


def timestamp(value):
    require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00', value) is not None)
    stamp = datetime.fromisoformat(value)
    require(stamp.tzinfo == timezone.utc)


def address(value):
    require(isinstance(value, str))
    parsed = ipaddress.IPv4Address(value)
    require(str(parsed) == value and parsed in ipaddress.IPv4Network('172.27.240.0/24'))
    return parsed


def validate_event(event):
    require(isinstance(event, dict) and isinstance(event.get('code'), str) and event['code'] in EVENT_CODES)
    fields = {'utc', 'code'}
    code = event['code']
    if code == 'service_state_changed':
        fields |= {'unit', 'state'}
        require(event.get('unit') in SERVICE_UNITS and event.get('state') in ACTIVE_STATES)
    elif code in ('authorization_granted', 'authorization_released'):
        fields.add('address')
        address(event.get('address'))
    elif code == 'ipv6_state_changed':
        fields.add('state')
        require(event.get('state') in ('enabled', 'disabled', 'unknown'))
    exact(event, fields)
    timestamp(event['utc'])


def _validate_snapshot(value):
    exact(value, SNAPSHOT_KEYS)
    require(type(value['version']) is int and value['version'] == 1)
    timestamp(value['generated_at'])
    tick = value['monotonic']
    require(type(tick) in (int, float) and math.isfinite(tick) and 0 <= tick < 10**15)
    services = value['services']
    require(isinstance(services, list) and len(services) == len(SERVICE_UNITS))
    for expected, service in zip(SERVICE_UNITS, services):
        exact(service, {'unit', 'active_state', 'sub_state', 'restarts', 'result'})
        require(service['unit'] == expected)
        for key, choices in (('active_state', ACTIVE_STATES), ('sub_state', SUB_STATES), ('result', RESULT_STATES)):
            require(service[key] is None or isinstance(service[key], str) and service[key] in choices)
        require(service['restarts'] is None or number(service['restarts']))
    tunnel = value['tunnel']
    exact(tunnel, {'present', 'kind', 'up', 'ipv4'})
    for key in ('present', 'up'):
        require(tunnel[key] is None or type(tunnel[key]) is bool)
    require(tunnel['kind'] is None or tunnel['kind'] in ('tun', 'ovpn', 'ovpn-dco', 'ovpn-dco-v2', 'unknown'))
    require(isinstance(tunnel['ipv4'], list) and len(tunnel['ipv4']) <= 8)
    for item in tunnel['ipv4']:
        require(isinstance(item, str))
        parsed = ipaddress.IPv4Interface(item)
        require(str(parsed) == item)
        address(str(parsed.ip))
    authorization = value['authorization']
    if authorization is not None:
        exact(authorization, {'element_count', 'addresses'})
        require(number(authorization['element_count'], 1))
        require(isinstance(authorization['addresses'], list) and len(authorization['addresses']) == authorization['element_count'])
        for item in authorization['addresses']:
            exact(item, {'ipv4', 'expires_ms'})
            address(item['ipv4'])
            require(item['expires_ms'] is None or number(item['expires_ms']))
    devices = value['devices']
    require(isinstance(devices, list) and len(devices) == len(DEVICE_NAMES))
    pins, addresses = set(), set()
    for name, device in zip(DEVICE_NAMES, devices):
        exact(device, {'name', 'enabled', 'address', 'certificate_sha256'})
        require(device['name'] == name and type(device['enabled']) is bool)
        parsed = address(device['address'])
        require(10 <= (int(parsed) & 255) <= 249)
        pin = device['certificate_sha256']
        require(isinstance(pin, str) and re.fullmatch(r'[0-9a-f]{64}', pin) is not None)
        require(pin not in pins and str(parsed) not in addresses)
        pins.add(pin)
        addresses.add(str(parsed))
    ipv6 = value['ipv6']
    exact(ipv6, {'kernel_disabled', 'boot_argument_active'})
    require(all(item is None or type(item) is bool for item in ipv6.values()))
    probe = value['dns_probe']
    exact(probe, {'status', 'rcode', 'answer_count', 'elapsed_ms'})
    require(isinstance(probe['status'], str) and probe['status'] in DNS_STATES)
    require(probe['rcode'] is None or number(probe['rcode'], 15))
    require(probe['answer_count'] is None or number(probe['answer_count'], 128))
    require(number(probe['elapsed_ms'], 10000))
    if probe['status'] == 'ok':
        require(probe['rcode'] == 0 and number(probe['answer_count'], 128) and probe['answer_count'] > 0)
    require(isinstance(value['events'], list) and len(value['events']) <= MAX_EVENTS)
    for event in value['events']:
        validate_event(event)
    return value


def validate_snapshot(value):
    """Return the same bounded public value or one fixed, non-secret error."""
    try:
        return _validate_snapshot(value)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ValueError('Unsupported panel snapshot.') from None
