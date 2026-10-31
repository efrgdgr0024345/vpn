#!/usr/bin/env python3
"""Strict local guard inspection and closure. Broad portal opening is disabled."""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import session_channel

from safe_io import bounded_run
from security import Refused, load_policy, service_account

NFT = '/usr/sbin/nft'
IP = '/usr/sbin/ip'
SET = 'portal_window'
COMMENT = 'vpn-dashboard-portal-window'


class MutationUnknown(Refused):
    pass


def run(argv, data=None):
    try:
        return bounded_run(argv, input=data, timeout=8, check=True,
                           env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}).stdout
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise Refused('Required system command failed; no automatic retry.') from exc


def mutate(batch):
    try:
        run([NFT, '-f', '-'], batch)
    except Refused as exc:
        raise MutationUnknown('Firewall outcome UNKNOWN. Keep awake; verify portal closure before connecting.') from exc


def js(argv):
    try:
        return json.loads(run(argv))
    except (ValueError, TypeError) as exc:
        raise Refused('System returned unsupported JSON.') from exc


def match(left, right):
    return {'match': {'op': '==', 'left': left, 'right': right}}


def meta(key):
    return {'meta': {'key': key}}


def payload(protocol, field):
    return {'payload': {'protocol': protocol, 'field': field}}


def allowed_rules(policy=None, vpn_uid=None):
    policy = load_policy() if policy is None else policy
    vpn_uid = service_account().pw_uid if vpn_uid is None else vpn_uid
    accept = {'accept': None}
    wifi = match(meta('oifname'), policy['wifi_interface'])
    protocol = 'udp' if policy['vpn_protocol'] == 'udp' else 'tcp'
    return [
        [match(meta('oifname'), 'lo'), accept],
        [match(meta('oifname'), 'tun0'), accept],
        [wifi, match(meta('nfproto'), 'ipv4'),
         match(meta('skuid'), {'set': [0, vpn_uid]}),
         match(payload('ip', 'daddr'), policy['vpn_server_ipv4']),
         match(payload(protocol, 'dport'), policy['vpn_port']), accept],
        [wifi, match(meta('nfproto'), 'ipv4'), match(meta('skuid'), 0),
         match(payload('ip', 'daddr'), {'set': ['255.255.255.255', policy['dhcp_server_ipv4']]}),
         match(payload('udp', 'sport'), 68), match(payload('udp', 'dport'), 67), accept],
    ]


def allowed_input_rules(policy):
    accept = {'accept': None}
    state={'match': {'op':'in','left':{'ct':{'key':'state'}},'right':{'set':['established','related']}}}
    protocol='udp' if policy['vpn_protocol']=='udp' else 'tcp'
    return [
        [match(meta('iifname'), 'lo'), accept],
        [match(meta('iifname'),'tun0'),state,accept],
        [match(meta('iifname'),policy['wifi_interface']),
         match(payload('ip','saddr'),policy['vpn_server_ipv4']),
         match(payload(protocol,'sport'),policy['vpn_port']),state,accept],
        [match(meta('iifname'),policy['wifi_interface']),match(meta('l4proto'),'icmp'),
         match({'ct':{'key':'state'}},'related'),accept],
        [match(meta('iifname'), policy['wifi_interface']), match(meta('nfproto'), 'ipv4'),
         match(payload('ip', 'saddr'), policy['dhcp_server_ipv4']),
         match(payload('udp', 'sport'), 67), match(payload('udp', 'dport'), 68), accept],
    ]


HOTSPOT_IF = 'vpn-ap0'
HOTSPOT_NETWORK = {'prefix': {'addr': '10.77.0.0', 'len': 24}}


def hotspot_rules():
    """Only AP DHCP and IPv4 forwarding through tun0; no physical fallback."""
    ap_in = match(meta('iifname'), HOTSPOT_IF)
    ap_out = match(meta('oifname'), HOTSPOT_IF)
    source = match(payload('ip', 'saddr'), HOTSPOT_NETWORK)
    ipv4 = match(meta('nfproto'), 'ipv4')
    accept = {'accept': None}
    state = {'match': {'op': 'in', 'left': {'ct': {'key': 'state'}}, 'right': {'set': ['established','related']}}}
    return {
        'input': [[ap_in, ipv4, match(payload('udp','sport'),68), match(payload('udp','dport'),67), accept]],
        'output': [[ap_out, ipv4, match(payload('udp','sport'),67), match(payload('udp','dport'),68), accept]],
        'forward': [[ap_in, source, match(meta('oifname'),'tun0'), accept],
                    [match(meta('iifname'),'tun0'), ap_out, match(payload('ip','daddr'),HOTSPOT_NETWORK), state, accept]],
        'prerouting': [[ap_in, source, match(payload(proto,'dport'),53), {'dnat': {'addr':'172.27.240.1','family':'ip'}}]
                       for proto in ('udp','tcp')],
        'postrouting': [[source, match(meta('oifname'),'tun0'), {'masquerade':None}]],
    }


def hotspot_present():
    links = js([IP, '-j', 'link', 'show'])
    if not isinstance(links,list):
        raise Refused('Cannot verify hotspot state.')
    return any(row.get('ifname')==HOTSPOT_IF for row in links)


def portal_expr():
    # Recognize an old owned window only so it can be cleared, never reopened.
    return [match(meta('nfproto'), 'ipv4'), match(meta('oifname'), '@' + SET), {'accept': None}]


def canonical(expression):
    """Anonymous set order is inert; statement/rule order is preserved."""
    if isinstance(expression, dict):
        if set(expression) == {'set'} and isinstance(expression['set'], list):
            return {'set': sorted((canonical(value) for value in expression['set']),
                                  key=lambda value: json.dumps(value, sort_keys=True))}
        return {key: canonical(value) for key, value in expression.items()}
    if isinstance(expression, list):
        return [canonical(value) for value in expression]
    return expression


def canonical_rule(expression):
    """Normalize only the equivalent forms emitted by nft's inet JSON reader."""
    result = canonical(expression)
    if not isinstance(result, list):
        return result
    # nft can suppress an explicit IPv4 family test when an IPv4 address payload
    # match already enforces it. Require an equality against actual IPv4 values;
    # a UDP port, IPv6 selector or negated address does not establish this.
    ipv4_address_match = False
    for statement in result:
        if not isinstance(statement, dict) or set(statement) != {'match'}:
            continue
        value = statement['match']
        if not isinstance(value, dict) or set(value) != {'op', 'left', 'right'}:
            continue
        if (value['op'] == 'in' and value['left'] == {'ct': {'key': 'state'}}
                and isinstance(value['right'], dict) and set(value['right']) == {'set'}
                and isinstance(value['right']['set'], list)):
            value['op'] = '=='
        if value['op'] != '==' or value['left'] not in (payload('ip', 'saddr'), payload('ip', 'daddr')):
            continue
        right = value['right']
        if isinstance(right,dict) and set(right)=={'prefix'}:
            prefix=right['prefix']
            if isinstance(prefix,dict) and set(prefix)=={'addr','len'} and type(prefix['len']) is int and 0<=prefix['len']<=32:
                try:
                    ipaddress.IPv4Network(str(prefix['addr'])+'/'+str(prefix['len']),strict=True)
                    ipv4_address_match=True
                except ValueError: pass
            continue
        values = right['set'] if isinstance(right, dict) and set(right) == {'set'} else [right]
        if not isinstance(values, list) or not values or not all(isinstance(item, str) for item in values):
            continue
        try:
            for item in values:
                ipaddress.IPv4Address(item)
        except ValueError:
            continue
        ipv4_address_match = True
    if ipv4_address_match:
        result = [statement for statement in result if statement != match(meta('nfproto'), 'ipv4')]
    return result


def inspect_guard(document):
    policy = load_policy()
    if not isinstance(document, dict) or not isinstance(document.get('nftables'), list):
        raise Refused('Missing nftables ruleset.')
    chains, rules, sets, tables = {}, [], [], []
    gateway = any(item.get('chain',{}).get('name')=='postrouting' for item in document['nftables'] if isinstance(item,dict))
    chain_names = {'input','output','forward'} | ({'prerouting','postrouting'} if gateway else set())
    for item in document['nftables']:
        if not isinstance(item, dict) or len(item) != 1:
            raise Refused('Unknown ruleset object.')
        kind, obj = next(iter(item.items()))
        if kind == 'metainfo':
            continue
        if kind not in ('table', 'chain', 'rule', 'set') or not isinstance(obj, dict):
            raise Refused('Unsupported firewall object; guard not changed.')
        if obj.get('family') != 'inet' or (obj.get('name') if kind == 'table' else obj.get('table')) != 'vpn_guard':
            raise Refused('Additional or missing firewall table; guard not changed.')
        if kind == 'table':
            if set(obj) - {'family', 'name', 'handle'}:
                raise Refused('Unsupported table settings.')
            tables.append(obj)
        elif kind == 'chain':
            name = obj.get('name')
            if name not in chain_names or name in chains:
                raise Refused('Unexpected firewall chain.')
            expected = {'family': 'inet', 'table': 'vpn_guard', 'name': name,
                        'type': 'filter', 'hook': name, 'prio': 0, 'policy': 'drop'}
            if name in ('prerouting','postrouting'):
                expected.update(type='nat',prio=-100 if name=='prerouting' else 100,policy='accept')
            if {k: v for k, v in obj.items() if k != 'handle'} != expected:
                raise Refused('Guard chain is not the required drop policy.')
            chains[name] = obj
        elif kind == 'rule':
            if set(obj) - {'family', 'table', 'chain', 'handle', 'expr', 'comment'} or obj.get('chain') not in chain_names:
                raise Refused('Unexpected firewall rule.')
            rules.append(obj)
        else:
            sets.append(obj)
    if len(tables) != 1 or set(chains) != chain_names:
        raise Refused('Required input/output/forward drop chains missing.')
    remaining = {chain: [canonical_rule(rule) for rule in expressions]
                 for chain, expressions in (('output', allowed_rules(policy)),
                                            ('input', allowed_input_rules(policy)))}
    if gateway:
        for chain,extra in hotspot_rules().items():
            remaining.setdefault(chain,[]).extend(canonical_rule(rule) for rule in extra)
    else:
        remaining['forward']=[]
    own_rules = 0
    for rule in rules:
        expr = rule.get('expr')
        if not isinstance(expr, list):
            raise Refused('Unsupported rule expression.')
        clean = canonical_rule([part for part in expr if not (isinstance(part, dict) and set(part) == {'counter'})])
        if rule['chain'] == 'output' and clean == portal_expr() and rule.get('comment') == COMMENT:
            own_rules += 1
        elif clean in remaining[rule['chain']]:
            remaining[rule['chain']].remove(clean)
        else:
            raise Refused('Unknown firewall exception; refusing action.')
    if any(remaining.values()) or own_rules > 1 or len(sets) > 1 or bool(sets) != bool(own_rules):
        raise Refused('Baseline rules or portal ownership do not match.')
    active = False
    if sets:
        obj = sets[0]
        allowed = {'family', 'table', 'name', 'handle', 'type', 'flags', 'timeout', 'elem'}
        if set(obj) - allowed or obj.get('name') != SET or obj.get('type') != 'ifname' or obj.get('flags') != ['timeout'] or obj.get('timeout') != 30000:
            raise Refused('Unsupported portal set.')
        elems = obj.get('elem', [])
        if not isinstance(elems, list) or len(elems) > 1:
            raise Refused('Unexpected portal elements.')
        for elem in elems:
            if not isinstance(elem, dict) or set(elem) != {'elem'} or not isinstance(elem['elem'], dict):
                raise Refused('Unsupported timed element.')
            val = elem['elem']
            if set(val) - {'val', 'timeout', 'expires'} or val.get('val') != policy['wifi_interface'] or val.get('timeout') != 30000:
                raise Refused('Unexpected portal element or timeout.')
            expires = val.get('expires')
            if type(expires) not in (int, float) or not 0 <= expires <= 30000:
                raise Refused('Unrecognized portal expiry.')
            active = True
    return bool(sets), active


def active_openvpn(proc=Path('/proc')):
    for entry in proc.iterdir():
        if entry.name.isdigit():
            try:
                name = (entry / 'comm').read_text().strip().lower()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise Refused('Cannot verify running VPN processes.') from exc
            if name.startswith('openvpn'):
                return True
    return False


def check_network():
    policy = load_policy()
    if active_openvpn():
        raise Refused('OpenVPN is already running.')
    links = js([IP, '-j', '-d', 'link', 'show'])
    if not isinstance(links, list) or not all(isinstance(x, dict) for x in links):
        raise Refused('Cannot verify interfaces.')
    if not any(x.get('ifname') == policy['wifi_interface'] and 'UP' in x.get('flags', []) for x in links):
        raise Refused('Configured Wi-Fi interface is not up.')
    for link in links:
        kind = link.get('linkinfo', {}).get('info_kind', '')
        if link.get('ifname', '').startswith(('tun', 'tap', 'wg')) or kind in ('tun', 'wireguard', 'gre', 'ipip', 'sit', 'vti', 'xfrm'):
            raise Refused('An unmanaged tunnel exists.')
    for family in ('-4', '-6'):
        try:
            routes = js([IP, '-j', family, 'route', 'show', 'table', 'all'])
        except Refused:
            if family == '-6' and session_channel.kernel_ipv6_disabled():
                continue
            raise
        if not isinstance(routes, list) or not all(isinstance(r, dict) for r in routes):
            raise Refused('Cannot verify routes.')
        if any(r.get('dev', '').startswith(('tun', 'tap', 'wg')) or 'encap' in r for r in routes):
            raise Refused('Unmanaged tunnel route exists.')
        if family == '-4':
            defaults = [r for r in routes if r.get('dst') == 'default']
            if len(defaults) != 1 or defaults[0].get('dev') != policy['wifi_interface'] or not defaults[0].get('gateway'):
                raise Refused('Exactly one IPv4 default via the configured Wi-Fi interface is required.')


def act(action):
    if action not in ('close', 'status'):
        raise Refused('Portal opening is disabled until browser traffic can be isolated.')
    if os.geteuid() != 0:
        raise Refused('Explicit sudo authorization is required.')
    exists, active = inspect_guard(js([NFT, '-j', 'list', 'ruleset']))
    if action == 'status':
        return {'state': 'open' if active else 'closed', 'verified_guard': True,
                'note': 'Opening disabled. Status does not certify VPN health.'}
    if exists:
        mutate('flush set inet vpn_guard portal_window\n')
    try:
        _, still_active = inspect_guard(js([NFT, '-j', 'list', 'ruleset']))
        if still_active:
            raise Refused('Portal remains active.')
    except Refused as exc:
        raise MutationUnknown('Cannot verify closed portal. Keep awake; do not connect.') from exc
    return {'state': 'closed'}


def main(action):
    try:
        if os.geteuid() != 0:
            raise Refused('Use the installed privileged entry point.')
        fd = os.open('/run/vpn-dashboard-portal.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
                raise Refused('Unsafe runtime lock.')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(act(action)))
    except (Refused, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(json.dumps({'state': 'unknown' if isinstance(exc, MutationUnknown) else 'refused',
                          'reason': str(exc) if isinstance(exc, Refused) else 'Verification or action lock failed.'}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit('Use the installed privileged entry point; do not sudo a checkout script.')
