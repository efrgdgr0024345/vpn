#!/usr/bin/env python3
"""Explicit root session: close/verify portal, serialize against portal opening."""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import stat
import select
import signal
import re
import socket
import struct
import subprocess
import queue
import secrets
import threading
import time
import session_channel
import network_setup
import portal_helper
import safe_io
from security import PROFILE, SERVICE_USER, load_policy, read_trusted, service_account, validate_profile


def ipv4_options(protocol):
    if protocol not in ('udp', 'tcp-client'):
        raise portal_helper.Refused('Unsupported VPN transport.')
    return ['--proto', 'udp4' if protocol == 'udp' else 'tcp4-client',
            # Keep IPv4 routing local and fixed even when an older lab server
            # pushes a combined IPv4/IPv6 redirect or IPv6 tunnel addresses.
            '--pull-filter', 'ignore', 'ifconfig-ipv6',
            '--pull-filter', 'ignore', 'route-ipv6',
            '--pull-filter', 'ignore', 'redirect-gateway',
            '--pull-filter', 'ignore', 'block-ipv6',
            '--redirect-gateway', 'def1']


def openvpn_argv():
    policy = load_policy()
    validate_profile(read_trusted(PROFILE, private=True), policy)
    service_account()
    executable = next((p for p in ('/usr/sbin/openvpn', '/usr/bin/openvpn') if Path(p).is_file()), None)
    if not executable:
        raise portal_helper.Refused('OpenVPN is not installed.')
    return ([executable, '--config', str(PROFILE), '--auth-user-pass', '--auth-nocache']
            + ipv4_options(policy['vpn_protocol']) + [
            '--mssfix', '1300', '--script-security', '1',
            '--verb', '3',
            '--allow-compression', 'no', '--user', SERVICE_USER,
            '--group', SERVICE_USER, '--persist-key', '--persist-tun'])


def prepare_session():
    if os.geteuid() != 0:
        raise portal_helper.Refused('This session helper requires explicit terminal sudo.')
    command = openvpn_argv()
    portal_helper.check_network()
    network_setup.prepare()
    portal_helper.act('close')
    if portal_helper.act('status').get('state') != 'closed':
        raise portal_helper.Refused('Portal closure could not be verified. VPN not started.')
    return command


class StartupWatch:
    def __init__(self, now, *, network_seconds=60, overall_seconds=180):
        self.started = now
        self.transport_at = None
        self.replied = False
        self.ready = False
        self.network_seconds = network_seconds
        self.overall_seconds = overall_seconds

    def observe(self, code, now):
        if code == 'tunnel_ready':
            self.ready = True
        elif code == 'reconnecting':
            if self.ready:
                self.replied = False
                self.started = now
                self.transport_at = now
            self.ready = False
        elif code in ('transport_start', 'server_replied'):
            if self.transport_at is None:
                self.transport_at = now
            if code == 'server_replied':
                self.replied = True

    def expired(self, now):
        if self.ready:
            return None
        if self.transport_at is not None and now-self.transport_at >= self.network_seconds:
            return 'handshake_timeout' if self.replied else 'server_timeout'
        if now-self.started >= self.overall_seconds:
            return 'startup_timeout'
        return None


def retain_last(owner, events, exit_status):
    try:
        session_channel.save_last(owner, events.snapshot(), exit_status)
    except OSError as error:
        print('The last-attempt record could not be saved (OS error '+str(error.errno)+'). Keep the terminal messages locally.', flush=True)
    except (ValueError, session_channel.ChannelError):
        print('The last-attempt record could not be saved. Keep the terminal messages locally.', flush=True)


def details_update(events, updates):
    changed = events.set_details(updates)
    if changed:
        print(session_channel.format_details(changed), flush=True)


def diagnostic(argv, *, as_json=True):
    try:
        result = safe_io.bounded_run(argv, timeout=2, limit=32768,
                                     env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
        if result.returncode:
            return None
        return json.loads(result.stdout) if as_json else result.stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def initial_details(events, policy):
    details_update(events, {'server_ipv4': policy['vpn_server_ipv4'], 'server_port': policy['vpn_port'],
        'protocol': 'udp4' if policy['vpn_protocol'] == 'udp' else 'tcp4-client',
        'wifi_interface': policy['wifi_interface'], 'expected_tls_name': policy['server_name'],
        'dhcp_server_ipv4': policy['dhcp_server_ipv4'],
        'dns_ipv4': network_setup.DNS, 'mssfix': 1300,
        'ipv6_kernel_disabled': session_channel.kernel_ipv6_disabled()})
    routes = diagnostic(['/usr/sbin/ip', '-j', '-4', 'route', 'get', policy['vpn_server_ipv4']])
    if isinstance(routes, list) and len(routes) == 1 and isinstance(routes[0], dict):
        for field, key in (('prefsrc', 'local_ipv4'), ('src', 'local_ipv4'), ('gateway', 'gateway_ipv4')):
            if isinstance(routes[0].get(field), str):
                try:
                    details_update(events, {key: routes[0][field]})
                except session_channel.ChannelError:
                    continue


def parse_socket_rows(text, owned):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if (len(fields) < 10 or not fields[9].isdigit() or int(fields[9]) not in owned
                or not all(re.fullmatch(r'[0-9A-Fa-f]{8}:[0-9A-Fa-f]{4}', value) for value in fields[1:3])):
            continue
        endpoints = []
        for value in fields[1:3]:
            address, port = value.split(':')
            endpoints.extend((socket.inet_ntoa(struct.pack('=I', int(address, 16))), int(port, 16)))
        rows.append(tuple(endpoints))
    return rows


def owned_socket_rows(pid, kind):
    if type(pid) is not int or pid <= 0 or kind not in ('udp', 'tcp'):
        return []
    try:
        base = Path('/proc')/str(pid)
        owned = set()
        for index, fd in enumerate((base/'fd').iterdir()):
            if index >= 256:
                break
            try:
                match = re.fullmatch(r'socket:\[([0-9]+)\]', os.readlink(fd))
                if match:
                    owned.add(int(match[1]))
            except OSError:
                continue
        with (base/'net'/kind).open('r', encoding='ascii') as stream:
            text = stream.read(65537)
        return parse_socket_rows(text, owned) if len(text) <= 65536 else []
    except (OSError, ValueError):
        return []


def socket_details(events, pid):
    details = events.snapshot()['details']
    if 'server_ipv4' not in details or 'server_port' not in details or 'protocol' not in details:
        return
    kind = 'udp' if details['protocol'] == 'udp4' else 'tcp'
    rows = owned_socket_rows(pid, kind)
    matches = [row for row in rows if row[2:] == (details['server_ipv4'], details['server_port'])]
    if not matches and kind == 'udp':
        matches = [row for row in rows if row[2:] == ('0.0.0.0', 0)]
    if len(matches) == 1:
        address, port = matches[0][:2]
        if not 1 <= port <= 65535:
            return
        updates = {'local_port': port}
        if address != '0.0.0.0':
            updates['local_ipv4'] = address
        details_update(events, updates)


def tunnel_details(events):
    interface = events.snapshot()['details'].get('tunnel_interface', 'tun0')
    links = diagnostic(['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', interface])
    if isinstance(links, list):
        for link in links:
            if isinstance(link, dict) and isinstance(link.get('addr_info'), list):
                if type(link.get('mtu')) is int and 68 <= link['mtu'] <= 65535:
                    details_update(events, {'tunnel_mtu': link['mtu']})
                for item in link['addr_info']:
                    if isinstance(item, dict) and item.get('family') == 'inet' and isinstance(item.get('local'), str):
                        try:
                            details_update(events, {'tunnel_interface': interface, 'tunnel_ipv4': item['local']})
                        except session_channel.ChannelError:
                            continue
    routes = diagnostic(['/usr/sbin/ip', '-j', '-4', 'route', 'show'])
    if isinstance(routes, list):
        destinations = {row.get('dst') for row in routes if isinstance(row, dict) and row.get('dev') == interface
                        and isinstance(row.get('dst'), str)}
        details_update(events, {'split_routes_verified': {'0.0.0.0/1', '128.0.0.0/1'} <= destinations})
    route = diagnostic(['/usr/sbin/ip', '-j', '-4', 'route', 'get', '9.9.9.9'])
    if isinstance(route, list) and len(route) == 1 and isinstance(route[0], dict) and isinstance(route[0].get('dev'), str):
        try:
            details_update(events, {'route_interface': route[0]['dev']})
        except session_channel.ChannelError:
            return
    try:
        details_update(events, {'dns_file_verified': network_setup.resolver_read() == network_setup.MANAGED_DNS})
    except (OSError, portal_helper.Refused):
        return


DNS_QUESTION = b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
DNS_NAME = (b'example', b'com')


def dns_name(packet, offset):
    """Read one bounded DNS name, rejecting compression loops and bad labels."""
    labels = []
    visited = set()
    end = None
    size = 1
    while True:
        if offset >= len(packet) or offset in visited or len(visited) >= 128:
            raise ValueError('Invalid DNS name.')
        visited.add(offset)
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError('Invalid DNS pointer.')
            pointer = ((length & 0x3f) << 8) | packet[offset+1]
            # A compressed name can only refer to a prior name in the packet.
            if pointer < 12 or pointer >= offset:
                raise ValueError('Invalid DNS pointer.')
            if end is None:
                end = offset+2
            offset = pointer
            continue
        if length & 0xc0 or offset+1+length > len(packet):
            raise ValueError('Invalid DNS label.')
        offset += 1
        if length == 0:
            return tuple(labels), end if end is not None else offset
        labels.append(packet[offset:offset+length].lower())
        size += length+1
        if size > 255:
            raise ValueError('DNS name is too long.')
        offset += length


def dns_reply_status(packet, identifier):
    """Validate only our fixed query. Return a fixed status, never raw DNS data."""
    try:
        if not 12 <= len(packet) <= 4096:
            return 'invalid'
        ident, flags, questions, answers, authorities, additional = struct.unpack('!6H', packet[:12])
        if ident != identifier or flags & 0xf800 != 0x8000 or flags & 0x0040 or questions != 1:
            return 'invalid'
        name, offset = dns_name(packet, 12)
        if name != DNS_NAME or packet[offset:offset+4] != struct.pack('!HH', 1, 1):
            return 'invalid'
        offset += 4
        if flags & 0x0200:
            return 'truncated'
        rcode = flags & 15
        if rcode:
            return {2: 'servfail', 5: 'refused'}.get(rcode, 'rcode_error')
        if answers+authorities+additional > 128:
            return 'invalid'
        records = []
        for index in range(answers+authorities+additional):
            owner, offset = dns_name(packet, offset)
            if offset+10 > len(packet):
                return 'invalid'
            kind, family, _, length = struct.unpack('!HHIH', packet[offset:offset+10])
            offset += 10
            end = offset+length
            if end > len(packet):
                return 'invalid'
            target = None
            if kind == 1 and length != 4:
                return 'invalid'
            if kind == 5:
                target, cname_end = dns_name(packet, offset)
                if cname_end != end:
                    return 'invalid'
            if index < answers and family == 1:
                records.append((owner, kind, target))
            offset = end
        if offset != len(packet):
            return 'invalid'
        # Accommodate a bounded CNAME chain, without accepting an unrelated A
        # record injected elsewhere in the answer or additional section.
        expected = DNS_NAME
        seen = set()
        for _ in range(16):
            if expected in seen:
                return 'invalid'
            seen.add(expected)
            if any(owner == expected and kind == 1 for owner, kind, _ in records):
                return 'ok'
            targets = {target for owner, kind, target in records if owner == expected and kind == 5}
            if len(targets) != 1:
                return 'no_answer'
            expected = next(iter(targets))
        return 'invalid'
    except (ValueError, struct.error):
        return 'invalid'


def dns_tunnel_source():
    routes = diagnostic(['/usr/sbin/ip', '-j', '-4', 'route', 'get', network_setup.DNS])
    if (not isinstance(routes, list) or len(routes) != 1 or not isinstance(routes[0], dict)
            or routes[0].get('dev') != 'tun0' or routes[0].get('type', 'unicast') != 'unicast'):
        return None
    source = routes[0].get('prefsrc', routes[0].get('src'))
    try:
        address = ipaddress.IPv4Address(source)
        if address.is_unspecified or address.is_multicast or address.is_loopback or str(address) != source:
            return None
    except (ValueError, TypeError):
        return None
    links = diagnostic(['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', 'tun0'])
    if not isinstance(links, list):
        return None
    for link in links:
        if (isinstance(link, dict) and link.get('ifname') == 'tun0' and 'UP' in link.get('flags', [])
                and isinstance(link.get('addr_info'), list)
                and any(isinstance(item, dict) and item.get('family') == 'inet' and item.get('local') == source
                        for item in link['addr_info'])):
            return source
    return None


def private_dns_probe():
    """One short UDP test, bound to the verified tunnel. Never use a fallback."""
    source = dns_tunnel_source()
    if source is None:
        return 'route_unavailable', 0
    started = time.monotonic()
    def result(status):
        return status, min(10000, int(max(0, time.monotonic()-started)*1000))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'tun0\0')
            channel.bind((source, 0))
            channel.settimeout(3)
            channel.connect((network_setup.DNS, 53))
            identifier = secrets.randbelow(65536)
            question = struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0)+DNS_QUESTION
            channel.send(question)
            packet, peer = channel.recvfrom(4097)
            if peer != (network_setup.DNS, 53):
                return result('invalid')
            return result(dns_reply_status(packet, identifier))
    except socket.timeout:
        return result('timeout')
    except OSError:
        return result('transport_failed')


class DNSHealthWatch:
    """One bounded worker; only the session loop may publish current results."""
    def __init__(self):
        self.generation = 0
        self.active = False
        self.next_at = 0
        self.worker = None
        self.results = queue.SimpleQueue()

    def observe(self, code):
        if code == 'tunnel_ready' or code == 'reconnecting' or code == 'stopping' or code in session_channel.FAILURES:
            self.generation += 1
            self.active = code == 'tunnel_ready'
            self.next_at = 0
            return {'dns_health': 'unchecked', 'dns_latency_ms': 0}
        return {}

    def _run(self, generation):
        try:
            status, elapsed = private_dns_probe()
        except (OSError, ValueError, TypeError):
            status, elapsed = 'transport_failed', 0
        self.results.put((generation, status, elapsed))

    def poll(self, now):
        updates = []
        while True:
            try:
                generation, status, elapsed = self.results.get_nowait()
            except queue.Empty:
                break
            if self.active and generation == self.generation:
                updates.append(('dns_'+status, {'dns_health': status, 'dns_latency_ms': elapsed}))
        if self.worker is not None and not self.worker.is_alive():
            self.worker = None
        if self.active and self.worker is None and now >= self.next_at:
            self.next_at = now+30
            self.worker = threading.Thread(target=self._run, args=(self.generation,), daemon=True)
            self.worker.start()
            updates.append(('dns_checking', {'dns_health': 'checking', 'dns_latency_ms': 0}))
        return updates


def main(owner_uid):
    events = None
    try:
        if os.geteuid() != 0:
            raise portal_helper.Refused('Requires explicit sudo in a visible terminal.')
        if type(owner_uid) is not int or owner_uid<=0:
            raise portal_helper.Refused('Run the app as your desktop user and authenticate through sudo.')
        events = session_channel.Events()
        events.add('starting')
        initial_details(events, load_policy())
        print(session_channel.format_event(events.add('preflight')),flush=True)
        retain_last(owner_uid,events,None)
        fd = os.open('/run/vpn-dashboard-portal.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
                raise portal_helper.Refused('Unsafe runtime lock file.')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise portal_helper.Refused('Another VPN action or session is active; stop it before connecting.') from None
            command = prepare_session()
            print('Portal verified closed. Starting OpenVPN; shared action lock held until exit.', flush=True)
            # One more check after firewall validation. External root network
            # managers remain outside this lock's trust boundary.
            portal_helper.check_network()
            version = diagnostic([command[0], '--version'], as_json=False)
            if isinstance(version, str):
                for line in version.splitlines():
                    details_update(events, session_channel.parse_details(line))
            return controlled_session(command,owner_uid,events=events)
    except (portal_helper.Refused,session_channel.ChannelError, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print('VPN NOT CONFIRMED: ' + (str(exc) if isinstance(exc, portal_helper.Refused)
                                      else 'Session verification or action lock failed. No automatic retry.'), flush=True)
        if events is not None:
            reason=next((code for code,message in session_channel.REFUSALS.items() if str(exc)==message),'local_check')
            details_update(events,{'preflight_reason':reason})
            events.add('preflight_failed')
            retain_last(owner_uid, events, None)
        return 1


def controlled_session(command,owner_uid,*,events=None):
    if type(owner_uid) is not int or owner_uid<=0:
        raise portal_helper.Refused('Start the app as your normal desktop user, then authenticate with sudo.')
    if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
        raise portal_helper.Refused('This controlled session requires Linux process-descriptor signaling.')
    events=events if events is not None else session_channel.Events()
    for code in ('guard_checked', 'dns_configured', 'credentials'):
        print(session_channel.format_event(events.add(code)),flush=True)
    process=None
    pidfd=None
    stop_at=None
    termination_requested=False
    watch=StartupWatch(time.monotonic())
    dns_watch=DNSHealthWatch()
    health_lock=threading.RLock()
    def emit(code):
        if code == 'tunnel_ready':
            tunnel_details(events)
        with health_lock:
            if code == 'tunnel_ready' and stop_at is not None:
                return
            updates = dns_watch.observe(code)
            if updates:
                details_update(events, updates)
            row=events.add(code)
            watch.observe(code,time.monotonic())
            print(session_channel.format_event(row),flush=True)
            if code.startswith('dns_') and code[4:] in session_channel.DNS_HEALTH-{'unchecked', 'checking', 'ok'}:
                print(session_channel.DNS_RECOVERY,flush=True)
        if code in ('transport_start','server_replied','server_timeout','handshake_timeout') and process is not None and process.poll() is None:
            socket_details(events,process.pid)
        retain_last(owner_uid,events,None)
    def line_event(value):
        line=value.decode('utf-8',errors='replace').strip()
        details_update(events,session_channel.parse_details(line))
        code=session_channel.classify(line)
        if code:
            emit(code)
    def stop():
        nonlocal stop_at
        # The IPC stop callback runs in a different thread. Serialize health
        # publication with its reset so an already-completed probe cannot mark
        # a stopping session healthy after the stop acknowledgement.
        with health_lock:
            if stop_at is None:
                stop_at=time.monotonic()
                emit('stopping')
        try:
            if pidfd is not None:
                signal.pidfd_send_signal(pidfd,signal.SIGTERM)
            elif process is not None:
                # Constructor cleanup only: this Popen object still owns the
                # just-created child if acquiring its pidfd failed. No PID is
                # ever supplied by a caller or read from a mutable file.
                process.terminate()
        except ProcessLookupError:
            # The child already exited; there is nothing left to signal.
            return
    def request_termination(number,frame):
        nonlocal termination_requested
        # Signal handlers must not acquire a lock that interrupted Python code
        # may already hold. The session loop handles the request promptly.
        termination_requested=True
    previous_handler=signal.getsignal(signal.SIGTERM)
    try:
        with session_channel.Server(owner_uid,events,stop):
            if stop_at is not None:
                return 0
            process=subprocess.Popen(command,cwd='/',extra_groups=[],stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     env={'PATH':'/usr/sbin:/usr/bin','LC_ALL':'C'})
            pidfd=os.pidfd_open(process.pid)
            if stop_at is not None:
                signal.pidfd_send_signal(pidfd,signal.SIGTERM)
            signal.signal(signal.SIGTERM,request_termination)
            buffer=b''
            discarding=False
            checked_at=0.0
            os.set_blocking(process.stdout.fileno(),False)
            while True:
                try:
                    if termination_requested:
                        stop()
                    expired=watch.expired(time.monotonic())
                    if stop_at is None and expired:
                        emit(expired)
                        print('The kill switch remains enabled. After this session stops, use Restore normal networking to return to Wi-Fi.',flush=True)
                        stop()
                    if stop_at is None and time.monotonic()-checked_at>=3:
                        if not network_setup.verify_during_session():
                            events.add('dns_repaired')
                        checked_at=time.monotonic()
                    with health_lock:
                        if stop_at is None:
                            for code, updates in dns_watch.poll(time.monotonic()):
                                details_update(events, updates)
                                emit(code)
                    if stop_at is not None and time.monotonic()-stop_at>10 and process.poll() is None:
                        signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                    if select.select([process.stdout],[],[],.25)[0]:
                        chunk=os.read(process.stdout.fileno(),4096)
                        if not chunk and process.poll() is not None:
                            if buffer and not discarding:
                                line_event(buffer)
                            break
                        if not chunk:
                            time.sleep(.1)
                            continue
                        for part in chunk.splitlines(keepends=True):
                            complete=part.endswith(b'\n')
                            if not discarding:
                                buffer+=part
                                if len(buffer)>8192:
                                    buffer=b''
                                    discarding=True
                            if complete:
                                if not discarding:
                                    line_event(buffer)
                                buffer=b''
                                discarding=False
                    elif process.poll() is not None:
                        if buffer and not discarding:
                            line_event(buffer)
                        break
                except KeyboardInterrupt:
                    stop()
            result=process.wait()
            details_update(events,dns_watch.observe('stopping'))
            events.add('stopped' if result==0 or stop_at is not None else 'process_failed')
            print(session_channel.MESSAGES['stopped' if result==0 or stop_at is not None else 'process_failed'],flush=True)
            print('OpenVPN exit status: '+str(result),flush=True)
            failed=events.snapshot()['state']=='error'
            if failed:
                emit('attempt_failed')
            # Leave the final status available briefly for the desktop poller.
            time.sleep(1)
            return 1 if failed else 0 if stop_at is not None else result
    except (portal_helper.Refused,OSError,ValueError,session_channel.ChannelError):
        events.add('process_failed')
        print('VPN stopped after a session or network-policy verification failure. Keep the guard enabled.',flush=True)
        return 1
    finally:
        with health_lock:
            events.set_details(dns_watch.observe('stopping'))
        signal.signal(signal.SIGTERM,previous_handler)
        if process is not None:
            if process.poll() is None:
                stop()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if pidfd is not None:
                        signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                    else:
                        process.kill()
                    process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
        retain_last(owner_uid,events,getattr(process,'returncode',None) if process is not None else None)
        if pidfd is not None:
            os.close(pidfd)

if __name__ == '__main__':
    raise SystemExit('Use the installed privileged entry point; do not sudo a checkout script.')
