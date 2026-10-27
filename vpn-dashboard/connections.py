"""Read-only socket snapshots, not packet capture or a complete traffic audit."""
from collections import deque
from datetime import datetime, timezone
import ipaddress
import re
import subprocess
from safe_io import bounded_run

SS_ARGV = ('/usr/bin/ss', '-H', '-n', '-t', '-u', '-a', '-p')

class ConnectionError(RuntimeError):
    pass


def endpoint_host(endpoint):
    if endpoint.startswith('['):
        return endpoint[1:].split(']', 1)[0]
    return endpoint.rsplit(':', 1)[0] if ':' in endpoint else endpoint


def scope(peer):
    host = endpoint_host(peer).split('%', 1)[0]
    try:
        address = ipaddress.ip_address(host)
        if address.is_loopback:
            return 'loopback'
        if address.is_link_local:
            return 'link-local'
        if address.is_private:
            return 'private/non-global'
        return 'global-address' if address.is_global else 'non-global'
    except ValueError:
        return 'unknown'


def peer_present(peer):
    host = endpoint_host(peer)
    port = peer.rsplit(':', 1)[-1]
    return host not in ('*', '0.0.0.0', '::', '') and port not in ('*', '0', '')


def process_summary(raw):
    # Only process names/PIDs, never an arbitrary remainder from command stdout.
    matches = re.findall(r'\("([^"\n]*)",pid=(\d+),fd=\d+\)', raw)
    return ', '.join(name + ' (PID ' + pid + ')' for name, pid in matches) or 'unavailable'


def parse_ss(text):
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 6)
        if len(parts) < 6 or parts[0].lower() not in ('tcp', 'udp'):
            raise ConnectionError('Unsupported socket output; snapshot not updated.')
        protocol, state, recvq, sendq, local, peer = parts[:6]
        state = state.upper()
        if state not in {'ESTAB', 'SYN-SENT', 'SYN-RECV', 'FIN-WAIT-1', 'FIN-WAIT-2', 'TIME-WAIT', 'CLOSE', 'CLOSE-WAIT', 'LAST-ACK', 'LISTEN', 'CLOSING', 'UNCONN'}:
            raise ConnectionError('Unsupported socket state; snapshot not updated.')
        if not recvq.isdigit() or not sendq.isdigit():
            raise ConnectionError('Unsupported socket output; snapshot not updated.')
        if state.upper() == 'LISTEN' or not peer_present(peer):
            continue
        records.append({'protocol': protocol.upper(), 'state': state,
                        'local': local, 'peer': peer,
                        'process': process_summary(parts[6] if len(parts) == 7 else ''),
                        'direction': 'UNKNOWN', 'scope': scope(peer)})
        if len(records) > 2000:
            raise ConnectionError('More than 2000 sockets; snapshot not updated to avoid partial coverage.')
    return records


def collect_connections():
    try:
        result = bounded_run(SS_ARGV, capture_output=True, text=True,
                                timeout=5, check=False,
                                env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
    except FileNotFoundError as error:
        raise ConnectionError('ss is not installed at /usr/bin/ss.') from error
    except subprocess.TimeoutExpired as error:
        raise ConnectionError('Socket check timed out; snapshot not updated.') from error
    except (OSError, UnicodeError, subprocess.SubprocessError) as error:
        raise ConnectionError('Socket information unavailable; snapshot not updated.') from error
    if result.returncode != 0 or result.stderr.strip():
        raise ConnectionError('Socket check failed or permission was denied; snapshot not updated.')
    if len(result.stdout) > 2_000_000:
        raise ConnectionError('Socket output exceeds safe snapshot size; snapshot not updated.')
    return parse_ss(result.stdout)


def record_key(record):
    return tuple(record.get(field, '') for field in
                 ('protocol', 'state', 'local', 'peer', 'process', 'direction', 'scope'))


class Tracker:
    def __init__(self, limit=300):
        self.events = deque(maxlen=max(1, min(limit, 300)))
        self.previous = {}

    def update(self, records):
        if len(records) > 2000:
            raise ConnectionError('More than 2000 sockets; history not updated.')
        current = {record_key(record): dict(record) for record in records}
        added = [current[key] for key in current.keys() - self.previous.keys()]
        removed = [self.previous[key] for key in self.previous.keys() - current.keys()]
        timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds')
        for action, rows in (('observed', added), ('no longer observed', removed)):
            for record in sorted(rows, key=record_key):
                self.events.append({'timestamp': timestamp, 'action': action, 'record': record})
        self.previous = current
        return added, removed


def format_record(record, redacted=True):
    local = '[ENDPOINT]' if redacted else record['local']
    peer = '[ENDPOINT]' if redacted else record['peer']
    process = '[PROCESS]' if redacted else record['process']
    return (f"{record['protocol']} {record['state']} local={local} peer={peer} "
            f"process={process} direction=UNKNOWN scope={record['scope']}")


def format_export(records, events, redacted=True, snapshot_at=None):
    lines = ['VPN Desk — observed socket metadata',
             'Privacy: ' + ('REDACTED endpoints/processes' if redacted else 'RAW endpoints/processes — inspect before sharing'),
             'Export generated UTC: ' + datetime.now(timezone.utc).isoformat(timespec='seconds'),
             'Last successful snapshot UTC: ' + (snapshot_at or 'not recorded'),
             'Not all internet connections: short-lived sockets may be missed; process details may be unavailable.',
             'Direction UNKNOWN: a peer does not establish inbound/outbound direction.',
             'Listening/wildcard-peer sockets excluded. No packet payload or password capture.',
             '', 'CURRENT SNAPSHOT']
    lines.extend(format_record(record, redacted) for record in records)
    lines.extend(['', 'BOUNDED OBSERVATION HISTORY (state changes may appear as removed + added)'])
    for event in events:
        lines.append(event['timestamp'] + ' ' + event['action'] + ' ' + format_record(event['record'], redacted))
    return '\n'.join(lines) + '\n'
