"""Bounded private network metadata store. Never stores packet bodies or URLs."""
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

ROOT_UID = 0
DIRECTORY = Path('/var/lib/vpn-lab-admin')
DATABASE = DIRECTORY/'history.sqlite3'
RETENTION_DAYS = 30
STORAGE_CAP = 64*1024*1024
DB_PAGES = 7680  # 30 MiB main database; rollback journal has <34 MiB headroom.
MAX_ROWS = 100000
MAX_RESULTS = 200
DEVICES = ('kali', 'iphone', 'android', 'unknown')
FIELDS = {'key','kind','device','source_ip','destination_ip','source_port','destination_port',
          'protocol','domain','query_type','first_seen','last_seen','outbound_bytes','reply_bytes','reply_observed'}


def trusted(path):
    for item in (*reversed(Path(path).parents), Path(path)):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise ValueError('Unprotected history directory.')


def database_metadata(path):
    trusted(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID
                or info.st_nlink != 1 or info.st_mode & 0o027 or info.st_size > 30*1024*1024):
            raise ValueError('Unprotected history database.')
    finally:
        os.close(fd)


def ipv4(value):
    return isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value


def domain_valid(value):
    return isinstance(value, str) and 1 <= len(value) <= 253 and all(
        re.fullmatch(r'[a-z0-9_-]{1,63}', part) for part in value.split('.'))


def validate_record(value):
    try:
        if (not isinstance(value, dict) or set(value) != FIELDS
                or not isinstance(value['key'], str) or not re.fullmatch('[0-9a-f]{32}', value['key'])
                or value['kind'] not in ('flow','dns') or value['device'] not in DEVICES
                or not ipv4(value['source_ip']) or not ipv4(value['destination_ip'])
                or ipaddress.IPv4Address(value['source_ip']) not in ipaddress.IPv4Network('172.27.240.0/24')
                or value['protocol'] not in ('tcp','udp','icmp')
                or any(v is not None and (type(v) is not int or not 0 <= v <= 65535)
                       for v in (value['source_port'],value['destination_port']))
                or any(type(value[k]) is not int or not 0 <= value[k] < 2**63
                       for k in ('first_seen','last_seen','outbound_bytes','reply_bytes'))
                or value['first_seen'] > value['last_seen'] or type(value['reply_observed']) is not bool):
            raise ValueError()
        if value['kind'] == 'dns':
            if not domain_valid(value['domain']) or type(value['query_type']) is not int or not 1 <= value['query_type'] <= 65535:
                raise ValueError()
        elif value['domain'] is not None or value['query_type'] is not None:
            raise ValueError()
        return value
    except (ValueError, KeyError, TypeError):
        raise ValueError('Unsupported network observation.') from None


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not re.fullmatch(r'[0-9a-f-]{36}', value):
        raise ValueError('Boot identity unavailable.')
    return value


class Store:
    def __init__(self, gid, path=DATABASE):
        self.path = Path(path)
        trusted(self.path.parent)
        if os.path.lexists(self.path):
            database_metadata(self.path)
        else:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o640)
            os.fchown(fd, ROOT_UID, gid)
            os.fchmod(fd, 0o640)
            os.close(fd)
        self.db = sqlite3.connect(str(self.path), timeout=1)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA page_size=4096')
        self.db.execute('PRAGMA max_page_count='+str(DB_PAGES))
        self.db.execute('PRAGMA journal_size_limit=0')
        self.db.executescript('''
CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
 device TEXT NOT NULL, source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL,
 source_port INTEGER, destination_port INTEGER, protocol TEXT NOT NULL,
 domain TEXT, query_type INTEGER, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
 outbound_bytes INTEGER NOT NULL, reply_bytes INTEGER NOT NULL, reply_observed INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS observation_time ON observations(first_seen);
CREATE INDEX IF NOT EXISTS observation_domain ON observations(domain COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS observation_destination ON observations(destination_ip COLLATE NOCASE);
''')
        self.started = int(time.time()*1000)
        self.boot = boot_id()
        self.evicted = int(self.meta('evicted', '0'))
        self.capture_starts = int(self.meta('capture_starts', '0'))+1
        self.counters = {key:int(self.meta(key, '0')) for key in ('socket_drops','dns_gaps','queue_drops')}
        self.db.commit()

    def meta(self, name, fallback):
        row = self.db.execute('SELECT value FROM metadata WHERE name=?',(name,)).fetchone()
        return row[0] if row else fallback

    def prune(self, now):
        cutoff = now-RETENTION_DAYS*86400000
        self.db.execute('DELETE FROM observations WHERE first_seen < ?', (cutoff,))
        count = self.db.execute('SELECT count(*) FROM observations').fetchone()[0]
        used = self.db.execute('PRAGMA page_count').fetchone()[0]-self.db.execute('PRAGMA freelist_count').fetchone()[0]
        remove = max(0, count-MAX_ROWS+512)
        if used > DB_PAGES-1024:
            remove = max(remove, 2000)
        if remove:
            changed = self.db.execute('DELETE FROM observations WHERE id IN (SELECT id FROM observations ORDER BY id LIMIT ?)',(remove,)).rowcount
            self.evicted += changed

    def write(self, records, counters, *, active=True):
        if len(records) > 512:
            raise ValueError('Too many observations in one batch.')
        for value in records:
            validate_record(value)
        if (set(counters) != {'socket_drops','dns_gaps','queue_drops'}
                or any(type(v) is not int or not 0 <= v < 2**63 for v in counters.values())):
            raise ValueError('Invalid capture counters.')
        previous_evicted = self.evicted
        try:
            self.prune(int(time.time()*1000))
            for value in records:
                row = dict(value)
                row['reply_observed'] = int(row['reply_observed'])
                self.db.execute('''INSERT INTO observations
(key,kind,device,source_ip,destination_ip,source_port,destination_port,protocol,domain,query_type,first_seen,last_seen,outbound_bytes,reply_bytes,reply_observed)
VALUES (:key,:kind,:device,:source_ip,:destination_ip,:source_port,:destination_port,:protocol,:domain,:query_type,:first_seen,:last_seen,:outbound_bytes,:reply_bytes,:reply_observed)
ON CONFLICT(key) DO UPDATE SET last_seen=max(last_seen,excluded.last_seen),
outbound_bytes=max(outbound_bytes,excluded.outbound_bytes), reply_bytes=max(reply_bytes,excluded.reply_bytes),
reply_observed=max(reply_observed,excluded.reply_observed)''',row)
            data = {'boot':self.boot,'heartbeat':str(time.monotonic() if active else -1000),'started':str(self.started),
                    'evicted':str(self.evicted),'capture_starts':str(self.capture_starts),**{k:str(v) for k,v in counters.items()}}
            self.db.executemany('INSERT INTO metadata(name,value) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value',data.items())
            self.db.commit()
        except (sqlite3.Error, ValueError):
            self.db.rollback()
            self.evicted = previous_evicted
            raise

    def close(self):
        self.db.close()


def filters(parameters):
    allowed = {'kind','device','search','before','from','to','limit'}
    if not isinstance(parameters, dict) or set(parameters)-allowed:
        raise ValueError('Unsupported history filter.')
    result = {'kind':'all','device':'all','search':'','limit':100,'before':2**63-1,
              'from':0,'to':2**63-1}
    for key,value in parameters.items():
        if not isinstance(value,str) or len(value)>253:
            raise ValueError('Unsupported history filter.')
        if key == 'kind':
            if value not in ('all','flow','dns'): raise ValueError('Unsupported history filter.')
            result[key]=value
        elif key == 'device':
            if value not in ('all',*DEVICES): raise ValueError('Unsupported history filter.')
            result[key]=value
        elif key == 'search':
            if value and not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,253}',value): raise ValueError('Unsupported history filter.')
            result[key]=value.lower()
        elif key in ('before','limit'):
            if not re.fullmatch(r'[1-9][0-9]{0,18}',value): raise ValueError('Unsupported history filter.')
            number=int(value)
            if number>=2**63 or key=='limit' and number>MAX_RESULTS: raise ValueError('Unsupported history filter.')
            result[key]=number
        else:
            stamp=datetime.fromisoformat(value.replace('Z','+00:00'))
            if stamp.tzinfo is None: raise ValueError('History dates require a timezone.')
            result[key]=int(stamp.timestamp()*1000)
            if not 0 <= result[key] <= 253402300799000: raise ValueError('Unsupported history date.')
    if result['from']>result['to']: raise ValueError('History date range is reversed.')
    return result


def stamp(value):
    return datetime.fromtimestamp(value/1000, timezone.utc).isoformat(timespec='milliseconds')


def _query(parameters, path=DATABASE):
    selected=filters(parameters)
    path=Path(path)
    database_metadata(path)
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.2)
    started=time.monotonic()
    db.set_progress_handler(lambda: int(time.monotonic()-started>.2),1000)
    try:
        db.execute('PRAGMA query_only=ON')
        clauses=['id < ?','first_seen >= ?','first_seen <= ?']
        args=[selected['before'],selected['from'],selected['to']]
        for key in ('kind','device'):
            if selected[key]!='all':
                clauses.append(key+' = ?');args.append(selected[key])
        if selected['search']:
            # Literal prefix search, never caller-supplied SQL or LIKE wildcards.
            term=selected['search'].replace('_','\\_')+'%'
            clauses.append("(domain LIKE ? ESCAPE '\\' OR destination_ip LIKE ? ESCAPE '\\')")
            args.extend((term,term))
        rows=db.execute('SELECT id,'+','.join(sorted(FIELDS))+' FROM observations WHERE '+' AND '.join(clauses)+' ORDER BY id DESC LIMIT ?',(*args,selected['limit']+1)).fetchall()
        records=[]
        for row in rows[:selected['limit']]:
            value=dict(zip(sorted(FIELDS),row[1:]))
            if value['reply_observed'] not in (0,1): raise RuntimeError('Invalid stored observation.')
            value['reply_observed']=bool(value['reply_observed'])
            validate_record(value)
            value.pop('key')
            value.update(id=row[0],first_seen=stamp(value['first_seen']),last_seen=stamp(value['last_seen']))
            records.append(value)
        meta=dict(db.execute('SELECT name,value FROM metadata'))
        age=time.monotonic()-float(meta.get('heartbeat','-1000'))
        count,oldest=db.execute('SELECT count(*), min(first_seen) FROM observations').fetchone()
        return {'version':1,'available':True,'collector_running':meta.get('boot')==boot_id() and 0<=age<=30,
                'retention_days':RETENTION_DAYS,'storage_cap_bytes':STORAGE_CAP,'record_cap':MAX_ROWS,
                'records':records,'next_before':records[-1]['id'] if len(rows)>selected['limit'] else None,
                'retained_from':stamp(oldest) if oldest is not None else None,'record_count':count,
                'evicted_records':int(meta.get('evicted','0')),
                'socket_drops':int(meta.get('socket_drops','0')),'dns_stream_gaps':int(meta.get('dns_gaps','0')),
                'queue_drops':int(meta.get('queue_drops','0')),'capture_starts':int(meta.get('capture_starts','0'))}
    finally:
        db.close()


def query(parameters, path=DATABASE):
    filters(parameters)  # Bad client filters remain HTTP 400, storage failures do not.
    try:
        return _query(parameters, path)
    except (sqlite3.Error, ValueError, OverflowError):
        raise RuntimeError('Private history unavailable.') from None
