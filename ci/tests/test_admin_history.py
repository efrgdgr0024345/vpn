"""Synthetic packet, retention, bounded query and private history regressions."""
import importlib.util
import os
from pathlib import Path
import socket
import sqlite3
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]

def module(name):
    spec=importlib.util.spec_from_file_location('admin_test_'+name, ROOT/'vpn-admin'/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

history=module('history');observer=module('observer')
DNS=struct.pack('!6H',1,256,1,0,0,0)+b'\x07example\x03com\x00\x00\x01\x00\x01'

def packet(payload=b'', *, source='172.27.240.10', destination='203.0.113.7', sport=32100,dport=443, tcp=False,seq=1,flags=16):
    if tcp:
        transport=struct.pack('!HHIIBBHHH',sport,dport,seq,0,80,flags,4096,0,0)+payload
    else:
        transport=struct.pack('!HHHH',sport,dport,len(payload)+8,0)+payload
    return struct.pack('!BBHHHBBH4s4s',69,0,20+len(transport),0,0,64,6 if tcp else 17,0,
                       socket.inet_aton(source),socket.inet_aton(destination))+transport

def record(number=1,now=None):
    value=observer.Tracker({'172.27.240.10':'kali'})
    value.observe(packet(),now or int(time.time()*1000))
    row=next(iter(value.pending.values()));row['key']=f'{number:032x}';return row

class PacketTests(unittest.TestCase):
    def test_headers_and_dns_questions_are_bounded(self):
        self.assertEqual(observer.questions(DNS),[('example.com',1)])
        for data in (b'',DNS[:15],DNS[:12]+b'\xc0\x0c',DNS[:12]+b'\x3f'+b'x'*3):
            self.assertEqual(observer.questions(data),[])
        for length in range(28):
            self.assertIsNone(observer.packet(packet()[:length]))

    def test_flow_reply_accounting_and_private_polling_exclusion(self):
        tracker=observer.Tracker({'172.27.240.10':'kali'})
        tracker.observe(packet(b'not-stored'),1000)
        tracker.observe(packet(b'also-not-stored',source='203.0.113.7',destination='172.27.240.10',sport=443,dport=32100),2000)
        row=next(iter(tracker.pending.values()))
        history.validate_record(row)
        self.assertTrue(row['reply_observed']);self.assertGreater(row['reply_bytes'],0)
        self.assertNotIn('payload',row)
        tracker.observe(packet(destination='172.27.240.1',dport=8443),3000)
        self.assertEqual(len(tracker.pending),1)

    def test_udp_dns_and_segmented_tcp_dns(self):
        tracker=observer.Tracker({'172.27.240.10':'kali'})
        tracker.observe(packet(DNS,destination='172.27.240.1',dport=53),1000)
        tracker.observe(packet(tcp=True,dport=53,flags=2,seq=5),2000)
        wire=len(DNS).to_bytes(2,'big')+DNS
        tracker.observe(packet(wire[:8],tcp=True,dport=53,seq=6),2001)
        tracker.observe(packet(wire[8:],tcp=True,dport=53,seq=14),2002)
        self.assertEqual(len(tracker.pending),2)
        self.assertTrue(all(v['domain']=='example.com' for v in tracker.pending.values()))
        tracker.observe(packet(b'gap',tcp=True,dport=53,seq=900),2003)
        self.assertEqual(tracker.counters['dns_gaps'],1)

    def test_tcp_syn_retransmission_does_not_invent_another_connection(self):
        tracker=observer.Tracker({'172.27.240.10':'kali'})
        tracker.observe(packet(tcp=True,flags=2),1000)
        tracker.observe(packet(tcp=True,flags=2),1100)
        self.assertEqual(len(tracker.pending),1)
        tracker.observe(packet(tcp=True,flags=2,seq=9),1200)
        self.assertEqual(len(tracker.pending),2)

    def test_queue_and_live_tracking_are_bounded(self):
        tracker=observer.Tracker({'172.27.240.10':'kali'})
        with patch.object(observer,'MAX_FLOWS',20):
            for port in range(600): tracker.observe(packet(sport=port),1000)
        self.assertLessEqual(len(tracker.flows),20)
        self.assertEqual(len(tracker.pending),512)
        self.assertEqual(tracker.counters['queue_drops'],88)

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'history.sqlite3'
        # /tmp ancestry is intentionally writable; production rejects it.
        self.trust=patch.object(history,'trusted');self.trust.start();self.addCleanup(self.trust.stop)
        self.uid=patch.object(history,'ROOT_UID',os.getuid());self.uid.start();self.addCleanup(self.uid.stop)
        self.store=history.Store(os.getgid(),self.path);self.addCleanup(self.store.close)
        self.counters={'socket_drops':0,'dns_gaps':0,'queue_drops':0}

    def test_store_query_parameterization_private_shape_and_read_only(self):
        self.store.write([record()],self.counters)
        value=history.query({'search':'203.0.113','device':'kali'},self.path)
        self.assertTrue(value['collector_running']);self.assertEqual(len(value['records']),1)
        self.assertNotIn('key',value['records'][0]);self.assertEqual(value['retention_days'],30)
        self.assertEqual(value['storage_cap_bytes'],64*1024*1024)
        self.assertEqual(history.query({'search':'nothing'},self.path)['records'],[])
        for bad in ({'search':"' OR 1=1"},{'limit':'201'},{'limit':'0'},{'x':'y'},{'from':'2026-01-01'}, {'search':'%'}):
            with self.subTest(bad=bad),self.assertRaises(ValueError): history.query(bad,self.path)

    def test_pagination_retention_and_capacity_evict_oldest(self):
        now=int(time.time()*1000)
        self.store.write([record(1,now-31*86400000),record(2,now),record(3,now)],self.counters)
        self.store.write([],self.counters)
        result=history.query({'limit':'1'},self.path)
        self.assertEqual(result['record_count'],2)
        second=history.query({'limit':'1','before':str(result['next_before'])},self.path)
        self.assertNotEqual(result['records'][0]['id'],second['records'][0]['id'])
        with patch.object(history,'MAX_ROWS',513):
            self.store.write([record(4,now),record(5,now)],self.counters)
            self.store.write([],self.counters)
        self.assertGreater(self.store.evicted,0)

    def test_bad_records_and_unprotected_database_are_refused(self):
        with self.assertRaises(ValueError): self.store.write([{**record(),'payload':'secret'}],self.counters)
        self.path.chmod(0o666)
        with self.assertRaises(RuntimeError): history.query({},self.path)

    def test_capture_restart_is_visible_and_drop_counters_survive(self):
        self.store.write([],{'socket_drops':3,'dns_gaps':2,'queue_drops':1})
        other=history.Store(os.getgid(),self.path)
        try:
            self.assertEqual(other.capture_starts,2)
            self.assertEqual(other.counters['socket_drops'],3)
        finally: other.close()

    def test_no_tunnel_maintenance_prunes_without_claiming_capture_is_running(self):
        self.store.write([record(1,int(time.time()*1000)-31*86400000)],self.counters)
        self.store.write([],self.counters,active=False)
        result=history.query({},self.path)
        self.assertFalse(result['collector_running'])
        self.assertEqual(result['record_count'],0)

    def test_writer_rollback_preserves_eviction_accounting(self):
        self.store.write([record(1),record(2)],self.counters)
        self.store.db.execute("CREATE TRIGGER reject_writes BEFORE INSERT ON observations BEGIN SELECT RAISE(ABORT,'fixture'); END;")
        self.store.db.commit()
        with patch.object(history,'MAX_ROWS',512),self.assertRaises(sqlite3.Error):
            self.store.write([record(3)],self.counters)
        self.assertEqual(self.store.evicted,0)
        self.assertEqual(history.query({},self.path)['record_count'],2)

    def test_broken_database_is_reported_without_sql_details(self):
        self.store.db.execute('DROP TABLE observations');self.store.db.commit()
        with self.assertRaisesRegex(RuntimeError,'^Private history unavailable.$'):
            history.query({},self.path)

if __name__=='__main__': unittest.main()
