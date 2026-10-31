import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    specification = importlib.util.spec_from_file_location(name, ROOT/'vpn-admin'/filename)
    value = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(value)
    return value


schema = module('admin_collector_schema_tests', 'schema.py')
collector = module('admin_collector_tests', 'collector.py')
STAMP = '2026-10-31T10:11:12+00:00'


def devices():
    return {name: {'cn': 'vpn-'+name+'-PRIVATE', 'sha256': str(index+1)*64,
                   'address': '172.27.240.'+str(index+10), 'enabled': True}
            for index, name in enumerate(schema.DEVICE_NAMES)}


def observation():
    return {'services': [{'unit': unit, 'active_state': 'active', 'sub_state': 'running',
                         'restarts': 0, 'result': 'success'} for unit in schema.SERVICE_UNITS],
            'tunnel': {'present': True, 'kind': 'tun', 'up': True, 'ipv4': ['172.27.240.1/24']},
            'authorization': {'element_count': 0, 'addresses': []},
            'dns_probe': {'status': 'ok', 'rcode': 0, 'answer_count': 1, 'elapsed_ms': 2}}


def snapshot():
    return {'version': 1, 'generated_at': STAMP, 'monotonic': 100.5,
            **observation(), 'devices': collector.registry_devices(json.dumps(devices()), schema.DEVICE_NAMES),
            'ipv6': {'kernel_disabled': True, 'boot_argument_active': True}, 'events': []}


class PanelSchemaTests(unittest.TestCase):
    def test_exact_public_snapshot_validates_without_private_common_names(self):
        value = snapshot()
        self.assertIs(schema.validate_snapshot(value), value)
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_unknown_nested_fields_invalid_states_and_numbers_are_refused(self):
        examples = []
        for location in ((), ('services', 0), ('tunnel',), ('devices', 0), ('ipv6',), ('dns_probe',)):
            value = snapshot()
            target = value
            for component in location:
                target = target[component]
            target['password'] = 'PRIVATE_SECRET'
            examples.append(value)
        for field, bad in (('version', True), ('monotonic', True), ('monotonic', float('nan')),
                           ('monotonic', float('inf')), ('generated_at', 'PRIVATE_SECRET')):
            value = snapshot()
            value[field] = bad
            examples.append(value)
        value = snapshot()
        value['services'][0]['active_state'] = 'PRIVATE_SECRET'
        examples.append(value)
        value = snapshot()
        value['dns_probe']['answer_count'] = 0
        examples.append(value)
        value = snapshot()
        value['devices'][1]['certificate_sha256'] = value['devices'][0]['certificate_sha256']
        examples.append(value)
        value = snapshot()
        value['authorization'] = {'element_count': 1, 'addresses': [{'ipv4': '127.0.0.1', 'expires_ms': 10}]}
        examples.append(value)
        for value in examples:
            with self.subTest(value=value), self.assertRaises(ValueError) as error:
                schema.validate_snapshot(value)
            self.assertEqual(str(error.exception), 'Unsupported panel snapshot.')

    def test_event_allowlist_rejects_arbitrary_log_data_and_unbounded_history(self):
        good = {'utc': STAMP, 'code': 'service_state_changed',
                'unit': schema.SERVICE_UNITS[0], 'state': 'failed'}
        value = snapshot()
        value['events'] = [good]
        schema.validate_snapshot(value)
        for event in ({**good, 'message': 'PRIVATE_SECRET'}, {**good, 'code': 'PRIVATE_SECRET'},
                      {**good, 'state': 'PRIVATE_SECRET'}, {'utc': STAMP, 'code': 'authorization_granted', 'address': '8.8.8.8'}):
            value['events'] = [event]
            with self.assertRaises(ValueError):
                schema.validate_snapshot(value)
        value['events'] = [good]*(schema.MAX_EVENTS+1)
        with self.assertRaises(ValueError):
            schema.validate_snapshot(value)

    def test_unknown_observations_remain_unknown(self):
        value = snapshot()
        value['authorization'] = None
        value['ipv6'] = {'kernel_disabled': None, 'boot_argument_active': None}
        for service in value['services']:
            service.update(active_state=None, sub_state=None, restarts=None, result=None)
        self.assertIsNone(schema.validate_snapshot(value)['authorization'])


class PanelCollectorTests(unittest.TestCase):
    def engine(self):
        self.report = observation()
        diagnostics = types.SimpleNamespace(collect=lambda: copy.deepcopy(self.report), validate_report=lambda value: value)
        return collector.Collector(schema, diagnostics, now=lambda: 100.5, stamp=lambda: STAMP)

    def collect(self, engine):
        with patch.object(collector, 'protected_read', return_value=json.dumps(devices())), \
             patch.object(collector, 'ipv6_state', return_value={'kernel_disabled': True, 'boot_argument_active': True}):
            return engine.collect()

    def commit(self, engine, value, events):
        with patch.object(collector, 'write_snapshot'):
            engine.publish(value, events, 1000)

    def test_private_registry_has_exact_identity_types_and_no_credential_fields(self):
        original = devices()
        self.assertNotIn('PRIVATE', json.dumps(collector.registry_devices(json.dumps(original), schema.DEVICE_NAMES)))
        bad = copy.deepcopy(original)
        bad['kali']['password'] = 'PRIVATE_SECRET'
        with self.assertRaises(ValueError):
            collector.registry_devices(json.dumps(bad), schema.DEVICE_NAMES)
        for change in (lambda d: d.pop('android'),
                       lambda d: d['android'].update(sha256=d['kali']['sha256']),
                       lambda d: d['kali'].update(address='127.0.0.1'),
                       lambda d: d['kali'].update(enabled=1)):
            bad = copy.deepcopy(original)
            change(bad)
            with self.assertRaises(ValueError):
                collector.registry_devices(json.dumps(bad), schema.DEVICE_NAMES)

    def test_grant_history_ignores_timeout_refresh_but_records_real_changes(self):
        engine = self.engine()
        first, events = self.collect(engine)
        self.assertEqual(events, [{'utc': STAMP, 'code': 'snapshot_ready'}])
        self.commit(engine, first, events)
        self.report['authorization'] = {'element_count': 1, 'addresses': [{'ipv4': '172.27.240.10', 'expires_ms': 18000}]}
        second, events = self.collect(engine)
        self.assertEqual(events, [{'utc': STAMP, 'code': 'authorization_granted', 'address': '172.27.240.10'}])
        self.commit(engine, second, events)
        self.report['authorization']['addresses'][0]['expires_ms'] = 13000
        third, events = self.collect(engine)
        self.assertEqual(events, [])
        self.commit(engine, third, events)
        self.report['authorization'] = {'element_count': 0, 'addresses': []}
        _, events = self.collect(engine)
        self.assertEqual(events, [{'utc': STAMP, 'code': 'authorization_released', 'address': '172.27.240.10'}])

    def test_snapshot_age_includes_the_entire_collection_duration(self):
        clock = [100.0]
        report = observation()
        report['authorization'] = {'element_count': 1, 'addresses': [
            {'ipv4': '172.27.240.10', 'expires_ms': 2000}]}
        def delayed_collection():
            # A sampled two-second lease has expired by the end of this call.
            clock[0] += 3.0
            return copy.deepcopy(report)
        diagnostics = types.SimpleNamespace(collect=delayed_collection,
                                            validate_report=lambda value: value)
        engine = collector.Collector(schema, diagnostics, now=lambda: clock[0], stamp=lambda: STAMP)
        value, _ = self.collect(engine)
        self.assertEqual(value['monotonic'], 100.0)
        age_ms = (clock[0]-value['monotonic'])*1000
        self.assertEqual(age_ms, 3000)
        self.assertGreaterEqual(age_ms, value['authorization']['addresses'][0]['expires_ms'])

    def test_unknown_grant_does_not_manufacture_disconnect(self):
        engine = self.engine()
        self.report['authorization'] = {'element_count': 1, 'addresses': [{'ipv4': '172.27.240.10', 'expires_ms': 18000}]}
        first, events = self.collect(engine)
        self.commit(engine, first, events)
        self.report['authorization'] = None
        _, events = self.collect(engine)
        self.assertEqual(events, [])

    def test_failed_publish_preserves_last_snapshot_and_history(self):
        engine = self.engine()
        value, events = self.collect(engine)
        with patch.object(collector, 'write_snapshot', side_effect=OSError('PRIVATE_SECRET')):
            with self.assertRaises(OSError):
                engine.publish(value, events, 1000)
        self.assertIsNone(engine.previous)
        self.assertEqual(list(engine.events), [])
        engine.failed = True
        retry, events = self.collect(engine)
        self.assertIn({'utc': STAMP, 'code': 'collector_error'}, events)
        self.commit(engine, retry, events)
        self.assertFalse(engine.failed)

    def test_history_is_bounded_and_raw_observation_fields_do_not_leak(self):
        engine = self.engine()
        for index in range(schema.MAX_EVENTS+20):
            self.report['services'][0]['active_state'] = 'active' if index % 2 else 'inactive'
            self.report['journal'] = 'PRIVATE_SECRET'
            value, events = self.collect(engine)
            self.commit(engine, value, events)
        self.assertEqual(len(value['events']), schema.MAX_EVENTS)
        self.assertNotIn('PRIVATE_SECRET', json.dumps(value))

    def test_atomic_publication_metadata_and_no_link_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/'panel'
            target.mkdir()
            uid, gid = os.getuid(), os.getgid()
            with patch.object(collector, 'RUNTIME', target), \
                 patch.object(collector, 'ROOT_UID', uid), \
                 patch.object(collector, 'trusted_directory'), \
                 patch.object(collector, 'runtime_directory', side_effect=lambda unused: target.chmod(0o750)):
                collector.write_snapshot(snapshot(), gid, schema)
                path = target/'status.json'
                info = path.lstat()
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o640)
                self.assertEqual((info.st_uid, info.st_gid, info.st_nlink), (uid, gid, 1))
                self.assertEqual(json.loads(path.read_bytes()), snapshot())
                self.assertEqual(list(target.glob('.snapshot-*')), [])
                original = path.read_bytes()
                path.rename(target/'untouched')
                path.symlink_to(target/'untouched')
                with self.assertRaises(OSError):
                    collector.write_snapshot(snapshot(), gid, schema)
                self.assertEqual((target/'untouched').read_bytes(), original)

    def test_protected_file_rejects_hardlinks_and_writable_input(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(collector, 'ROOT_UID', os.getuid()), \
             patch.object(collector, 'trusted_directory'):
            path = Path(temporary)/'registry'
            path.write_text('{}')
            path.chmod(0o600)
            self.assertEqual(collector.protected_read(path, private=True), b'{}')
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                collector.protected_read(path, private=True)
            path.chmod(0o600)
            os.link(path, Path(temporary)/'other')
            with self.assertRaises(ValueError):
                collector.protected_read(path, private=True)

    def test_ipv6_flags_require_actual_kernel_values_and_unambiguous_argument(self):
        cases = [('1', 'root=/dev/disk ipv6.disable=1', True, True),
                 ('0', 'root=/dev/disk', False, False),
                 (None, None, None, None),
                 ('PRIVATE_SECRET', 'ipv6.disable=1 ipv6.disable=0', None, None)]
        for module_value, cmdline, disabled, active in cases:
            with self.subTest(module=module_value), patch.object(collector, 'kernel_text', side_effect=[module_value, cmdline]):
                self.assertEqual(collector.ipv6_state(), {'kernel_disabled': disabled, 'boot_argument_active': active})


if __name__ == '__main__':
    unittest.main()
