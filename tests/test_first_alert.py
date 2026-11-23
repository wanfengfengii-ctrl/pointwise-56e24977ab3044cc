from dataclasses import replace
import json
from hashlib import sha256
from pathlib import Path

from audit.archive import read_first_alert
from capture.recording import register_recording
from demo import prepare_sample
from handover.format import decode_package, encode_package
from handover.issue import issue_alert_package, issue_package
from offline.accept import accept_package
from offline.corrections import ByteConflict, CorrectionRequest
from offline.settle import correct_package
from tests import BenchCase
from tests.test_replay import LEGACY_WIRE
from views.layout import ViewLayout
from views.registry import register_views


def fixture_cases():
    path = Path(__file__).resolve().parent.parent / 'examples' / 'first_alert.json'
    return json.loads(path.read_text(encoding='utf-8'))


class FirstAlertTests(BenchCase):
    def publish_alert(self, recording, names, observation, threshold):
        return issue_alert_package(
            self.recordings, self.registry, self.index,
            recording, names, observation, threshold,
        )

    def prepare_alert(self, sample):
        recording = prepare_sample(self.recordings, self.registry, sample)
        issued = self.publish_alert(
            recording, sample['selection'], sample['observation_name'], sample['threshold'],
        )
        return recording, issued

    def test_fixture_alerts_on_source_and_after_corrections(self):
        for sample in fixture_cases():
            with self.subTest(recording=sample['recording']):
                _, issued = self.prepare_alert(sample)
                self.disconnect_source()
                parent = accept_package(self.offline, issued.wire)
                name, threshold, before = read_first_alert(self.offline, parent)
                self.assertEqual(name, sample['observation_name'])
                self.assertEqual(threshold, sample['threshold'])
                self.assertEqual(before, sample['before_alarm'])
                for trial in sample['trials']:
                    child, _ = correct_package(
                        self.offline, parent,
                        [CorrectionRequest(*request) for request in trial['requests']],
                    )
                    self.assertEqual(read_first_alert(self.offline, child)[2], trial['after_alarm'])
                self.open_source()

    def test_fixture_observation_values_match_the_complete_recording(self):
        for sample in fixture_cases():
            with self.subTest(recording=sample['recording']):
                recording = prepare_sample(self.recordings, self.registry, sample)
                views = {view.name: view for view in self.registry.get_catalog(recording)}
                observation = views[sample['observation_name']]
                # Replay each trial's corrected edits on the full source recording.
                banks = {bank.name: bytearray(bank.data) for bank in self.recordings.get(recording).banks}
                for trial in sample['trials']:
                    working = {name: bytearray(data) for name, data in banks.items()}
                    for view_name, index, value in trial['requests']:
                        layout = views[view_name]
                        start = layout.start + index * layout.stride
                        working[layout.bank_name][start:start + layout.width] = value.to_bytes(
                            layout.width, layout.byteorder,
                        )
                    bank = working[observation.bank_name]
                    values = tuple(
                        int.from_bytes(
                            bytes(bank[observation.start + i * observation.stride + j]
                                  for j in range(observation.width)),
                            observation.byteorder,
                        )
                        for i in range(observation.count)
                    )
                    self.assertEqual(list(values), trial['after_values'])
                self.open_source()

    def test_alert_delivers_only_selected_bytes_and_sufficient_evidence(self):
        sample = fixture_cases()[0]
        _, issued = self.prepare_alert(sample)
        envelope = decode_package(issued.wire)
        self.assertEqual(envelope.payload.data.hex(), sample['selected_hex'])
        self.assertEqual(envelope.wire_version, 3)
        self.assertEqual(
            (envelope.alert.observation_name, envelope.alert.threshold),
            (sample['observation_name'], sample['threshold']),
        )
        self.assertEqual(len(envelope.alert.elements), len(sample['before_values']))
        # The decoded payload and evidence alone settle the original alert.
        self.disconnect_source()
        parent = accept_package(self.offline, issued.wire)
        self.assertEqual(read_first_alert(self.offline, parent)[2], sample['before_alarm'])

    def test_identity_replay_and_distinct_variants(self):
        sample = fixture_cases()[0]
        recording, first = self.prepare_alert(sample)
        self.source_db.close()
        self.open_source()
        again = self.publish_alert(
            recording, sample['selection'], sample['observation_name'], sample['threshold'],
        )
        self.assertEqual(again, first)
        for variant in (
            (sample['selection'], sample['observation_name'], sample['threshold'] + 1),
            (['B', 'A'], sample['observation_name'], sample['threshold']),
        ):
            self.assertNotEqual(
                self.publish_alert(recording, *variant).package_id, first.package_id,
            )
        self.assertNotEqual(
            self.publish_alert(recording, sample['selection'], 'WATCH', sample['threshold'] + 2).package_id,
            first.package_id,
        )
        normal = issue_package(
            self.recordings, self.registry, self.index, recording, sample['selection'],
        )
        self.assertNotEqual(normal.package_id, first.package_id)
        self.assertIsNone(decode_package(normal.wire).alert)
        rows = self.source_db.execute(
            'SELECT count(*) FROM issued_alert_packages WHERE recording_id = ?', (recording,),
        ).fetchone()[0]
        self.assertEqual(rows, 4)

    def test_invalid_requests_do_not_publish(self):
        sample = fixture_cases()[0]
        recording, _ = self.prepare_alert(sample)
        rows = self.source_db.execute('SELECT count(*) FROM issued_alert_packages').fetchone()[0]
        for names, observation, threshold in (
            (sample['selection'], 'WATCH', True),
            (sample['selection'], 'WATCH', -1),
            (sample['selection'], 'WATCH', 256),
            (sample['selection'], 'A', 9),
            ((), 'WATCH', 9),
            (('A', 'A'), 'WATCH', 9),
        ):
            with self.subTest(observation=observation, threshold=threshold), self.assertRaises(ValueError):
                self.publish_alert(recording, names, observation, threshold)
        with self.assertRaises(KeyError):
            self.publish_alert(recording, sample['selection'], 'NOPE', 9)
        after = self.source_db.execute('SELECT count(*) FROM issued_alert_packages').fetchone()[0]
        self.assertEqual(after, rows)

    def test_children_inherit_the_alert_and_are_independent(self):
        parent = accept_package(self.offline, self.prepare_alert(fixture_cases()[0])[1].wire)
        self.disconnect_source()
        child, receipt = correct_package(
            self.offline, parent,
            [CorrectionRequest('A', 0, 0), CorrectionRequest('B', 0, 9)],
        )
        self.assertEqual(read_first_alert(self.offline, child), ('WATCH', 9, 1))
        self.assertEqual(self.offline.get_receipt(child), receipt)
        sibling, _ = correct_package(self.offline, child, [CorrectionRequest('B', 0, 8)])
        self.assertEqual(read_first_alert(self.offline, sibling), ('WATCH', 9, 2))
        self.assertEqual(read_first_alert(self.offline, child), ('WATCH', 9, 1))
        self.assertEqual(read_first_alert(self.offline, parent), ('WATCH', 9, 0))
        self.reopen_offline()
        self.assertEqual(read_first_alert(self.offline, sibling), ('WATCH', 9, 2))
        self.assertEqual(read_first_alert(self.offline, child), ('WATCH', 9, 1))
        self.assertEqual(read_first_alert(self.offline, parent), ('WATCH', 9, 0))
        self.assertEqual(self.offline.get_receipt(sibling).request_count, 1)
        self.assertEqual(self.offline.get(sibling).parent_id, child)

    def test_legacy_and_plain_packages_refuse_first_alert(self):
        self.disconnect_source()
        accept_package(self.offline, LEGACY_WIRE)
        with self.assertRaises(ValueError):
            read_first_alert(self.offline, 'bench-legacy-001')
        self.open_source()
        sample = fixture_cases()[0]
        recording = prepare_sample(self.recordings, self.registry, sample)
        normal = issue_package(self.recordings, self.registry, self.index, recording, sample['selection'])
        parent = accept_package(self.offline, normal.wire)
        with self.assertRaises(ValueError):
            read_first_alert(self.offline, parent)
        with self.assertRaises(KeyError):
            read_first_alert(self.offline, 'missing')

    def _tamper(self, wire, mutate):
        outer = json.loads(wire)
        mutate(outer['body']['alert'])
        signed = {key: outer[key] for key in ('version', 'body')}
        outer['sha256'] = sha256(
            json.dumps(signed, sort_keys=True, separators=(',', ':')).encode('ascii')
        ).hexdigest()
        return json.dumps(outer, sort_keys=True, separators=(',', ':')).encode('ascii')

    def test_tampered_evidence_is_rejected(self):
        _, issued = self.prepare_alert(fixture_cases()[2])
        self.disconnect_source()

        def outside(alert):
            alert['elements'][0]['refs'][0] = 99

        def duplicate(alert):
            alert['elements'][0]['refs'][1] = alert['elements'][0]['refs'][0]

        def boolean(alert):
            alert['elements'][0]['refs'][0] = True

        def large_limit(alert):
            alert['elements'][0]['limit'] = 1 << 40

        def bad_threshold(alert):
            alert['threshold'] = 1 << 20

        def empty(alert):
            alert['elements'] = []

        def short(alert):
            alert['elements'][0]['refs'] = alert['elements'][0]['refs'][:1]

        def extra_field(alert):
            alert['payload'] = 'sneaky'

        for label, mutate in (
            ('outside', outside), ('duplicate', duplicate), ('boolean', boolean),
            ('limit', large_limit), ('threshold', bad_threshold),
            ('empty', empty), ('short', short), ('extra', extra_field),
        ):
            with self.subTest(label=label), self.assertRaises(ValueError):
                accept_package(self.offline, self._tamper(issued.wire, mutate))
        self.assertEqual(self.inventory(), ((), ()))
        self.assertEqual(accept_package(self.offline, issued.wire), issued.package_id)

    def test_observation_name_cannot_join_the_selection(self):
        _, issued = self.prepare_alert(fixture_cases()[0])
        envelope = decode_package(issued.wire)
        forged = replace(envelope, alert=replace(envelope.alert, observation_name='A'))
        self.assertIn('A', tuple(view.name for view in envelope.payload.views))
        with self.assertRaises(ValueError):
            accept_package(self.offline, encode_package(forged))
        self.assertEqual(self.inventory(), ((), ()))

    def test_failed_commit_leaves_no_alert_child(self):
        parent = accept_package(self.offline, self.prepare_alert(fixture_cases()[0])[1].wire)
        self.disconnect_source()
        before = self.inventory()

        def refuse():
            raise OSError('final write refused')

        with self.assertRaises(OSError):
            correct_package(self.offline, parent, [CorrectionRequest('A', 0, 0)], before_commit=refuse)
        self.assertEqual(self.inventory(), before)
        self.assertEqual(read_first_alert(self.offline, parent), ('WATCH', 9, 0))
        with self.assertRaises(ByteConflict):
            correct_package(
                self.offline, parent,
                [CorrectionRequest('A', 0, 0), CorrectionRequest('B', 0, 9),
                 CorrectionRequest('A', 0, 1)],
            )
        self.assertEqual(self.inventory(), before)

    def test_reverse_overlap_settles_through_a_shared_physical_byte(self):
        sample = fixture_cases()[2]
        _, issued = self.prepare_alert(sample)
        self.assertEqual(decode_package(issued.wire).payload.data.hex(), sample['selected_hex'])
        self.disconnect_source()
        parent = accept_package(self.offline, issued.wire)
        self.assertEqual(read_first_alert(self.offline, parent)[2], sample['before_alarm'])
        child, _ = correct_package(self.offline, parent, [CorrectionRequest('MID', 0, 9)])
        self.assertEqual(read_first_alert(self.offline, child)[2], sample['trials'][0]['after_alarm'])

    def test_threshold_zero_is_an_unsigned_integer(self):
        recording = register_recording(self.recordings, 'zero', {'P': bytes([0, 0])})
        register_views(self.recordings, self.registry, recording, [
            ViewLayout('E', 'P', 0, 1, 1, 1, 'little'),
            ViewLayout('O', 'P', 1, 1, 1, 1, 'little'),
        ])
        issued = self.publish_alert(recording, ['E'], 'O', 0)
        self.disconnect_source()
        parent = accept_package(self.offline, issued.wire)
        self.assertEqual(read_first_alert(self.offline, parent), ('O', 0, 0))

    def test_observation_outside_selection_is_a_fixed_fact(self):
        # O never touches the selection; its alarm state is independent of edits.
        recording = register_recording(self.recordings, 'outside', {'P': bytes([5, 200, 0])})
        register_views(self.recordings, self.registry, recording, [
            ViewLayout('E', 'P', 0, 1, 1, 1, 'little'),
            ViewLayout('LOW', 'P', 1, 1, 1, 1, 'little'),
            ViewLayout('HIGH', 'P', 2, 1, 1, 1, 'little'),
        ])
        low = self.publish_alert(recording, ['E'], 'LOW', 200)
        high = self.publish_alert(recording, ['E'], 'HIGH', 1)
        self.disconnect_source()
        low_parent = accept_package(self.offline, low.wire)
        high_parent = accept_package(self.offline, high.wire)
        self.assertEqual(read_first_alert(self.offline, low_parent)[2], 0)
        self.assertEqual(read_first_alert(self.offline, high_parent)[2], None)
        for parent in (low_parent, high_parent):
            child, _ = correct_package(self.offline, parent, [CorrectionRequest('E', 0, 0)])
            self.assertEqual(
                read_first_alert(self.offline, child)[2],
                read_first_alert(self.offline, parent)[2],
            )

    def test_partial_element_that_already_meets_the_threshold(self):
        # O element 0 covers P[0] (undelivered 200) and P[1] (delivered); 200 >= 100
        # regardless of what the selected byte becomes.
        recording = register_recording(self.recordings, 'partial', {'P': bytes([200, 0, 9])})
        register_views(self.recordings, self.registry, recording, [
            ViewLayout('E', 'P', 1, 1, 1, 1, 'little'),
            ViewLayout('O', 'P', 0, 1, 1, 2, 'little'),
        ])
        issued = self.publish_alert(recording, ['E'], 'O', 100)
        self.disconnect_source()
        parent = accept_package(self.offline, issued.wire)
        self.assertEqual(read_first_alert(self.offline, parent)[2], 0)
        child, _ = correct_package(self.offline, parent, [CorrectionRequest('E', 0, 3)])
        self.assertEqual(read_first_alert(self.offline, child)[2], 0)

    def test_children_of_plain_packages_still_refuse_first_alert(self):
        sample = fixture_cases()[0]
        recording = prepare_sample(self.recordings, self.registry, sample)
        normal = issue_package(self.recordings, self.registry, self.index, recording, sample['selection'])
        self.disconnect_source()
        parent = accept_package(self.offline, normal.wire)
        child, _ = correct_package(self.offline, parent, [CorrectionRequest('A', 0, 0)])
        for package_id in (parent, child):
            with self.assertRaises(ValueError):
                read_first_alert(self.offline, package_id)

    def test_single_element_wide_threshold_upper_bound(self):
        recording = register_recording(self.recordings, 'wide', {'P': bytes([255, 255, 0, 0])})
        register_views(self.recordings, self.registry, recording, [
            ViewLayout('E', 'P', 0, 2, 1, 1, 'little'),
            ViewLayout('W', 'P', 2, 2, 1, 2, 'little'),
        ])
        self.assertEqual(
            decode_package(self.publish_alert(recording, ['E'], 'W', 65535).wire)
            .alert.threshold,
            65535,
        )
        with self.assertRaises(ValueError):
            self.publish_alert(recording, ['E'], 'W', 65536)
