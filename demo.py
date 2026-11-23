from contextlib import closing
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory

from audit.archive import read_audit, read_first_alert, source_check
from audit.compare import compare_audits
from capture.catalog import RecordingCatalog
from capture.recording import register_recording
from handover.issue import issue_alert_package, issue_package
from handover.issued_index import IssuedIndex
from offline.accept import accept_package
from offline.corrections import ByteConflict, CorrectionRequest
from offline.revisions import RevisionStore
from offline.settle import correct_package
from views.layout import ViewLayout
from views.registry import ViewRegistry, register_views


def load_sample() -> dict:
    return json.loads((Path(__file__).resolve().parent / 'examples' / 'bench.json').read_text(encoding='utf-8'))


def prepare_sample(recordings: RecordingCatalog, registry: ViewRegistry, sample: dict) -> str:
    banks = {name: bytes(values) for name, values in sample['banks'].items()}
    recording = register_recording(recordings, sample['recording'], banks)
    register_views(recordings, registry, recording, (ViewLayout(**row) for row in sample['views']))
    return recording


def _scenario(case_id, inputs, expected, actual, downstream_expected, downstream_actual, paths, oracle):
    if actual != expected or downstream_actual != downstream_expected:
        marker = 'SHARED_BYTE_SETTLEMENT_MISMATCH' if case_id in ('n6', 'n7') else 'HANDOVER_MISMATCH'
        raise SystemExit(f'{marker} {case_id} actual={actual!r} downstream={downstream_actual!r}')
    result = {
        'case_id': case_id,
        'input': inputs,
        'expected': expected,
        'actual': actual,
        'downstream_expected': downstream_expected,
        'downstream_actual': downstream_actual,
        'code_paths': paths,
        'oracle': oracle,
    }
    print('POINTWISE_SCENARIO ' + json.dumps(result, sort_keys=True), flush=True)


def _counts(connection):
    revisions = connection.execute('SELECT count(*) FROM revisions').fetchone()[0]
    receipts = connection.execute('SELECT count(*) FROM correction_receipts').fetchone()[0]
    return [revisions, receipts]


def _load_alert_sample() -> dict:
    path = Path(__file__).resolve().parent / 'examples' / 'first_alert.json'
    return json.loads(path.read_text(encoding='utf-8'))[0]


def run_alert_demo(root: Path) -> None:
    sample = _load_alert_sample()
    names = sample['selection']
    source_path = root / 'alert-source.sqlite'
    offline_path = root / 'alert-offline.sqlite'
    with closing(sqlite3.connect(source_path)) as source:
        recordings, registry, index = RecordingCatalog(source), ViewRegistry(source), IssuedIndex(source)
        recordings.initialize()
        registry.initialize()
        index.initialize()
        recording = prepare_sample(recordings, registry, sample)
        observation = source_check(recordings, registry, recording, sample['observation_name'])
        issued = issue_alert_package(
            recordings, registry, index, recording, names,
            sample['observation_name'], sample['threshold'],
        )
        replay = issue_alert_package(
            recordings, registry, index, recording, names,
            sample['observation_name'], sample['threshold'],
        )
        if replay.package_id != issued.package_id or replay.wire != issued.wire:
            raise SystemExit('ALERT_ISSUE_REPLAY_MISMATCH')
        print(f'首告警发行 {issued.package_id} 观察={sample["observation_name"]} '
              f'原值={list(observation.values)} 门槛={sample["threshold"]}')
    source_path.rename(root / 'alert-disconnected.sqlite')

    with closing(sqlite3.connect(offline_path)) as connection:
        store = RevisionStore(connection)
        store.initialize()
        parent_id = accept_package(store, issued.wire)
        parent_alert = read_first_alert(store, parent_id)
        if parent_alert != (sample['observation_name'], sample['threshold'], sample['before_alarm']):
            raise SystemExit('ALERT_PARENT_MISMATCH')
        print(f'源库退场后实收 {parent_id} 首告警={parent_alert[2]}')

        child_id, receipt = correct_package(
            store, parent_id, [CorrectionRequest(*request) for request in sample['trials'][0]['requests']],
        )
        child_alert = read_first_alert(store, child_id)
        if child_alert[2] != sample['trials'][0]['after_alarm']:
            raise SystemExit('ALERT_CHILD_MISMATCH')
        if read_first_alert(store, parent_id) != parent_alert:
            raise SystemExit('ALERT_PARENT_NOT_PRESERVED')
        print(f'整批更正 A=0 后子件 {child_id} 首告警={child_alert[2]}，原件仍为 {parent_alert[2]}')

        batch = [CorrectionRequest(*request) for request in sample['trials'][1]['requests']]
        together_id, _ = correct_package(store, parent_id, batch)
        together = read_first_alert(store, together_id)
        if together[2] != sample['trials'][1]['after_alarm']:
            raise SystemExit('ALERT_BATCH_MISMATCH')
        print(f'同批更正 A=0 B=9 后子件 {together_id} 首告警={together[2]}')

    with closing(sqlite3.connect(offline_path)) as connection:
        store = RevisionStore(connection)
        store.initialize()
        for package_id, expected in (
            (parent_id, parent_alert[2]),
            (child_id, child_alert[2]),
            (together_id, together[2]),
        ):
            observed = read_first_alert(store, package_id)[2]
            if observed != expected:
                raise SystemExit('ALERT_REPLAY_MISMATCH')
        if store.get_receipt(child_id) != receipt:
            raise SystemExit('ALERT_RECEIPT_REPLAY_MISMATCH')
    print(f'重开隔离库按件号复领：原件 {parent_id}、子件 {child_id} 回执请求数 {receipt.request_count}，'
          f'同批子件 {together_id}')


def main() -> None:
    sample = load_sample()
    names = sample['selection']
    with TemporaryDirectory(prefix='bench-handover-') as scratch:
        root = Path(scratch)
        source_path = root / 'source.sqlite'
        offline_path = root / 'offline.sqlite'
        with closing(sqlite3.connect(source_path)) as source:
            recordings, registry, index = RecordingCatalog(source), ViewRegistry(source), IssuedIndex(source)
            recordings.initialize()
            registry.initialize()
            index.initialize()
            recording = prepare_sample(recordings, registry, sample)
            source_values = [source_check(recordings, registry, recording, name).values[0] for name in names]
            issued = issue_package(recordings, registry, index, recording, names)
        source_path.rename(root / 'disconnected.sqlite')
        with closing(sqlite3.connect(offline_path)) as connection:
            store = RevisionStore(connection)
            store.initialize()
            parent_id = accept_package(store, issued.wire)
            parent = read_audit(store, parent_id)
            parent_values = [view.values[0] for view in parent.views]
            _scenario(
                'n4', {'selection': names, 'banks': sample['banks']},
                [513, 515, 513], source_values, [513, 515, 513], parent_values,
                ['audit/archive.py', 'handover/issue.py', 'offline/accept.py'],
                'Read 01 02 as little endian, 02 03 as big endian, and Q independently.',
            )
            child_id, receipt = correct_package(store, parent_id, [CorrectionRequest('A', 0, 1025)])
            child = read_audit(store, child_id)
            differences = compare_audits(store, parent_id, child_id)
            _scenario(
                'n6', {'view': 'A', 'index': 0, 'value': 1025},
                [1025, 1027, 513], [view.values[0] for view in child.views],
                {'deltas': [512, 512, 0], 'parent': [513, 515, 513]},
                {'deltas': [row.total_delta for row in differences],
                 'parent': [view.values[0] for view in read_audit(store, parent_id).views]},
                ['handover/project.py', 'offline/corrections.py', 'audit/compare.py'],
                'A encodes as 01 04. B reads 04 03 in big endian. Q byte 1 stays 02.',
            )
            batch = (CorrectionRequest('A', 0, 1025), CorrectionRequest('B', 0, 1283))
            before = _counts(connection)
            outcomes = []
            for order in (batch, batch[::-1]):
                try:
                    correct_package(store, parent_id, order)
                except ByteConflict:
                    outcomes.append('rejected')
                else:
                    outcomes.append('issued')
            after = _counts(connection)
            _scenario(
                'n7', {'batch': [request.__dict__ for request in batch], 'both_orders': True},
                ['rejected', 'rejected'], outcomes, [0, 0],
                [end - start for start, end in zip(before, after, strict=True)],
                ['offline/corrections.py', 'offline/settle.py', 'offline/revisions.py'],
                'The same P byte would need both 04 and 05. Neither order may commit.',
            )
        with closing(sqlite3.connect(offline_path)) as connection:
            store = RevisionStore(connection)
            store.initialize()
            if (read_audit(store, parent_id), read_audit(store, child_id), store.get_receipt(child_id)) != (
                parent, child, receipt,
            ):
                raise SystemExit('HANDOVER_REPLAY_MISMATCH')
            print(f'复领父件 {parent_id} 与子件 {child_id}，回执请求数 {receipt.request_count}')
        run_alert_demo(root)


if __name__ == '__main__':
    main()
