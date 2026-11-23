"""First-alert linkage verification.

Covers the fallback divergence and reverse overlap fixtures, invalid thresholds
and evidence rejection, failed commits, and old-format read-back.  Returns zero
only when every check holds.
"""

from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory

from audit.archive import read_first_alert
from capture.catalog import RecordingCatalog
from demo import prepare_sample
from handover.format import decode_package
from handover.issue import issue_alert_package, issue_package
from handover.issued_index import IssuedIndex
from offline.accept import accept_package
from offline.corrections import CorrectionRequest
from offline.revisions import RevisionStore
from offline.settle import correct_package
from tests.test_replay import LEGACY_WIRE
from views.registry import ViewRegistry


def _cases() -> list[dict]:
    path = Path(__file__).resolve().parent / 'examples' / 'first_alert.json'
    return json.loads(path.read_text(encoding='utf-8'))


def _expect(actual, expected, context: str) -> None:
    if actual != expected:
        raise AssertionError(f'{context}: got {actual!r}, expected {expected!r}')


class _Source:
    def __init__(self, root: Path):
        self.connection = sqlite3.connect(root / 'source.sqlite')
        self.recordings = RecordingCatalog(self.connection)
        self.registry = ViewRegistry(self.connection)
        self.index = IssuedIndex(self.connection)
        for component in (self.recordings, self.registry, self.index):
            component.initialize()

    def close(self, root: Path) -> None:
        self.connection.close()
        (root / 'source.sqlite').rename(root / 'disconnected-source.sqlite')


class _Offline:
    def __init__(self, root: Path):
        self.path = root / 'offline.sqlite'
        self.open()

    def open(self) -> None:
        self.connection = sqlite3.connect(self.path)
        self.store = RevisionStore(self.connection)
        self.store.initialize()

    def reopen(self) -> None:
        self.connection.close()
        self.open()


def check_fixtures(root: Path) -> None:
    for case in _cases():
        label = case['recording']
        source = _Source(root)
        recording_id = prepare_sample(source.recordings, source.registry, case)
        issued = issue_alert_package(
            source.recordings, source.registry, source.index, recording_id,
            case['selection'], case['observation_name'], case['threshold'],
        )
        replay = issue_alert_package(
            source.recordings, source.registry, source.index, recording_id,
            case['selection'], case['observation_name'], case['threshold'],
        )
        _expect(replay, issued, f'{label} replay identity')
        _expect(decode_package(issued.wire).payload.data.hex(), case['selected_hex'], f'{label} payload')
        source.close(root)

        offline = _Offline(root)
        parent = accept_package(offline.store, issued.wire)
        initial = (case['observation_name'], case['threshold'], case['before_alarm'])
        _expect(read_first_alert(offline.store, parent), initial, f'{label} parent alert')
        children = []
        for number, trial in enumerate(case['trials']):
            child, receipt = correct_package(
                offline.store, parent,
                [CorrectionRequest(*request) for request in trial['requests']],
            )
            _expect(read_first_alert(offline.store, child)[2], trial['after_alarm'], f'{label} trial {number}')
            _expect(offline.store.get_receipt(child), receipt, f'{label} receipt {number}')
            children.append((child, trial['after_alarm'], receipt))
        _expect(read_first_alert(offline.store, parent), initial, f'{label} parent preserved')

        offline.reopen()
        for child, alarm, receipt in children:
            _expect(read_first_alert(offline.store, child)[2], alarm, f'{label} child reopen {child}')
            _expect(offline.store.get_receipt(child), receipt, f'{label} receipt reopen {child}')
        offline.connection.close()
        print(f'{label}: source={case["before_values"]} selected={case["selected_hex"]} '
              f'parent={case["before_alarm"]} children={[alarm for _, alarm, _ in children]}')


def _resign(wire: dict) -> bytes:
    signed = {key: wire[key] for key in ('version', 'body')}
    wire['sha256'] = sha256(
        json.dumps(signed, sort_keys=True, separators=(',', ':')).encode('ascii')
    ).hexdigest()
    return json.dumps(wire, sort_keys=True, separators=(',', ':')).encode('ascii')


def check_rejections(root: Path) -> None:
    case = _cases()[0]
    source = _Source(root)
    recording_id = prepare_sample(source.recordings, source.registry, case)
    for names, observation, threshold in (
        (case['selection'], case['observation_name'], True),
        (case['selection'], case['observation_name'], -1),
        (case['selection'], case['observation_name'], 1 << 40),
        (case['selection'], 'A', case['threshold']),
        ((), case['observation_name'], case['threshold']),
        (('A', 'A'), case['observation_name'], case['threshold']),
    ):
        try:
            issue_alert_package(
                source.recordings, source.registry, source.index,
                recording_id, names, observation, threshold,
            )
        except ValueError:
            continue
        raise AssertionError(f'invalid alert issue was accepted: {names!r} {observation!r} {threshold!r}')
    try:
        issue_alert_package(
            source.recordings, source.registry, source.index,
            recording_id, case['selection'], 'MISSING', case['threshold'],
        )
    except KeyError:
        pass
    else:
        raise AssertionError('unknown observation view was accepted')
    _expect(
        source.connection.execute('SELECT count(*) FROM issued_alert_packages').fetchone()[0],
        0, 'invalid issues must not publish',
    )
    issued = issue_alert_package(
        source.recordings, source.registry, source.index, recording_id,
        case['selection'], case['observation_name'], case['threshold'],
    )
    plain = issue_package(
        source.recordings, source.registry, source.index, recording_id, case['selection'],
    )
    source.close(root)

    tampered = json.loads(issued.wire)
    tampered['body']['alert']['elements'][0]['refs'][0] = 99
    bad_ref_wire = _resign(tampered)
    bad_observation = json.loads(issued.wire)
    bad_observation['body']['alert']['observation'] = 'A'
    bad_observation_wire = _resign(bad_observation)

    offline = _Offline(root)
    for label, wire in (('tampered reference', bad_ref_wire), ('selection observation', bad_observation_wire)):
        try:
            accept_package(offline.store, wire)
        except ValueError:
            continue
        raise AssertionError(f'{label} was accepted')
    _expect(offline.connection.execute('SELECT count(*) FROM revisions').fetchone()[0], 0,
            'no record after bad package')

    parent = accept_package(offline.store, issued.wire)
    before = offline.connection.execute('SELECT count(*) FROM revisions').fetchone()[0]

    def refuse():
        raise OSError('linkage commit refused')

    try:
        correct_package(offline.store, parent, [CorrectionRequest('A', 0, 0)], before_commit=refuse)
    except OSError:
        pass
    else:
        raise AssertionError('failed commit was reported as success')
    _expect(offline.connection.execute('SELECT count(*) FROM revisions').fetchone()[0], before,
            'no child after failed commit')
    _expect(read_first_alert(offline.store, parent)[2], case['before_alarm'], 'parent alert after failed commit')

    accept_package(offline.store, LEGACY_WIRE)
    plain_parent = accept_package(offline.store, plain.wire)
    for package_id in ('bench-legacy-001', plain_parent):
        try:
            read_first_alert(offline.store, package_id)
        except ValueError:
            continue
        raise AssertionError(f'old package {package_id!r} reported a first alert')
    try:
        read_first_alert(offline.store, 'missing-package')
    except KeyError:
        pass
    else:
        raise AssertionError('unknown package reported a first alert')

    offline.reopen()
    _expect(read_first_alert(offline.store, parent)[2], case['before_alarm'], 'alert after reopen')
    print('rejections: invalid thresholds, tampered evidence, failed commit, old read-back all refused')


def main() -> int:
    try:
        with TemporaryDirectory(prefix='alert-linkage-') as scratch:
            root = Path(scratch)
            fixtures = root / 'fixtures'
            fixtures.mkdir()
            check_fixtures(fixtures)
            rejections = root / 'rejections'
            rejections.mkdir()
            check_rejections(rejections)
    except AssertionError as error:
        print(f'ALERT_LINKAGE_FAIL {error}')
        return 1
    print('ALERT_LINKAGE_PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
