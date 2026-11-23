from contextlib import closing
import json
from pathlib import Path
import sqlite3

from audit.archive import read_audit, source_check
from capture.catalog import RecordingCatalog
from demo import prepare_sample
from handover.format import decode_package
from handover.issue import issue_package
from handover.issued_index import IssuedIndex
from offline.accept import accept_package
from offline.corrections import CorrectionRequest
from offline.revisions import RevisionStore
from offline.settle import correct_package
from views.registry import ViewRegistry


def require_equal(actual, expected, context):
    if actual != expected:
        raise AssertionError(f"{context}: got {actual!r}, expected {expected!r}")


def check_case(case):
    label = case["recording"]
    with closing(sqlite3.connect(":memory:")) as source:
        recordings = RecordingCatalog(source)
        registry = ViewRegistry(source)
        index = IssuedIndex(source)
        for component in (recordings, registry, index):
            component.initialize()
        recording_id = prepare_sample(recordings, registry, case)
        values = source_check(recordings, registry, recording_id, case["observation_name"]).values
        require_equal(list(values), case["before_values"], label)
        issued = issue_package(recordings, registry, index, recording_id, case["selection"])
        selected = decode_package(issued.wire).payload.data.hex()
        require_equal(selected, case["selected_hex"], label)

    outcomes = []
    with closing(sqlite3.connect(":memory:")) as offline:
        store = RevisionStore(offline)
        store.initialize()
        parent = accept_package(store, issued.wire)
        initial = read_audit(store, parent)
        require_equal([view.name for view in initial.views], case["selection"], label)
        for trial in case["trials"]:
            requests = [CorrectionRequest(*request) for request in trial["requests"]]
            child, receipt = correct_package(store, parent, requests)
            audit = read_audit(store, child)
            require_equal(audit.parent_id, parent, label)
            require_equal(store.get_receipt(child), receipt, label)
            by_name = {view.name: view.values for view in audit.views}
            for request in requests:
                require_equal(by_name[request.view_name][request.element_index], request.value, label)
            require_equal(read_audit(store, parent), initial, label)
            outcomes.append([list(view.values) for view in audit.views])
    print(f"{label}: source={list(values)} selected={selected} offline_edits={outcomes}")


def main():
    path = Path(__file__).resolve().parent / "examples" / "first_alert.json"
    cases = json.loads(path.read_text(encoding="utf-8"))
    if not cases:
        raise ValueError("expected alert fixture cases")
    for case in cases:
        check_case(case)


if __name__ == "__main__":
    main()
