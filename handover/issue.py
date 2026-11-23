from collections.abc import Iterable
from uuid import uuid4

from capture.catalog import RecordingCatalog
from handover.alert import build_alert_evidence
from handover.format import PackageEnvelope, encode_package
from handover.issued_index import IssuedIndex, IssuedPackage
from handover.project import project_selected_bytes, project_with_positions
from handover.selection import resolve_selection
from views.integers import unsigned_limit
from views.registry import ViewRegistry


def issue_package(
    recordings: RecordingCatalog,
    registry: ViewRegistry,
    index: IssuedIndex,
    recording_id: str,
    names: Iterable[str],
) -> IssuedPackage:
    recording = recordings.get(recording_id)
    selection = resolve_selection(recording_id, registry.get_catalog(recording_id), names)
    previous = index.find_selection(selection)
    if previous is not None:
        return previous
    payload = project_selected_bytes(recording, selection)
    envelope = PackageEnvelope('pkg-' + uuid4().hex, recording_id, payload)
    return index.store(selection, IssuedPackage(envelope.package_id, encode_package(envelope)))


def issue_alert_package(
    recordings: RecordingCatalog,
    registry: ViewRegistry,
    index: IssuedIndex,
    recording_id: str,
    names: Iterable[str],
    observation_name: str,
    threshold: int,
) -> IssuedPackage:
    recording = recordings.get(recording_id)
    catalog = registry.get_catalog(recording_id)
    selection = resolve_selection(recording_id, catalog, names)
    by_name = {view.name: view for view in catalog}
    if not isinstance(observation_name, str) or not observation_name.strip():
        raise ValueError('observation name must be a nonempty string')
    try:
        observation = by_name[observation_name]
    except KeyError:
        raise KeyError(observation_name) from None
    if observation_name in selection.names:
        raise ValueError('observation view must be outside the edit selection')
    if type(threshold) is not int or not 0 <= threshold <= unsigned_limit(observation.width):
        raise ValueError('threshold must be an unsigned integer within the observation width')
    previous = index.find_alert(selection, observation_name, threshold)
    if previous is not None:
        return previous
    payload, positions = project_with_positions(recording, selection)
    evidence = build_alert_evidence(recording, observation, threshold, positions)
    envelope = PackageEnvelope(
        'pkg-' + uuid4().hex, recording_id, payload, wire_version=3, alert=evidence,
    )
    return index.store_alert(
        selection, observation_name, threshold,
        IssuedPackage(envelope.package_id, encode_package(envelope)),
    )
