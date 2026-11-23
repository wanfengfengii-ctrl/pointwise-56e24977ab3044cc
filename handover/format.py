import base64
from dataclasses import dataclass
from hashlib import sha256
import json

from handover.alert import (
    AlertElement,
    AlertEvidence,
    validate_alert_evidence,
)
from handover.payload import SelectedPayload, ViewByteReferences, validate_payload_references
from views.integers import validate_integer_format


@dataclass(frozen=True)
class PackageEnvelope:
    package_id: str
    recording_id: str
    payload: SelectedPayload
    wire_version: int = 2
    alert: AlertEvidence | None = None


def _json_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _object(value, fields: set[str]) -> dict:
    if not isinstance(value, dict) or value.keys() != fields:
        raise ValueError('invalid package object fields')
    return value


def _unique_object(pairs) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate package field {key!r}')
        result[key] = value
    return result


def _identifier(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('package and recording identifiers must be nonempty strings')
    value.encode('utf-8')
    return value


def _binary(value) -> bytes:
    if not isinstance(value, str):
        raise ValueError('package data must be base64 text')
    return base64.b64decode(value, validate=True)


def _encode_views(payload: SelectedPayload, version: int) -> list[dict]:
    result = []
    if version == 1:
        slots = sum(len(view.elements) * view.width for view in payload.views)
        if slots != len(payload.data):
            raise ValueError('wire version 1 cannot represent shared references')
    for view in payload.views:
        fields = {'name': view.name, 'width': view.width, 'byteorder': view.byteorder}
        if version == 1:
            view_bytes = bytes(payload.data[ref] for element in view.elements for ref in element)
            fields['data'] = base64.b64encode(view_bytes).decode('ascii')
        else:
            fields['elements'] = view.elements
        result.append(fields)
    return result


def _encode_alert(evidence: AlertEvidence) -> dict:
    return {
        'observation': evidence.observation_name,
        'threshold': evidence.threshold,
        'width': evidence.width,
        'byteorder': evidence.byteorder,
        'elements': [
            {'refs': list(element.refs), 'limit': element.limit}
            for element in evidence.elements
        ],
    }


def encode_package(package: PackageEnvelope) -> bytes:
    version = package.wire_version
    if type(version) is not int or version not in (1, 2, 3):
        raise ValueError('unsupported package version')
    validate_payload_references(package.payload)
    if version == 3:
        if package.alert is None:
            raise ValueError('an alert package requires first-alert evidence')
        validate_alert_evidence(
            package.alert, package.payload,
            tuple(view.name for view in package.payload.views),
        )
    elif package.alert is not None:
        raise ValueError('first-alert evidence requires wire version 3')
    body = {
        'id': _identifier(package.package_id),
        'recording': _identifier(package.recording_id),
        'views': _encode_views(package.payload, version),
    }
    if version != 1:
        body['data'] = base64.b64encode(package.payload.data).decode('ascii')
    if version == 3:
        body['alert'] = _encode_alert(package.alert)
    signed = {'version': version, 'body': body}
    return _json_bytes({**signed, 'sha256': sha256(_json_bytes(signed)).hexdigest()})


def _read_inline_views(items: list) -> SelectedPayload:
    data = bytearray()
    references = []
    for item in items:
        _object(item, {'name', 'width', 'byteorder', 'data'})
        width, byteorder = item['width'], item['byteorder']
        validate_integer_format(width, byteorder)
        raw = _binary(item['data'])
        if not raw or len(raw) % width:
            raise ValueError('legacy view data does not hold whole elements')
        start = len(data)
        elements = tuple(
            tuple(range(offset, offset + width))
            for offset in range(start, start + len(raw), width)
        )
        data.extend(raw)
        references.append(ViewByteReferences(item['name'], width, byteorder, elements))
    return SelectedPayload(bytes(data), tuple(references))


def _read_referenced_views(items: list, data: bytes) -> SelectedPayload:
    references = []
    for item in items:
        _object(item, {'name', 'width', 'byteorder', 'elements'})
        elements = item['elements']
        if not isinstance(elements, list) or any(not isinstance(element, list) for element in elements):
            raise ValueError('package element references must be arrays')
        references.append(ViewByteReferences(
            item['name'], item['width'], item['byteorder'],
            tuple(tuple(element) for element in elements),
        ))
    return SelectedPayload(data, tuple(references))


def _read_alert(value) -> AlertEvidence:
    value = _object(value, {'observation', 'threshold', 'width', 'byteorder', 'elements'})
    name = value['observation']
    if not isinstance(name, str):
        raise ValueError('first-alert observation must be text')
    width, byteorder = value['width'], value['byteorder']
    validate_integer_format(width, byteorder)
    raw_elements = value['elements']
    if not isinstance(raw_elements, list) or not raw_elements:
        raise ValueError('first-alert evidence must contain observation elements')
    elements = []
    for item in raw_elements:
        item = _object(item, {'refs', 'limit'})
        refs = item['refs']
        if not isinstance(refs, list) or len(refs) != width:
            raise ValueError('observation element reference count differs from width')
        elements.append(AlertElement(tuple(refs), item['limit']))
    return AlertEvidence(name, value['threshold'], width, byteorder, tuple(elements))


def decode_package(wire: bytes) -> PackageEnvelope:
    if not isinstance(wire, bytes):
        raise ValueError('package must be supplied as complete bytes')
    try:
        outer = _object(json.loads(wire.decode('utf-8'), object_pairs_hook=_unique_object),
                        {'version', 'body', 'sha256'})
        version = outer['version']
        if type(version) is not int or version not in (1, 2, 3):
            raise ValueError('unsupported package version')
        fields = {'id', 'recording', 'views'}
        if version != 1:
            fields.add('data')
        if version == 3:
            fields.add('alert')
        body = _object(outer['body'], fields)
        signed = {'version': version, 'body': body}
        if sha256(_json_bytes(signed)).hexdigest() != outer['sha256']:
            raise ValueError('package checksum mismatch')
        items = body['views']
        if not isinstance(items, list):
            raise ValueError('package views must be an ordered array')
        if version == 1:
            payload = _read_inline_views(items)
        else:
            payload = _read_referenced_views(items, _binary(body['data']))
        validate_payload_references(payload)
        alert = None
        if version == 3:
            alert = _read_alert(body['alert'])
            validate_alert_evidence(
                alert, payload, tuple(view.name for view in payload.views),
            )
        return PackageEnvelope(
            _identifier(body['id']), _identifier(body['recording']), payload, version, alert,
        )
    except RecursionError as error:
        raise ValueError('package nesting is too deep') from error
