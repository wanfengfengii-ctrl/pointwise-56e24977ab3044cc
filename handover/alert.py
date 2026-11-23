"""First-alert evidence carried with an alert handover package.

The evidence never contains an unselected source byte.  For every observation
element it keeps, in address order, a reference into the delivered payload when
that physical byte is part of the edit selection, and ``None`` when the byte
stays at the station.  The undelivered contribution of an element is folded
into the ``limit`` of that element, so the night shift can settle the alert
from the received package and its local corrections alone.

For an element the decoded known contribution is

    sum(payload_byte * place_value for delivered positions)

and the element reaches the threshold exactly when that value is greater than or
equal to ``limit``.  A limit of zero is an element that always reaches the
threshold; ``known_maximum + 1`` is an element that never reaches it.
"""

from dataclasses import dataclass

from capture.banks import read_bank
from capture.catalog import StoredRecording
from handover.payload import SelectedPayload
from views.coordinates import SourceBytePosition, iter_element_positions
from views.integers import unsigned_limit, validate_integer_format
from views.layout import ViewLayout


@dataclass(frozen=True)
class AlertElement:
    refs: tuple[int | None, ...]
    limit: int


@dataclass(frozen=True)
class AlertEvidence:
    observation_name: str
    threshold: int
    width: int
    byteorder: str
    elements: tuple[AlertElement, ...]


def place_values(width: int, byteorder: str) -> tuple[int, ...]:
    """Return the positional value of each address-ordered byte of an element."""
    validate_integer_format(width, byteorder)
    if byteorder == 'little':
        return tuple(256 ** index for index in range(width))
    return tuple(256 ** (width - 1 - index) for index in range(width))


def build_alert_evidence(
    recording: StoredRecording,
    layout: ViewLayout,
    threshold: int,
    positions: dict[SourceBytePosition, int],
) -> AlertEvidence:
    bank = read_bank(recording.banks, layout.bank_name)
    weights = place_values(layout.width, layout.byteorder)
    elements = []
    for original_positions in iter_element_positions(layout):
        refs: list[int | None] = []
        undelivered = 0
        known_maximum = 0
        for weight, position in zip(weights, original_positions, strict=True):
            ref = positions.get(position)
            refs.append(ref)
            if ref is None:
                undelivered += bank[position.offset] * weight
            else:
                known_maximum += 255 * weight
        limit = threshold - undelivered
        if limit < 0:
            limit = 0
        elif limit > known_maximum:
            limit = known_maximum + 1
        elements.append(AlertElement(tuple(refs), limit))
    return AlertEvidence(layout.name, threshold, layout.width, layout.byteorder, tuple(elements))


def element_value(payload: SelectedPayload, evidence: AlertEvidence, element: AlertElement) -> int:
    raw = bytes(
        payload.data[ref] if ref is not None else 0
        for ref in element.refs
    )
    return int.from_bytes(raw, evidence.byteorder, signed=False)


def first_alert_index(payload: SelectedPayload, evidence: AlertEvidence) -> int | None:
    for index, element in enumerate(evidence.elements):
        if element_value(payload, evidence, element) >= element.limit:
            return index
    return None


def validate_alert_evidence(
    evidence: AlertEvidence,
    payload: SelectedPayload,
    selection_names: tuple[str, ...],
) -> None:
    if not isinstance(evidence, AlertEvidence):
        raise ValueError('invalid first-alert evidence')
    name = evidence.observation_name
    if not isinstance(name, str) or not name.strip():
        raise ValueError('observation name must be a nonempty string')
    name.encode('utf-8')
    if name in selection_names:
        raise ValueError('observation view must be outside the edit selection')
    validate_integer_format(evidence.width, evidence.byteorder)
    if type(evidence.threshold) is not int:
        raise ValueError('threshold must be an integer')
    if not 0 <= evidence.threshold <= unsigned_limit(evidence.width):
        raise ValueError('threshold is outside the observation width')
    if not isinstance(evidence.elements, tuple) or not evidence.elements:
        raise ValueError('first-alert evidence must contain observation elements')
    width = evidence.width
    bound = 1 << (8 * width)
    for element in evidence.elements:
        if not isinstance(element, AlertElement):
            raise ValueError('invalid observation element evidence')
        refs = element.refs
        if not isinstance(refs, tuple) or len(refs) != width:
            raise ValueError('observation element reference count differs from width')
        delivered = [ref for ref in refs if ref is not None]
        for ref in refs:
            if ref is None:
                continue
            if type(ref) is not int or not 0 <= ref < len(payload.data):
                raise ValueError('observation reference outside selected payload')
        if len(set(delivered)) != len(delivered):
            raise ValueError('an observation element must address distinct payload bytes')
        if type(element.limit) is not int or not 0 <= element.limit <= bound:
            raise ValueError('observation element limit is outside its value domain')
