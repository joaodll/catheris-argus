"""A report's filters as stored (jsonb) and as the findings iterator reads them. The API validates
what it stores; reading back refuses anything else, and the report's kind, not its filters,
decides which tools it covers."""

from dataclasses import asdict, fields
from datetime import date
from typing import Any

from argus.findings import MISCONFIGURATION_TOOLS, VULNERABILITY_TOOL, FindingFilters
from argus.reports.model import ReportKind

_TUPLES = {f.name for f in fields(FindingFilters) if isinstance(f.default, tuple)}
_DATES = {"first_seen_from", "first_seen_to"}
_NAMES = {f.name for f in fields(FindingFilters)}
# Fields a stored report never takes from its filters: the scope is the row's own resolved
# list, and the tools come from the kind.
_SET_BY_THE_REPORT = {"connection_ids", "tools"}

KIND_TOOLS: dict[str, tuple[str, ...]] = {
    "misconfigurations": MISCONFIGURATION_TOOLS,
    "vulnerabilities": (VULNERABILITY_TOOL,),
}


def to_json(filters: FindingFilters) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in asdict(filters).items():
        if isinstance(value, tuple):
            out[name] = list(value)
        elif isinstance(value, date):
            out[name] = value.isoformat()
        else:
            out[name] = value
    return out


def from_json(
    kind: ReportKind, stored: dict[str, Any], *, connection_ids: list[int]
) -> FindingFilters:
    """The filters a build runs: the stored ones, over the row's scope, with the kind's tools
    (narrowed by a stored tool filter, never widened)."""
    unknown = set(stored) - _NAMES
    if unknown:
        raise ValueError(f"unknown report filters: {sorted(unknown)}")
    values: dict[str, Any] = {}
    for name, value in stored.items():
        if name in _SET_BY_THE_REPORT:
            continue
        if name in _TUPLES:
            values[name] = tuple(value or ())
        elif name in _DATES:
            values[name] = date.fromisoformat(value) if value else None
        else:
            values[name] = value
    allowed = KIND_TOOLS[kind]
    asked = tuple(t for t in stored.get("tools") or () if t in allowed)
    return FindingFilters(**values, connection_ids=tuple(connection_ids), tools=asked or allowed)
