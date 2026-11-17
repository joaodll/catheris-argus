"""A report's filters as stored (jsonb) and as the build reads them. The API validates what it
stores; reading back refuses anything else. A Misconfigurations or Vulnerabilities report runs
findings.FindingFilters, and its kind, not its filters, decides which tools it covers; a
Resources report runs findings.ResourceListFilters (the Resources list's own)."""

from dataclasses import asdict, fields
from datetime import date
from typing import Any

from argus.findings import (
    MISCONFIGURATION_TOOLS,
    VULNERABILITY_TOOL,
    FindingFilters,
    ResourceListFilters,
)
from argus.reports.model import ReportKind

ReportFilters = FindingFilters | ResourceListFilters

# Stored as ISO days: every day bound of either filter set (first seen, removed).
_DATES = {"first_seen_from", "first_seen_to", "deleted_from", "deleted_to"}
# Fields a stored report never takes from its filters: the scope is the row's own resolved
# list, and the tools come from the kind.
_SET_BY_THE_REPORT = {"connection_ids", "tools"}

# The tools whose data a report covers: its findings' tools, or the inventory's for Resources
# (its data-through day).
KIND_TOOLS: dict[str, tuple[str, ...]] = {
    "misconfigurations": MISCONFIGURATION_TOOLS,
    "vulnerabilities": (VULNERABILITY_TOOL,),
    "resources": ("steampipe",),
}


def to_json(filters: ReportFilters) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in asdict(filters).items():
        if isinstance(value, tuple):
            out[name] = list(value)
        elif isinstance(value, date):
            out[name] = value.isoformat()
        else:
            out[name] = value
    return out


def _tags(stored: Any) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Stored tags, [[name, [values]], ...], back to FindingFilters.tags; any other shape is
    refused, as an unknown filter is."""
    out: list[tuple[str, tuple[str, ...]]] = []
    for item in stored or ():
        match item:
            case [str() as key, list() as values] if all(isinstance(v, str) for v in values):
                out.append((key, tuple(values)))
            case _:
                raise ValueError("malformed report tag filter")
    return tuple(out)


def _values(cls: type[ReportFilters], stored: dict[str, Any]) -> dict[str, Any]:
    """The stored filters as `cls`'s field values, the report's own fields left out. An unknown
    filter is refused."""
    known = {f.name: f for f in fields(cls)}
    unknown = set(stored) - set(known)
    if unknown:
        raise ValueError(f"unknown report filters: {sorted(unknown)}")
    values: dict[str, Any] = {}
    for name, value in stored.items():
        if name in _SET_BY_THE_REPORT:
            continue
        default = known[name].default
        if name == "tags":
            values[name] = _tags(value)
        elif isinstance(default, tuple):
            values[name] = tuple(value or ())
        elif name in _DATES:
            values[name] = date.fromisoformat(value) if value else None
        else:
            values[name] = value
    return values


def from_json(
    kind: ReportKind, stored: dict[str, Any], *, connection_ids: list[int]
) -> ReportFilters:
    """The filters a build runs: the stored ones over the row's scope. A findings kind gets its
    tools (narrowed by a stored tool filter, never widened)."""
    if kind == "resources":
        return ResourceListFilters(
            **_values(ResourceListFilters, stored), connection_ids=tuple(connection_ids)
        )
    values = _values(FindingFilters, stored)
    allowed = KIND_TOOLS[kind]
    asked = tuple(t for t in stored.get("tools") or () if t in allowed)
    return FindingFilters(**values, connection_ids=tuple(connection_ids), tools=asked or allowed)
