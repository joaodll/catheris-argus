"""A report's filters as stored (jsonb) and as the build reads them. The API validates what it
stores; reading back refuses anything else. A Misconfigurations or Vulnerabilities report runs
findings.FindingFilters, and its kind, not its filters, decides which tools it covers; a
Resources report runs findings.ResourceListFilters (the Resources list's own); a by-resource
report runs ResourceProblemFilters (the Resources list's, then its problems' severities and
tags)."""

from dataclasses import asdict, dataclass, field, fields
from datetime import date
from typing import Any

from argus.findings import (
    MISCONFIGURATION_TOOLS,
    VULNERABILITY_TOOL,
    FindingFilters,
    ResourceListFilters,
)
from argus.reports.model import ReportKind


@dataclass(frozen=True)
class ResourceProblemFilters:
    """A by-resource report's filters (ADR-0047 section 3d): the Resources list's, which choose
    the resources, then the severities and tags of the problems kept. Stored flat: the list's
    fields beside `severities` and `tags`."""

    resources: ResourceListFilters = field(default_factory=ResourceListFilters)
    severities: tuple[str, ...] = ()
    tags: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # One resource, from its sheet: the list's filters then only bound its accounts.
    resource_id: int | None = None

    @property
    def connection_ids(self) -> tuple[int, ...]:
        """The accounts asked for: the Resources list's own."""
        return self.resources.connection_ids


ReportFilters = FindingFilters | ResourceListFilters | ResourceProblemFilters

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
    "resource-problems": (*MISCONFIGURATION_TOOLS, VULNERABILITY_TOOL),
}
# The fields a by-resource report adds to the Resources list's.
_PROBLEM_FIELDS = {"severities", "tags", "resource_id"}


def to_json(filters: ReportFilters) -> dict[str, Any]:
    if isinstance(filters, ResourceProblemFilters):
        flat = to_json(filters.resources)
        flat["severities"] = list(filters.severities)
        flat["tags"] = [[key, list(values)] for key, values in filters.tags]
        flat["resource_id"] = filters.resource_id
        return flat
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


def _resource_id(stored: Any) -> int | None:
    if stored is None or (isinstance(stored, int) and not isinstance(stored, bool) and stored > 0):
        return stored
    raise ValueError("malformed report resource filter")


def _values(
    cls: type[FindingFilters] | type[ResourceListFilters], stored: dict[str, Any]
) -> dict[str, Any]:
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
    if kind == "resource-problems":
        rest = {k: v for k, v in stored.items() if k not in _PROBLEM_FIELDS}
        severities = stored.get("severities") or ()
        if not all(isinstance(s, str) for s in severities):
            raise ValueError("malformed report severity filter")
        return ResourceProblemFilters(
            resources=ResourceListFilters(
                **_values(ResourceListFilters, rest), connection_ids=tuple(connection_ids)
            ),
            severities=tuple(severities),
            tags=_tags(stored.get("tags")),
            resource_id=_resource_id(stored.get("resource_id")),
        )
    values = _values(FindingFilters, stored)
    allowed = KIND_TOOLS[kind]
    asked = tuple(t for t in stored.get("tools") or () if t in allowed)
    return FindingFilters(**values, connection_ids=tuple(connection_ids), tools=asked or allowed)
