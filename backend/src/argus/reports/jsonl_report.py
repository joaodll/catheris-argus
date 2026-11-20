"""A Resources report as JSON Lines (ADR-0047 section 3c): one resource per line, the CSV's
fields plus its links and its configuration, as its panel shows them. gzip-compressed: a
resource's configuration is long, and a whole estate's is the point.

A line holds the CSV's columns under the same names (resources_columns tells them), as JSON
values: a number is a number, a day an ISO date, and a cell the CSV leaves empty is null. Then:
- `included`: "matched" (the filters chose it) or "linked" (one link away from a matched
  resource, in the report's accounts, and left out by the filters);
- `links`: its links, each with its direction, its other end and how the link was found;
- `config`: the configuration stored at ingest (redacted there, ADR core.redaction), or null when
  the resource is not in its account's standing inventory.

JSON escapes what a reader would take for markup; nothing here is guarded as a CSV cell is,
because no spreadsheet reads it."""

import gzip
import json
from datetime import date, datetime
from typing import IO, Any

from argus.findings import VulnerabilitySummary
from argus.inventory import RoleLastUsed

Row = dict[str, Any]
INCLUDED = ("matched", "linked")


def _plain(value: Any) -> Any:
    if isinstance(value, datetime | date):
        return value.isoformat()
    raise TypeError(f"not JSON: {type(value).__name__}")


def _role(row: Row, name: str) -> Any:
    used: RoleLastUsed | None = row.get("role_last_used")
    return getattr(used, name) if used else None


def _cve(row: Row, name: str) -> int | None:
    cell: VulnerabilitySummary | None = row.get("vulnerabilities")
    return getattr(cell, name) if cell else None


def resource_fields(row: Row) -> dict[str, Any]:
    """The CSV's Resources columns (csv_report.COLUMNS["resources"]) as JSON values."""
    return {
        "account_id": row.get("account_id") or None,
        "account": row.get("connection") or None,
        "region": row.get("region"),
        "resource_type": row.get("type"),
        "resource_name": row.get("name"),
        "native_id": row.get("native_id"),
        "resource_uid": row.get("resource_uid"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "removed_on": row.get("deleted_on"),
        "open_misconfigurations": row.get("open_misconfigurations"),
        "worst_severity": row.get("worst_severity"),
        "open_vulnerabilities": _cve(row, "open"),
        "exploitable_vulnerabilities": _cve(row, "exploitable"),
        "last_used": _role(row, "last_used_at"),
        "last_used_region": _role(row, "last_used_region"),
        "last_used_read_on": _role(row, "observed_on"),
        "role_created": _role(row, "created_at"),
        "workloads": row.get("workloads"),
    }


def link(edge: Row, resource_id: int, ends: dict[int, Row]) -> dict[str, Any]:
    """One of a resource's links as its panel lists it: which way it points, the other end (with
    its name, type and account when that end is in the inventory) and how it was found."""
    outgoing = edge["source_resource_id"] == resource_id
    other_id = edge["target_resource_id"] if outgoing else edge["source_resource_id"]
    other = ends.get(other_id) if other_id is not None else None
    return {
        "type": edge["type"],
        "direction": "out" if outgoing else "in",
        "other_uid": edge["target_uid"] if outgoing else edge["source_uid"],
        "other_name": other["name"] if other else None,
        "other_type": other["type"] if other else None,
        "other_account_id": other["account_id"] if other else None,
        "origin": edge["origin"],
        "layer": edge["layer"],
        "attributes": edge["attributes"] or {},
        "first_seen": edge["first_seen"],
        "last_seen": edge["last_seen"],
    }


class JsonlReport:
    """Writes one Resources report's lines to an open binary file, gzip-compressed. Reproducible
    bytes: no name and no time in the gzip header."""

    def __init__(self, out: IO[bytes]) -> None:
        self._zipped = gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0)

    def write(
        self,
        row: Row,
        *,
        included: str,
        links: list[dict[str, Any]],
        config: Any,
    ) -> None:
        if included not in INCLUDED:
            raise ValueError(included)
        line = {"included": included, **resource_fields(row), "links": links, "config": config}
        text = json.dumps(line, default=_plain, ensure_ascii=False, separators=(",", ":"))
        self._zipped.write(text.encode() + b"\n")

    def close(self) -> None:
        self._zipped.close()
