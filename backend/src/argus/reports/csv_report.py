"""The CSV of a report (ADR-0047): fixed columns per kind, UTF-8 with a byte-order mark so
spreadsheets read it as UTF-8, and a guard against formulas.

A cell a spreadsheet would read as a formula (it starts with = + - @, a tab or a carriage
return) gets a leading apostrophe. Resource names, tags and titles come from scanned clouds and
are not ours to trust. Numbers are written as numbers and never guarded: a negative number is
not a formula."""

import csv
from collections.abc import Callable
from datetime import date, datetime
from typing import Any, TextIO

from argus.findings import VulnerabilityFacts, VulnerabilitySummary
from argus.inventory import RoleLastUsed
from argus.reports.model import ReportKind

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

Row = dict[str, Any]


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, list | tuple):
        value = "; ".join(str(v) for v in value)
    out = str(value)
    return f"'{out}" if out.startswith(_FORMULA_START) else out


def _number(value: Any) -> str:
    return "" if value is None else repr(float(value)) if isinstance(value, float) else str(value)


def _field(name: str) -> Callable[[Row], str]:
    return lambda row: _text(row.get(name))


def _fact(name: str, *, number: bool = False) -> Callable[[Row], str]:
    def get(row: Row) -> str:
        facts: VulnerabilityFacts | None = row.get("vulnerability")
        value = getattr(facts, name) if facts else None
        return _number(value) if number else _text(value)

    return get


_COMMON_HEAD: list[tuple[str, Callable[[Row], str]]] = [
    ("account_id", _field("account_id")),
    ("account", _field("connection")),
    ("region", _field("region")),
]
_RESOURCE: list[tuple[str, Callable[[Row], str]]] = [
    ("resource_type", _field("resource_type")),
    ("resource_uid", _field("resource_uid")),
    ("resource_name", _field("resource_name")),
]
_DATES: list[tuple[str, Callable[[Row], str]]] = [
    ("state", _field("state")),
    ("muted", _field("muted")),
    ("first_seen", _field("first_seen")),
    ("last_seen", _field("last_seen")),
]


def _cve(name: str) -> Callable[[Row], str]:
    """The Vulnerabilities cell's count; empty when no scanner covers the resource ("not
    covered", never a zero)."""

    def get(row: Row) -> str:
        cell: VulnerabilitySummary | None = row.get("vulnerabilities")
        return _number(getattr(cell, name)) if cell else ""

    return get


def _role(name: str) -> Callable[[Row], str]:
    """A role's last use as AWS records it, and its creation; empty on any other type, or before
    it was read. An empty last_used with a last_used_read_on is AWS saying no use in its tracking
    window: since role_created, when that is inside the window."""

    def get(row: Row) -> str:
        used: RoleLastUsed | None = row.get("role_last_used")
        return _text(getattr(used, name)) if used else ""

    return get


COLUMNS: dict[str, list[tuple[str, Callable[[Row], str]]]] = {
    "misconfigurations": [
        *_COMMON_HEAD,
        ("service", _field("service")),
        *_RESOURCE,
        ("tool", _field("tool")),
        ("check_id", _field("check_id")),
        ("title", _field("title")),
        ("result", _field("detail")),
        ("severity", _field("severity")),
        ("status", _field("status")),
        *_DATES,
        ("reach", _field("reach")),
        ("remediation", _field("remediation_text")),
        ("remediation_url", _field("remediation_url")),
    ],
    "vulnerabilities": [
        *_COMMON_HEAD,
        *_RESOURCE,
        ("vulnerability_id", _fact("vulnerability_id")),
        ("title", _field("title")),
        ("severity", _field("severity")),
        ("cvss", _fact("cvss_score", number=True)),
        ("epss", _fact("epss_score", number=True)),
        ("exploit_available", _fact("exploit_available")),
        ("package", _fact("package_name")),
        ("installed_version", _fact("installed_version")),
        ("fixed_version", _fact("fixed_version")),
        ("fix_available", _fact("fix_available")),
        *_DATES,
        ("scanner", _fact("scanner")),
    ],
    # One row per problem, by resource (ADR-0047 section 3d). The resource's columns come from
    # the inventory; a CVE's columns are empty on a misconfiguration's row, and its result on a
    # CVE's.
    "resource-problems": [
        *_COMMON_HEAD,
        *_RESOURCE,
        ("source", _field("source")),
        ("severity", _field("severity")),
        ("tool", _field("tool")),
        ("check_id", _field("check_id")),
        ("title", _field("title")),
        (
            "result",
            lambda row: _text(row.get("detail")) if row.get("source") != "vulnerability" else "",
        ),
        ("vulnerability_id", _fact("vulnerability_id")),
        ("cvss", _fact("cvss_score", number=True)),
        ("epss", _fact("epss_score", number=True)),
        ("exploit_available", _fact("exploit_available")),
        ("package", _fact("package_name")),
        ("installed_version", _fact("installed_version")),
        ("fixed_version", _fact("fixed_version")),
        ("fix_available", _fact("fix_available")),
        *_DATES,
        ("remediation", _field("remediation_text")),
        ("remediation_url", _field("remediation_url")),
    ],
    "resources": [
        *_COMMON_HEAD,
        ("resource_type", _field("type")),
        ("resource_name", _field("name")),
        ("native_id", _field("native_id")),
        ("resource_uid", _field("resource_uid")),
        ("first_seen", _field("first_seen")),
        ("last_seen", _field("last_seen")),
        ("removed_on", _field("deleted_on")),
        ("open_misconfigurations", lambda row: _number(row.get("open_misconfigurations"))),
        ("worst_severity", _field("worst_severity")),
        ("open_vulnerabilities", _cve("open")),
        ("exploitable_vulnerabilities", _cve("exploitable")),
        ("last_used", _role("last_used_at")),
        ("last_used_region", _role("last_used_region")),
        ("last_used_read_on", _role("observed_on")),
        ("role_created", _role("created_at")),
        ("workloads", lambda row: _number(row.get("workloads"))),
    ],
}


class CsvReport:
    """Writes one report's rows to an open text file, header first."""

    def __init__(self, out: TextIO, kind: ReportKind) -> None:
        self._columns = COLUMNS[kind]
        self._writer = csv.writer(out, lineterminator="\r\n")
        out.write("\ufeff")
        self._writer.writerow([name for name, _ in self._columns])

    def write(self, row: Row) -> None:
        self._writer.writerow([get(row) for _, get in self._columns])
