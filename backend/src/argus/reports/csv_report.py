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

from argus.findings import VulnerabilityFacts
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
