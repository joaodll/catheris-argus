"""The Investigate summaries' read model (the Summary tab of Misconfigurations and of
Vulnerabilities; owner's decisions 2026-11-05 and 2026-11-06).

Built from metric_daily only: the findings module writes each screen's family of rows
(misconfigurations.*, vulnerabilities.*) after every run that changes its open findings
(findings.put_misconfiguration_metrics, findings.put_vulnerability_metrics). A request reads one
day of one scope plus a bounded window, never the finding table, so its cost does not grow with
the estate. A value that does not exist is None, never 0.

Every number is defined by the list filters that reproduce it. Misconfigurations: open (open and
reopened), status FAIL, not muted, Prowler and CloudFox. Vulnerabilities: open, not suppressed in
the scanner. "All connections" is connection 0, each enabled connection's latest count however
old (store.rollup_family), so a disabled connection's findings, which the lists still show, are
left out, as on the Overview.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from sqlalchemy import Connection, text

from argus import connections
from argus.metrics.series import HISTORY_DAYS
from argus.metrics.store import ALL_CONNECTIONS

SEVERITIES = ("critical", "high", "medium", "low", "informational")
EVENT_KINDS = ("opened", "reopened", "resolved")


@dataclass(frozen=True)
class Family:
    """One Investigate screen's summary metrics, all written together by their owner: open
    findings by severity (zero-filled, so its "critical" row marks every day the family was
    counted), opened / reopened / resolved that day (a flow, zero-filled), open findings by
    first-seen day, and the screen's own breakdowns, each "<value>|<severity>" unless its name
    says by severity (vulnerabilities.suppressed_by_severity)."""

    prefix: str
    breakdowns: tuple[str, ...]

    def metric(self, name: str) -> str:
        return f"{self.prefix}.{name}"

    @property
    def open_by_severity(self) -> str:
        return self.metric("open_by_severity")

    @property
    def open_by_first_seen(self) -> str:  # "<YYYY-MM-DD>|<severity>"
        return self.metric("open_by_first_seen")

    @property
    def events(self) -> str:
        return self.metric("events")

    @property
    def marker(self) -> tuple[str, str]:
        return (self.open_by_severity, "critical")

    @property
    def state_metrics(self) -> tuple[str, ...]:
        return (
            self.open_by_severity,
            *(self.metric(b) for b in self.breakdowns),
            self.open_by_first_seen,
        )

    @property
    def metrics(self) -> list[str]:
        return [*self.state_metrics, self.events]

    def zero(self) -> dict[tuple[str, str], float]:
        """The rows written every time, at 0: a day with them is a day the family was counted,
        so the weekly flow tells a week without changes (0) from the weeks before any count."""
        values = {(self.open_by_severity, s): 0.0 for s in SEVERITIES}
        return values | {(self.events, e): 0.0 for e in EVENT_KINDS}


# Investigate → Misconfigurations: open, status FAIL, not muted, Prowler and CloudFox.
MISCONFIGURATIONS = Family(
    "misconfigurations",
    ("open_by_tool", "open_by_category", "open_by_service", "open_by_region", "reach"),
)
OPEN_BY_TOOL = MISCONFIGURATIONS.metric("open_by_tool")
OPEN_BY_CATEGORY = MISCONFIGURATIONS.metric("open_by_category")
OPEN_BY_SERVICE = MISCONFIGURATIONS.metric("open_by_service")
OPEN_BY_REGION = MISCONFIGURATIONS.metric("open_by_region")
REACH = MISCONFIGURATIONS.metric("reach")
REACHES = ("confirmed", "restricted", "unknown", "not_covered")

# Investigate → Vulnerabilities: open, not suppressed in the scanner (muted). The suppressed ones
# are counted apart, by severity only.
VULNERABILITIES = Family(
    "vulnerabilities",
    (
        "suppressed_by_severity",
        "open_by_resource_type",
        "open_by_region",
        "open_by_fix",
        "open_exploitable_by_fix",
    ),
)
SUPPRESSED_BY_SEVERITY = VULNERABILITIES.metric("suppressed_by_severity")  # dimension: severity
OPEN_BY_RESOURCE_TYPE = VULNERABILITIES.metric("open_by_resource_type")
VULNERABILITIES_BY_REGION = VULNERABILITIES.metric("open_by_region")
# The list's fix filter: available = a fixed version for every or some of its packages (YES or
# PARTIAL), none = not yet (NO); unknown = the scanner does not say (no list filter).
OPEN_BY_FIX = VULNERABILITIES.metric("open_by_fix")
OPEN_EXPLOITABLE_BY_FIX = VULNERABILITIES.metric("open_exploitable_by_fix")
FIXES = ("available", "none", "unknown")

TOP = 10  # items per breakdown; the rest are counted in `more`
WEEKS = 12
RECENT_DAYS = 30
# Age columns: (key, youngest age in days, oldest age in days or None for "older").
AGES: tuple[tuple[str, int, int | None], ...] = (
    ("under_30_days", 0, 29),
    ("30_to_90_days", 30, 89),
    ("90_to_180_days", 90, 179),
    ("180_to_365_days", 180, 364),
    ("over_a_year", 365, None),
)


def dimension(value: str, severity: str) -> str:
    """The composite dimension of a misconfigurations.* breakdown: "<value>|<severity>"."""
    return f"{value}|{severity}"


def _split(dim: str) -> tuple[str, str]:
    value, _, severity = dim.rpartition("|")
    return value, severity


def _counts() -> dict[str, int]:
    return dict.fromkeys(SEVERITIES, 0)


@dataclass(frozen=True)
class _Item:
    value: str
    severities: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.severities.values())

    def out(self) -> dict[str, Any]:
        return {"value": self.value, "total": self.total, "severities": self.severities}


def _rank(item: _Item) -> tuple[int, int, int, str]:
    """Worst first: most critical, then most high, then most in all, then by name."""
    return (-item.severities["critical"], -item.severities["high"], -item.total, item.value)


def _items(dims: dict[str, float]) -> list[_Item]:
    by_value: dict[str, dict[str, int]] = defaultdict(_counts)
    for dim, n in dims.items():
        value, severity = _split(dim)
        if severity in SEVERITIES:
            by_value[value][severity] += int(n)
    return sorted((_Item(v, s) for v, s in by_value.items()), key=_rank)


def _breakdown(dims: dict[str, float]) -> dict[str, Any]:
    items = _items(dims)
    return {"items": [i.out() for i in items[:TOP]], "more": max(0, len(items) - TOP)}


def _latest_day(
    conn: Connection, family: Family, connection_id: int, start: date, end: date
) -> date | None:
    day: date | None = conn.execute(
        text("""
            SELECT max(snapshot_date) FROM metric_daily
            WHERE connection_id = :c AND metric = :m AND dimension = 'critical'
              AND snapshot_date BETWEEN :s AND :e
        """),
        {"c": connection_id, "m": family.open_by_severity, "s": start, "e": end},
    ).scalar_one()
    return day


def latest_counted_day(conn: Connection, family: Family, connection_id: int) -> date | None:
    """The newest day a connection's summary counts were written, however old: one index probe
    on the marker row (metric_daily_by_connection). For the writer: current counts always go on
    this day or a later one, so a re-derive or a late ingest of an older day never leaves the
    newest row stale."""
    day: date | None = conn.execute(
        text("""
            SELECT max(snapshot_date) FROM metric_daily
            WHERE connection_id = :c AND metric = :m AND dimension = 'critical'
        """),
        {"c": connection_id, "m": family.open_by_severity},
    ).scalar_one()
    return day


def _day_rows(
    conn: Connection, family: Family, connection_id: int, day: date
) -> dict[str, dict[str, float]]:
    rows = conn.execute(
        text("""
            SELECT metric, dimension, value FROM metric_daily
            WHERE snapshot_date = :d AND connection_id = :c AND metric = ANY(CAST(:m AS text[]))
        """),
        {"d": day, "c": connection_id, "m": list(family.state_metrics)},
    )
    out: dict[str, dict[str, float]] = defaultdict(dict)
    for metric, dim, value in rows:
        out[metric][dim] = float(value)
    return out


def _by_account(conn: Connection, family: Family, start: date, end: date) -> dict[str, Any]:
    """Each enabled connection's open findings by severity, on its latest day in the window."""
    rows = conn.execute(
        text(f"""
            WITH latest AS (
              SELECT connection_id, max(snapshot_date) AS day FROM metric_daily
              WHERE metric = :m AND dimension = 'critical' AND connection_id > 0
                AND snapshot_date BETWEEN :s AND :e
              GROUP BY connection_id
            )
            SELECT c.id, c.name, c.provider, md.dimension, md.value
            FROM latest l
            JOIN metric_daily md ON md.connection_id = l.connection_id
              AND md.snapshot_date = l.day AND md.metric = :m
            JOIN ({connections.DIRECTORY_SQL}) c ON c.id = l.connection_id AND c.enabled
            WHERE md.snapshot_date BETWEEN :s AND :e
        """),  # noqa: S608 - an exported SQL constant only
        {"m": family.open_by_severity, "s": start, "e": end},
    )
    accounts: dict[int, dict[str, Any]] = {}
    for cid, name, provider, severity, value in rows:
        account = accounts.setdefault(
            cid, {"connection_id": cid, "name": name, "provider": provider, "s": _counts()}
        )
        if severity in SEVERITIES:
            account["s"][severity] += int(value)
    items = sorted(
        (
            (_Item(a["name"], a["s"]), a)
            for a in accounts.values()
            if sum(a["s"].values())  # an account with nothing open is not in the list
        ),
        key=lambda pair: (*_rank(pair[0])[:3], pair[0].value, pair[1]["connection_id"]),
    )
    return {
        "items": [
            {
                "connection_id": a["connection_id"],
                "provider": a["provider"],
                **item.out(),
            }
            for item, a in items[:TOP]
        ],
        "more": max(0, len(items) - TOP),
    }


def _ages(dims: dict[str, float], today: date) -> list[dict[str, Any]]:
    columns = [(key, lo, hi, _counts()) for key, lo, hi in AGES]
    for dim, n in dims.items():
        first_seen, severity = _split(dim)
        if severity not in SEVERITIES:
            continue
        age = (today - date.fromisoformat(first_seen)).days
        for _key, lo, hi, counts in columns:
            if age >= lo and (hi is None or age <= hi):
                counts[severity] += int(n)
                break
    return [
        {
            "key": key,
            # The list's first-seen filter that reproduces the column, both ends inclusive.
            "first_seen_from": None if hi is None else today - timedelta(days=hi),
            "first_seen_to": None if lo == 0 else today - timedelta(days=lo),
            "total": sum(counts.values()),
            "severities": counts,
        }
        for key, lo, hi, counts in columns
    ]


def _flow(conn: Connection, family: Family, connection_id: int, today: date) -> dict[str, Any]:
    """Opened, reopened and resolved per ISO week, the last WEEKS weeks, and over the last
    RECENT_DAYS days. A week before the first counted day is None (no history), a later week
    without a run is 0 (nothing can open or resolve without one)."""
    monday = today - timedelta(days=today.weekday())
    start = monday - timedelta(weeks=WEEKS - 1)
    by_day: dict[date, dict[str, float]] = defaultdict(dict)
    for day, event, value in conn.execute(
        text("""
            SELECT snapshot_date, dimension, value FROM metric_daily
            WHERE connection_id = :c AND metric = :m AND snapshot_date BETWEEN :s AND :e
        """),
        {"c": connection_id, "m": family.events, "s": start, "e": today},
    ):
        by_day[day][event] = float(value)
    earlier = conn.execute(
        text("""
            SELECT EXISTS (SELECT 1 FROM metric_daily
                           WHERE connection_id = :c AND metric = :m
                             AND snapshot_date BETWEEN :s AND :e)
        """),
        {
            "c": connection_id,
            "m": family.events,
            "s": start - timedelta(days=HISTORY_DAYS),
            "e": start - timedelta(days=1),
        },
    ).scalar_one()
    first = date.min if earlier else min(by_day, default=None)

    def total(days: list[date]) -> dict[str, int]:
        return {k: int(sum(by_day.get(d, {}).get(k, 0) for d in days)) for k in EVENT_KINDS}

    weeks = []
    for i in range(WEEKS):
        week = start + timedelta(weeks=i)
        days = [week + timedelta(days=n) for n in range(7)]
        known = first is not None and days[-1] >= first
        weeks.append(
            {
                "week": week,
                "partial": week == monday,
                **(total(days) if known else dict.fromkeys(EVENT_KINDS)),
            }
        )
    recent = [today - timedelta(days=n) for n in range(RECENT_DAYS)]
    return {
        "weeks": weeks,
        "last_30_days": total(recent) if first is not None else None,
    }


def _severities(dims: dict[str, float]) -> dict[str, int]:
    counts = _counts()
    for severity, n in dims.items():
        if severity in SEVERITIES:
            counts[severity] = int(n)
    return counts


def _fixed(items: list[_Item], values: tuple[str, ...]) -> list[dict[str, Any]]:
    """A breakdown with a fixed set of values, in that order, each present (zero when none)."""
    by_value = {i.value: i for i in items}
    return [(by_value[v] if v in by_value else _Item(v, _counts())).out() for v in values]


@dataclass(frozen=True)
class _Read:
    """What every family's summary shares: the day it shows, its rows, and the flow."""

    day: date | None
    rows: dict[str, dict[str, float]]
    flow: dict[str, Any]
    by_account: dict[str, Any] | None
    by_age: list[dict[str, Any]] | None


def _read(conn: Connection, family: Family, connection_id: int, today: date) -> _Read:
    start = today - timedelta(days=HISTORY_DAYS)
    day = _latest_day(conn, family, connection_id, start, today)
    flow = _flow(conn, family, connection_id, today)
    if day is None:
        return _Read(None, {}, flow, None, None)
    rows = _day_rows(conn, family, connection_id, day)
    return _Read(
        day,
        rows,
        flow,
        _by_account(conn, family, start, today) if connection_id == ALL_CONNECTIONS else None,
        _ages(rows.get(family.open_by_first_seen, {}), today),
    )


def misconfiguration_summary(
    conn: Connection, *, connection_id: int = ALL_CONNECTIONS, today: date
) -> dict[str, Any]:
    """The Misconfigurations Summary tab for all connections (0) or one, as of each account's
    latest count."""
    read = _read(conn, MISCONFIGURATIONS, connection_id, today)
    if read.day is None:
        return {
            "data_through": None,
            "open": None,
            "by_account": None,
            "by_category": None,
            "by_service": None,
            "by_region": None,
            "by_age": None,
            "reach": None,
            **read.flow,
        }
    rows = read.rows
    severities = _severities(rows.get(MISCONFIGURATIONS.open_by_severity, {}))
    tools = {"prowler": 0, "cloudfox": 0}
    for dim, n in rows.get(OPEN_BY_TOOL, {}).items():
        tool, _ = _split(dim)
        if tool in tools:
            tools[tool] += int(n)
    return {
        "data_through": read.day,
        "open": {"total": sum(severities.values()), "severities": severities, "tools": tools},
        "by_account": read.by_account,
        "by_category": _breakdown(rows.get(OPEN_BY_CATEGORY, {})),
        "by_service": _breakdown(rows.get(OPEN_BY_SERVICE, {})),
        "by_region": _breakdown(rows.get(OPEN_BY_REGION, {})),
        "by_age": read.by_age,
        "reach": _fixed(_items(rows.get(REACH, {})), REACHES),
        **read.flow,
    }


def vulnerability_summary(
    conn: Connection, *, connection_id: int = ALL_CONNECTIONS, today: date
) -> dict[str, Any]:
    """The Vulnerabilities Summary tab for all connections (0) or one, as of each account's
    latest count."""
    read = _read(conn, VULNERABILITIES, connection_id, today)
    if read.day is None:
        return {
            "data_through": None,
            "open": None,
            "by_account": None,
            "by_resource_type": None,
            "by_region": None,
            "by_age": None,
            "by_fix": None,
            **read.flow,
        }
    rows = read.rows
    severities = _severities(rows.get(VULNERABILITIES.open_by_severity, {}))
    exploitable = {i.value: i.total for i in _items(rows.get(OPEN_EXPLOITABLE_BY_FIX, {}))}
    return {
        "data_through": read.day,
        "open": {
            "total": sum(severities.values()),
            "severities": severities,
            "suppressed": int(sum(rows.get(SUPPRESSED_BY_SEVERITY, {}).values())),
            "exploitable": sum(exploitable.values()),
            "exploitable_with_fix": exploitable.get("available", 0),
        },
        "by_account": read.by_account,
        "by_resource_type": _breakdown(rows.get(OPEN_BY_RESOURCE_TYPE, {})),
        "by_region": _breakdown(rows.get(VULNERABILITIES_BY_REGION, {})),
        "by_age": read.by_age,
        "by_fix": _fixed(_items(rows.get(OPEN_BY_FIX, {})), FIXES),
        **read.flow,
    }
