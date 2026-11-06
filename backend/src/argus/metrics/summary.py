"""The Misconfigurations summary read model (Investigate → Misconfigurations → Summary, owner's
decision 2026-11-05).

Built from metric_daily only: the findings module writes the misconfigurations.* rows after
every run that changes open findings or their reach (findings.put_misconfiguration_metrics). A
request reads one day of one scope plus a bounded window, never the finding table, so its cost
does not grow with the estate. A value that does not exist is None, never 0.

Every number is defined by the Misconfigurations list filters that reproduce it: open (open and
reopened), status FAIL, not muted, Prowler and CloudFox. "All connections" is connection 0, each
enabled connection's latest count however old (store.rollup), so a disabled connection's
findings, which the list still shows, are left out, as on the Overview.
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
# The metric names, one definition: the findings module writes them, this module reads them.
OPEN_BY_SEVERITY = "misconfigurations.open_by_severity"
OPEN_BY_TOOL = "misconfigurations.open_by_tool"
OPEN_BY_CATEGORY = "misconfigurations.open_by_category"
OPEN_BY_SERVICE = "misconfigurations.open_by_service"
OPEN_BY_REGION = "misconfigurations.open_by_region"
OPEN_BY_FIRST_SEEN = "misconfigurations.open_by_first_seen"  # "<YYYY-MM-DD>|<severity>"
REACH = "misconfigurations.reach"
EVENTS = "misconfigurations.events"  # opened / reopened / resolved that day (a flow)
EVENT_KINDS = ("opened", "reopened", "resolved")
STATE_METRICS = (
    OPEN_BY_SEVERITY,
    OPEN_BY_TOOL,
    OPEN_BY_CATEGORY,
    OPEN_BY_SERVICE,
    OPEN_BY_REGION,
    OPEN_BY_FIRST_SEEN,
    REACH,
)
METRICS = [*STATE_METRICS, EVENTS]
REACHES = ("confirmed", "restricted", "unknown", "not_covered")
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


def _latest_day(conn: Connection, connection_id: int, start: date, end: date) -> date | None:
    day: date | None = conn.execute(
        text("""
            SELECT max(snapshot_date) FROM metric_daily
            WHERE connection_id = :c AND metric = :m AND dimension = 'critical'
              AND snapshot_date BETWEEN :s AND :e
        """),
        {"c": connection_id, "m": OPEN_BY_SEVERITY, "s": start, "e": end},
    ).scalar_one()
    return day


def latest_counted_day(conn: Connection, connection_id: int) -> date | None:
    """The newest day a connection's summary counts were written, however old: one index probe
    on the marker row (metric_daily_by_connection). For the writer: current counts always go on
    this day or a later one, so a re-derive or a late ingest of an older day never leaves the
    newest row stale."""
    day: date | None = conn.execute(
        text("""
            SELECT max(snapshot_date) FROM metric_daily
            WHERE connection_id = :c AND metric = :m AND dimension = 'critical'
        """),
        {"c": connection_id, "m": OPEN_BY_SEVERITY},
    ).scalar_one()
    return day


def _day_rows(conn: Connection, connection_id: int, day: date) -> dict[str, dict[str, float]]:
    rows = conn.execute(
        text("""
            SELECT metric, dimension, value FROM metric_daily
            WHERE snapshot_date = :d AND connection_id = :c AND metric = ANY(CAST(:m AS text[]))
        """),
        {"d": day, "c": connection_id, "m": list(STATE_METRICS)},
    )
    out: dict[str, dict[str, float]] = defaultdict(dict)
    for metric, dim, value in rows:
        out[metric][dim] = float(value)
    return out


def _by_account(conn: Connection, start: date, end: date) -> dict[str, Any]:
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
        {"m": OPEN_BY_SEVERITY, "s": start, "e": end},
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
            if sum(a["s"].values())  # an account with nothing open is not "misconfigured"
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


def _flow(conn: Connection, connection_id: int, today: date) -> dict[str, Any]:
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
        {"c": connection_id, "m": EVENTS, "s": start, "e": today},
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
            "m": EVENTS,
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


def misconfiguration_summary(
    conn: Connection, *, connection_id: int = ALL_CONNECTIONS, today: date
) -> dict[str, Any]:
    """The Summary tab for all connections (0) or one, as of each account's latest count."""
    start = today - timedelta(days=HISTORY_DAYS)
    day = _latest_day(conn, connection_id, start, today)
    flow = _flow(conn, connection_id, today)
    if day is None:
        return {
            "data_through": None,
            "open": None,
            "by_account": None,
            "by_category": None,
            "by_service": None,
            "by_region": None,
            "by_age": None,
            "reach": None,
            **flow,
        }
    rows = _day_rows(conn, connection_id, day)
    severities = _counts()
    for severity, n in rows.get(OPEN_BY_SEVERITY, {}).items():
        if severity in SEVERITIES:
            severities[severity] = int(n)
    tools = {"prowler": 0, "cloudfox": 0}
    for dim, n in rows.get(OPEN_BY_TOOL, {}).items():
        tool, _ = _split(dim)
        if tool in tools:
            tools[tool] += int(n)
    reach = {i.value: i for i in _items(rows.get(REACH, {}))}
    return {
        "data_through": day,
        "open": {"total": sum(severities.values()), "severities": severities, "tools": tools},
        "by_account": _by_account(conn, start, today) if connection_id == ALL_CONNECTIONS else None,
        "by_category": _breakdown(rows.get(OPEN_BY_CATEGORY, {})),
        "by_service": _breakdown(rows.get(OPEN_BY_SERVICE, {})),
        "by_region": _breakdown(rows.get(OPEN_BY_REGION, {})),
        "by_age": _ages(rows.get(OPEN_BY_FIRST_SEEN, {}), today),
        "reach": [(reach[r] if r in reach else _Item(r, _counts())).out() for r in REACHES],
        **flow,
    }
