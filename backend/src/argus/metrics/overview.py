"""The Overview read model (design: "Overview screen (MVP)").

Built from metric_daily only, in one query over a bounded date range, so the request reads a
handful of monthly partitions and never counts snapshot rows. A value that does not exist is
None, never 0: the UI says "no data" or "not covered" instead of drawing a false zero.

Point-in-time values are each tool's latest scan on or before `as_of` (today by default): a
block shows its own tool's data whatever ran first or on which day, and a tool that has not run
leaves only its own blocks empty. The UI shows the current state only; history is in the
month-end strip, the pass-rate months and the severity series, never as a delta against an
earlier day.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from sqlalchemy import Connection, text

from argus.metrics.series import HISTORY_DAYS, Range, latest_on_or_before, month_ends, range_days

SEVERITIES = ("critical", "high", "medium", "low", "informational")
THREATSCORE_TARGET = 80.0
# One metric per tool family marks the day of that tool's latest scan.
LATEST_SCAN_METRICS = (
    "assets.total",  # Steampipe
    "checks.status",  # Prowler
    "threatscore.score",
    "findings.open_by_severity",
    "attack_paths.open_by_severity",  # CloudFox
)
# Every metric a block reads. The load names them: compliance alone writes six rows per
# framework a day (about 40 frameworks on AWS), which the Overview never shows.
OVERVIEW_METRICS = (
    "assets.total",
    "assets.by_type",
    "threatscore.score",
    "checks.status",
    "findings.open_by_severity",
    "attack_paths.open_by_severity",
    "attack_paths.open_by_category",
)

Series = dict[date, dict[str, float]]


@dataclass(frozen=True)
class _Data:
    by_metric: dict[str, Series]

    def at(self, metric: str, day: date | None, dimension: str = "") -> float | None:
        if day is None:
            return None
        return self.by_metric.get(metric, {}).get(day, {}).get(dimension)

    def dims(self, metric: str, day: date | None) -> dict[str, float]:
        if day is None:
            return {}
        return dict(self.by_metric.get(metric, {}).get(day, {}))

    def days(self, metric: str) -> list[date]:
        return list(self.by_metric.get(metric, {}))

    def latest_on_or_before(self, metric: str, day: date) -> date | None:
        return latest_on_or_before(self.days(metric), day)


def _load(conn: Connection, connection_id: int, start: date, end: date) -> _Data:
    rows = conn.execute(
        text("""
        SELECT snapshot_date, metric, dimension, value FROM metric_daily
        WHERE connection_id = :c AND snapshot_date BETWEEN :s AND :e
          AND metric = ANY(CAST(:m AS text[]))
    """),
        {"c": connection_id, "s": start, "e": end, "m": list(OVERVIEW_METRICS)},
    )
    by_metric: dict[str, Series] = defaultdict(lambda: defaultdict(dict))
    for day, metric, dimension, value in rows:
        by_metric[metric][day][dimension] = float(value)
    return _Data({m: dict(s) for m, s in by_metric.items()})


def _delta(now: float | None, before: float | None) -> float | None:
    return None if now is None or before is None else now - before


def _month_ends(data: _Data, metric: str, ref: date) -> list[tuple[str, date]]:
    return month_ends(data.days(metric), ref)


def _severity_points(data: _Data, ref: date, rng: Range) -> list[dict[str, Any]]:
    metric = "findings.open_by_severity"
    return [
        {"date": d, **{s: data.at(metric, d, s) for s in SEVERITIES}}
        for d in range_days(data.days(metric), ref, rng)
    ]


def build(
    conn: Connection, *, connection_id: int, as_of: date, severity_range: Range = "6M"
) -> dict[str, Any]:
    data = _load(conn, connection_id, as_of - timedelta(days=HISTORY_DAYS), as_of)

    def latest(metric: str) -> date | None:
        return data.latest_on_or_before(metric, as_of)

    scanned = [d for d in (latest(m) for m in LATEST_SCAN_METRICS) if d is not None]
    data_through = max(scanned) if scanned else None

    def kpi(metric: str, dimension: str = "") -> dict[str, float | None]:
        return {"value": data.at(metric, latest(metric), dimension)}

    paths_day = latest("attack_paths.open_by_severity")
    exploitable = {
        "value": None
        if paths_day is None
        else sum(
            data.at("attack_paths.open_by_severity", paths_day, s) or 0
            for s in ("critical", "high")
        ),
    }

    strip_days = _month_ends(data, "threatscore.score", as_of)
    strip: list[dict[str, Any]] = []
    scores: list[float | None] = []
    for i, (month, day) in enumerate(strip_days):
        score = data.at("threatscore.score", day)
        prior = scores[i - 1] if i else None
        scores.append(score)
        strip.append({"month": month, "score": score, "change": _delta(score, prior)})

    checks = data.dims("checks.status", latest("checks.status"))
    passed, failed = checks.get("PASS"), checks.get("FAIL")
    monthly_pass = []
    for month, day in _month_ends(data, "checks.status", as_of):
        d = data.dims("checks.status", day)
        assessed = d.get("PASS", 0) + d.get("FAIL", 0)
        monthly_pass.append(
            {"month": month, "pass_rate": 100 * d.get("PASS", 0) / assessed if assessed else None}
        )

    month_table = []
    sev_months = _month_ends(data, "findings.open_by_severity", as_of)
    for i, (month, day) in enumerate(sev_months):
        values = {s: data.at("findings.open_by_severity", day, s) for s in SEVERITIES}
        month_total = sum(v or 0 for v in values.values())
        prior_month: dict[str, float | None] = (
            {s: data.at("findings.open_by_severity", sev_months[i - 1][1], s) for s in SEVERITIES}
            if i
            else {}
        )
        month_table.append(
            {
                "month": month,
                "values": values,
                "total": month_total,
                "change": {s: _delta(values[s], prior_month.get(s)) for s in SEVERITIES}
                if i
                else None,
            }
        )

    return {
        "as_of": as_of,
        "data_through": data_through,
        "kpis": {
            "assets": kpi("assets.total"),
            "threatscore": {**kpi("threatscore.score"), "target": THREATSCORE_TARGET},
            "open_critical": kpi("findings.open_by_severity", "critical"),
            "exploitable_paths": exploitable,
        },
        "threatscore": {
            "strip": strip,
            "change_since_first": _delta(scores[-1], scores[0]) if scores else None,
            "pillars": [
                {"pillar": dim, "score": value}
                for dim, value in sorted(
                    data.dims("threatscore.score", latest("threatscore.score")).items()
                )
                if dim
            ],
        },
        "check_results": {
            "passed": passed,
            "failed": failed,
            "muted": checks.get("MUTED"),
            "manual": checks.get("MANUAL"),
            "pass_rate": 100 * passed / (passed + (failed or 0)) if passed is not None else None,
            "monthly_pass_rate": monthly_pass,
        },
        "failed_by_severity": [
            {"severity": s, **kpi("findings.open_by_severity", s)} for s in SEVERITIES
        ],
        "severity_over_time": {
            "range": severity_range,
            "points": _severity_points(data, as_of, severity_range),
            "month_table": month_table,
        },
        "attack_paths_by_category": [
            {"category": c, "count": n}
            # Same day as the severities: no category row means no open path in it.
            for c, n in sorted(data.dims("attack_paths.open_by_category", paths_day).items())
        ],
        "inventory": {
            "by_type": [
                {"type": t, "count": n}
                for t, n in sorted(
                    data.dims("assets.by_type", latest("assets.by_type")).items(),
                    key=lambda x: -x[1],
                )
            ],
        },
        "coverage": {"aws": "covered", "gcp": "not covered", "oci": "not covered"},
    }
