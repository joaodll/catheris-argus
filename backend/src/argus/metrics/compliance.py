"""Compliance per framework over time, from metric_daily only (Posture → Compliance).

A framework's score is requirements passed ÷ requirements assessed, manual ones excluded
(findings.metrics); connection 0 is the score of the summed parts. A value that does not exist
is None, never 0.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from sqlalchemy import Connection, text

from argus.metrics.series import (
    HISTORY_DAYS,
    Range,
    calendar_month_ends,
    month_ends,
    range_days,
    sample,
)

STATUSES = ("PASS", "FAIL", "MANUAL")
TREND_WEEKS = 26


@dataclass
class _Framework:
    scores: dict[date, float] = field(default_factory=dict)
    requirements: dict[date, dict[str, float]] = field(default_factory=lambda: defaultdict(dict))

    def latest_day(self) -> date | None:
        days = self.scores.keys() | self.requirements.keys()
        return max(days) if days else None

    def counts(self) -> dict[str, int] | None:
        """Requirements by status on the latest day with any; a status with none is 0."""
        if not self.requirements:
            return None
        on_day = self.requirements[max(self.requirements)]
        return {s.lower(): int(on_day.get(s, 0)) for s in STATUSES}

    def change(self, ref: date) -> tuple[float | None, str | None]:
        """Score change since the first month-end of the last six months, and that month."""
        ends = month_ends(self.scores.keys(), ref)
        if len(ends) < 2:
            return None, None
        return self.scores[ends[-1][1]] - self.scores[ends[0][1]], ends[0][0]

    def months(self, ref: date) -> list[dict[str, Any]]:
        """Each of the six calendar months: the month-end score and its change from the month
        before (None when either month had no scan)."""
        out: list[dict[str, Any]] = []
        prior: float | None = None
        for month, day in calendar_month_ends(self.scores.keys(), ref):
            score = self.scores[day] if day else None
            change = score - prior if score is not None and prior is not None else None
            out.append({"month": month, "score": score, "change": change})
            prior = score
        return out

    def summary(self, ref: date) -> dict[str, Any]:
        latest = self.latest_day()
        change, since = self.change(ref)
        return {
            "latest_day": latest,
            "score": self.scores.get(latest) if latest else None,
            "change": change,
            "change_since": since,
            "requirements": self.counts(),
        }


# Every framework, or one: its score and its requirement counts ("<framework>|<status>").
_EVERY = "metric IN ('compliance.score', 'compliance.requirements')"
# The score's dimension is the key, the counts' "<key>|<status>": no other metric shares them.
_ONE = (
    "metric IN ('compliance.score', 'compliance.requirements')"
    " AND dimension = ANY(CAST(:dims AS text[]))"
)


def _load(
    conn: Connection, *, connection_id: int, as_of: date, framework: str | None
) -> dict[str, _Framework]:
    rows = conn.execute(
        text(f"""
        SELECT snapshot_date, metric, dimension, value FROM metric_daily
        WHERE connection_id = :c AND snapshot_date BETWEEN :s AND :e
          AND {_ONE if framework else _EVERY}
    """),  # noqa: S608 - constant SQL only
        {
            "c": connection_id,
            "s": as_of - timedelta(days=HISTORY_DAYS),
            "e": as_of,
            "dims": [framework, *(f"{framework}|{s}" for s in STATUSES)],
        },
    )
    out: dict[str, _Framework] = defaultdict(_Framework)
    for day, metric, dimension, value in rows:
        if metric == "compliance.score":
            out[dimension].scores[day] = float(value)
        else:
            name, _, status = dimension.rpartition("|")
            out[name].requirements[day][status] = float(value)
    return out


def compliance_scores(conn: Connection, *, connection_id: int, as_of: date) -> list[dict[str, Any]]:
    """Every framework with results in the last six months: its latest score and counts, the
    change over the months, and a weekly trend for a sparkline."""
    out = []
    loaded = _load(conn, connection_id=connection_id, as_of=as_of, framework=None)
    for name, fw in sorted(loaded.items()):
        trend = sample(fw.scores.keys(), as_of, 7, TREND_WEEKS)
        out.append(
            {
                "framework": name,
                **fw.summary(as_of),
                "trend": [{"date": d, "score": fw.scores[d]} for d in trend],
            }
        )
    return out


def compliance_history(
    conn: Connection, *, framework: str, connection_id: int, as_of: date, rng: Range = "6M"
) -> dict[str, Any]:
    """One framework: its summary, the score sampled for the range, and the month table."""
    fw = _load(conn, connection_id=connection_id, as_of=as_of, framework=framework).get(
        framework, _Framework()
    )
    return {
        **fw.summary(as_of),
        "range": rng,
        "series": [
            {"date": d, "score": fw.scores[d]} for d in range_days(fw.scores.keys(), as_of, rng)
        ],
        "month_table": fw.months(as_of),
    }


def compliance_by_account(
    conn: Connection, *, framework: str, as_of: date
) -> dict[int, dict[str, Any]]:
    """Per connection with a score for the framework in the last six months: its latest score
    and the six month-ends with their changes."""
    rows = conn.execute(
        text("""
        SELECT connection_id, snapshot_date, value FROM metric_daily
        WHERE metric = 'compliance.score' AND dimension = :f AND connection_id > 0
          AND snapshot_date BETWEEN :s AND :e
    """),
        {"f": framework, "s": as_of - timedelta(days=HISTORY_DAYS), "e": as_of},
    )
    by_connection: dict[int, _Framework] = defaultdict(_Framework)
    for connection_id, day, value in rows:
        by_connection[connection_id].scores[day] = float(value)
    out = {}
    for connection_id, fw in by_connection.items():
        latest = fw.latest_day()
        out[connection_id] = {
            "latest_day": latest,
            "score": fw.scores.get(latest) if latest else None,
            "months": fw.months(as_of),
        }
    return out
