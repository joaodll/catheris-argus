"""Findings and compliance rollups for the Overview.

ThreatScore follows Prowler 5.44.0 to 5.47.0 (api/src/backend/tasks/jobs/threatscore.py): for each
requirement with results, rate = passed / total and rfac = 1 + 0.25 * level of risk;
score = sum(rate * total * weight * rfac) / sum(total * weight * rfac) * 100, overall and per
section (the pillars). Numerator and denominator are stored, not just the score, so "all
connections" is the true combined score rather than an average of averages.
"""

from datetime import date

from sqlalchemy import Connection, text

from argus import metrics
from argus.findings.lifecycle import CHECK_METRICS
from argus.findings.model import SEVERITIES
from argus.metrics import summary

THREATSCORE_FRAMEWORK = "prowler_threatscore_aws"
ADDITIVE = [
    "findings.open_by_severity",
    "findings.events",
    "compliance.passed",
    "compliance.assessed",
    "compliance.requirements",
    "threatscore.numerator",
    "threatscore.denominator",
    *CHECK_METRICS,
]
DERIVED = ["compliance.score", "threatscore.score"]
FINDING_METRICS = [m for m in ADDITIVE if m not in CHECK_METRICS] + DERIVED
_STATUS = {1: "FAIL", 2: "MANUAL", 3: "PASS"}


def _values(conn: Connection, connection_id: int, day: date) -> dict[tuple[str, str], float]:
    p = {"d": day, "c": connection_id}
    values: dict[tuple[str, str], float] = {("findings.open_by_severity", s): 0 for s in SEVERITIES}
    for code, n in conn.execute(
        text("""
            SELECT fs.severity, count(*) FROM finding_snapshot fs
            JOIN finding f ON f.id = fs.finding_id
            WHERE fs.snapshot_date = :d AND f.connection_id = :c AND f.tool = 'prowler'
              AND fs.status = 1 AND NOT fs.muted
            GROUP BY fs.severity"""),
        p,
    ):
        values[("findings.open_by_severity", SEVERITIES[code - 1])] = n
    for event, n in conn.execute(
        text("""
            SELECT e.event, count(*) FROM finding_event e JOIN finding f ON f.id = e.finding_id
            WHERE e.occurred_on = :d AND f.connection_id = :c AND f.tool = 'prowler'
            GROUP BY e.event"""),
        p,
    ):
        values[("findings.events", event)] = n
    numerator: dict[str, float] = {}
    denominator: dict[str, float] = {}
    for framework, section, status, passed, failed, risk, weight in conn.execute(
        text("""
            SELECT cr.framework, cr.section, cs.status, cs.passed_checks, cs.failed_checks,
                   cr.level_of_risk, cr.weight
            FROM compliance_snapshot cs
            JOIN compliance_requirement cr ON cr.id = cs.requirement_id
            WHERE cs.snapshot_date = :d AND cs.connection_id = :c"""),
        p,
    ):
        key = ("compliance.requirements", f"{framework}|{_STATUS[status]}")
        values[key] = values.get(key, 0) + 1
        if status != 2:  # manual requirements are excluded from the score
            values[("compliance.assessed", framework)] = (
                values.get(("compliance.assessed", framework), 0) + 1
            )
            values[("compliance.passed", framework)] = values.get(
                ("compliance.passed", framework), 0
            ) + (1 if status == 3 else 0)
        total = passed + failed
        if framework == THREATSCORE_FRAMEWORK and total and weight:
            rfac = 1 + 0.25 * (risk or 0)
            for dim in ("", section or "Unknown"):
                numerator[dim] = numerator.get(dim, 0) + passed * weight * rfac
                denominator[dim] = denominator.get(dim, 0) + total * weight * rfac
    for dim, value in numerator.items():
        values[("threatscore.numerator", dim)] = value
        values[("threatscore.denominator", dim)] = denominator[dim]
    return values


def _derive(conn: Connection, connection_id: int, day: date) -> None:
    """Scores from their stored parts, for one connection (or 0 after the rollup)."""
    rows = metrics.read(
        conn,
        day=day,
        connection_id=connection_id,
        metrics=[
            "compliance.passed",
            "compliance.assessed",
            "threatscore.numerator",
            "threatscore.denominator",
        ],
    )
    parts = {(m, d): v for m, d, v in rows}
    values: dict[tuple[str, str], float] = {}
    for (metric, dim), assessed in parts.items():
        if metric == "compliance.assessed" and assessed:
            values[("compliance.score", dim)] = (
                100 * parts.get(("compliance.passed", dim), 0) / assessed
            )
        if metric == "threatscore.denominator" and assessed:
            values[("threatscore.score", dim)] = (
                100 * parts.get(("threatscore.numerator", dim), 0) / assessed
            )
    metrics.put(conn, day=day, connection_id=connection_id, values=values, replace=DERIVED)


def rederive_scores(conn: Connection, *, connection_id: int, day: date) -> None:
    """After a failed run carried the parts forward: the scores of the connection and of all
    connections, so the score history has no gap and connection 0 is not stale."""
    _derive(conn, connection_id, day)
    _derive(conn, metrics.ALL_CONNECTIONS, day)


def rollup_findings(conn: Connection, *, day: date) -> None:
    """All connections' findings metrics and scores for one day, from what is stored."""
    metrics.rollup(conn, day=day, metrics=ADDITIVE)
    _derive(conn, metrics.ALL_CONNECTIONS, day)


def put_findings_metrics(conn: Connection, *, connection_id: int, day: date) -> None:
    metrics.put(
        conn,
        day=day,
        connection_id=connection_id,
        values=_values(conn, connection_id, day),
        replace=[m for m in ADDITIVE if m not in CHECK_METRICS],
    )
    _derive(conn, connection_id, day)
    metrics.rollup(conn, day=day, metrics=ADDITIVE)
    _derive(conn, metrics.ALL_CONNECTIONS, day)


# The Misconfigurations summary (Investigate → Misconfigurations → Summary, owner 2026-11-05):
# open, failing, unmuted Prowler and CloudFox findings. The Overview keeps findings.* (Prowler
# only, from the day's snapshot); these count the current finding table, so they also follow a
# reach change after a Steampipe run or a re-derive. The names and the "<value>|<severity>"
# dimensions are defined once by their reader, metrics.summary.
MISCONFIGURATION_TOOLS = ("prowler", "cloudfox")
MISCONFIGURATION_METRICS = summary.METRICS


def _misconfiguration_values(
    conn: Connection, connection_id: int, day: date
) -> dict[tuple[str, str], float]:
    # Zero-filled: a day with these rows is a day the summary was counted, so the weekly flow
    # tells a week without changes (0) from the weeks before any count (no data).
    values: dict[tuple[str, str], float] = {(summary.OPEN_BY_SEVERITY, s): 0.0 for s in SEVERITIES}
    values |= {(summary.EVENTS, e): 0.0 for e in summary.EVENT_KINDS}

    dim = summary.dimension

    def add(metric: str, dimension: str, n: int) -> None:
        values[(metric, dimension)] = values.get((metric, dimension), 0) + n

    for severity, tool, service, region, categories, first_seen, reach, n in conn.execute(
        text("""
            SELECT f.severity, f.tool, coalesce(f.service, ''), f.region, f.categories,
                   f.first_seen, f.reach, count(*)
            FROM finding f
            WHERE f.connection_id = :c AND f.tool = ANY(CAST(:tools AS text[]))
              AND f.state IN ('open', 'reopened') AND f.status = 'FAIL' AND NOT f.muted
            GROUP BY 1, 2, 3, 4, 5, 6, 7"""),
        {"c": connection_id, "tools": list(MISCONFIGURATION_TOOLS)},
    ):
        add(summary.OPEN_BY_SEVERITY, severity, n)
        add(summary.OPEN_BY_TOOL, dim(tool, severity), n)
        add(summary.OPEN_BY_SERVICE, dim(service, severity), n)
        add(summary.OPEN_BY_REGION, dim(region, severity), n)
        add(summary.OPEN_BY_FIRST_SEEN, dim(first_seen.isoformat(), severity), n)
        # A finding counts once under each of its categories; "" holds the ones with none.
        for category in sorted(set(categories)) or [""]:
            add(summary.OPEN_BY_CATEGORY, dim(category, severity), n)
        if reach is not None:
            add(summary.REACH, dim(reach, severity), n)
    for event, n in conn.execute(
        text("""
            SELECT e.event, count(*) FROM finding_event e JOIN finding f ON f.id = e.finding_id
            WHERE e.occurred_on = :d AND f.connection_id = :c
              AND f.tool = ANY(CAST(:tools AS text[])) AND f.status = 'FAIL' AND NOT f.muted
              AND e.event = ANY(CAST(:kinds AS text[]))
            GROUP BY e.event"""),
        {
            "d": day,
            "c": connection_id,
            "tools": list(MISCONFIGURATION_TOOLS),
            "kinds": list(summary.EVENT_KINDS),
        },
    ):
        values[(summary.EVENTS, event)] = n
    return values


def put_misconfiguration_metrics(conn: Connection, *, connection_id: int, day: date) -> None:
    """The Misconfigurations summary's numbers for one connection after a run that changed its
    findings or their reach (Prowler, CloudFox, a Steampipe run's reach check, a re-derive),
    then all connections. Counted from the current finding table, so a failed run, which
    changes nothing there, needs nothing carried forward.

    The day's events go on the run's day. The counts are the current state, so they go on the
    run's day or the connection's newest counted day, whichever is later: a re-derive of an
    older load, or an older run ingested late, must not leave the newest row stale. All
    connections is then rolled up on those days and on every later day that carried this
    connection's previous counts."""
    values = _misconfiguration_values(conn, connection_id, day)
    latest = summary.latest_counted_day(conn, connection_id)
    state_day = max(day, latest) if latest else day
    metrics.put(
        conn,
        day=day,
        connection_id=connection_id,
        values={k: v for k, v in values.items() if k[0] == summary.EVENTS},
        replace=[summary.EVENTS],
    )
    metrics.put(
        conn,
        day=state_day,
        connection_id=connection_id,
        values={k: v for k, v in values.items() if k[0] != summary.EVENTS},
        replace=list(summary.STATE_METRICS),
    )
    carried = metrics.carried_days(
        conn, after=state_day, metrics=[summary.OPEN_BY_SEVERITY], connection_id=connection_id
    )
    for rolled in sorted({day, state_day, *carried}):
        metrics.rollup_family(
            conn,
            day=rolled,
            metrics=MISCONFIGURATION_METRICS,
            marker=(summary.OPEN_BY_SEVERITY, "critical"),  # zero-filled: written every time
        )
