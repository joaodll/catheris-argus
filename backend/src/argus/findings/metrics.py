"""Findings and compliance rollups for the Overview.

ThreatScore follows Prowler 5.44.0 and 5.45.0 (api/src/backend/tasks/jobs/threatscore.py): for each
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
