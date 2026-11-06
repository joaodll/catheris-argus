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
from argus.findings.model import (
    MISCONFIGURATION_TOOLS,
    OPEN_MISCONFIGURATION,
    SEVERITIES,
    VULNERABILITY_TOOL,
)
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


# The Investigate summaries (owner, 2026-11-05 and 2026-11-06): one family of rows per screen,
# counted from the current finding table, so they follow every change to open findings (and, for
# misconfigurations, to their reach after a Steampipe run or a re-derive), and a failed run, which
# changes nothing there, needs nothing carried forward. The Overview keeps findings.* (Prowler
# only, from the day's snapshot). The names and the "<value>|<severity>" dimensions are defined
# once by their reader, metrics.summary.
MISCONFIGURATION_METRICS = summary.MISCONFIGURATIONS.metrics
VULNERABILITY_METRICS = summary.VULNERABILITIES.metrics


def _events(
    conn: Connection, family: summary.Family, *, where: str, params: dict[str, object]
) -> dict[tuple[str, str], float]:
    """The day's opened, reopened and resolved findings of a family, by the finding's current
    status and muting (an accepted approximation: not as they were when the event happened)."""
    rows = conn.execute(
        text(f"""
            SELECT e.event, count(*) FROM finding_event e JOIN finding f ON f.id = e.finding_id
            WHERE e.occurred_on = :d AND f.connection_id = :c AND {where}
              AND e.event = ANY(CAST(:kinds AS text[]))
            GROUP BY e.event"""),  # noqa: S608 - fixed fragments only
        {**params, "kinds": list(summary.EVENT_KINDS)},
    )
    return {(family.events, event): float(n) for event, n in rows}


def _misconfiguration_values(
    conn: Connection, connection_id: int, day: date
) -> dict[tuple[str, str], float]:
    values = summary.MISCONFIGURATIONS.zero()
    dim = summary.dimension

    def add(metric: str, dimension: str, n: int) -> None:
        values[(metric, dimension)] = values.get((metric, dimension), 0) + n

    for severity, tool, service, region, categories, first_seen, reach, n in conn.execute(
        text(f"""
            SELECT f.severity, f.tool, coalesce(f.service, ''), f.region, f.categories,
                   f.first_seen, f.reach, count(*)
            FROM finding f
            WHERE f.connection_id = :c AND {OPEN_MISCONFIGURATION}
            GROUP BY 1, 2, 3, 4, 5, 6, 7"""),  # noqa: S608 - a constant only
        {"c": connection_id},
    ):
        add(summary.MISCONFIGURATIONS.open_by_severity, severity, n)
        add(summary.OPEN_BY_TOOL, dim(tool, severity), n)
        add(summary.OPEN_BY_SERVICE, dim(service, severity), n)
        add(summary.OPEN_BY_REGION, dim(region, severity), n)
        add(summary.MISCONFIGURATIONS.open_by_first_seen, dim(first_seen.isoformat(), severity), n)
        # A finding counts once under each of its categories; "" holds the ones with none.
        for category in sorted(set(categories)) or [""]:
            add(summary.OPEN_BY_CATEGORY, dim(category, severity), n)
        if reach is not None:
            add(summary.REACH, dim(reach, severity), n)
    values |= _events(
        conn,
        summary.MISCONFIGURATIONS,
        where="f.tool = ANY(CAST(:tools AS text[])) AND f.status = 'FAIL' AND NOT f.muted",
        params={"d": day, "c": connection_id, "tools": list(MISCONFIGURATION_TOOLS)},
    )
    return values


def _vulnerability_values(
    conn: Connection, connection_id: int, day: date
) -> dict[tuple[str, str], float]:
    values = summary.VULNERABILITIES.zero()
    dim = summary.dimension

    def add(metric: str, dimension: str, n: int) -> None:
        values[(metric, dimension)] = values.get((metric, dimension), 0) + n

    # The fix and exploit buckets are the list's filters: fix=available is YES or PARTIAL,
    # fix=none is NO, exploit=1 a public exploit; a finding without facts is neither.
    for severity, muted, resource_type, region, first_seen, fix, exploit, n in conn.execute(
        text(f"""
            SELECT f.severity, f.muted, coalesce(f.resource_type, ''), f.region, f.first_seen,
                   CASE WHEN v.fix_available IN ('YES', 'PARTIAL') THEN 'available'
                        WHEN v.fix_available = 'NO' THEN 'none' ELSE 'unknown' END,
                   coalesce(v.exploit_available, false), count(*)
            FROM finding f LEFT JOIN finding_vulnerability v ON v.finding_id = f.id
            WHERE f.connection_id = :c AND f.tool = '{VULNERABILITY_TOOL}'
              AND f.state IN ('open', 'reopened')
            GROUP BY 1, 2, 3, 4, 5, 6, 7"""),  # noqa: S608 - a constant only
        {"c": connection_id},
    ):
        if muted:  # suppressed in the scanner: counted apart, left out of everything else
            add(summary.SUPPRESSED_BY_SEVERITY, severity, n)
            continue
        add(summary.VULNERABILITIES.open_by_severity, severity, n)
        add(summary.OPEN_BY_RESOURCE_TYPE, dim(resource_type, severity), n)
        add(summary.VULNERABILITIES_BY_REGION, dim(region, severity), n)
        add(summary.VULNERABILITIES.open_by_first_seen, dim(first_seen.isoformat(), severity), n)
        add(summary.OPEN_BY_FIX, dim(fix, severity), n)
        if exploit:
            add(summary.OPEN_EXPLOITABLE_BY_FIX, dim(fix, severity), n)
    values |= _events(
        conn,
        summary.VULNERABILITIES,
        where=f"f.tool = '{VULNERABILITY_TOOL}' AND NOT f.muted",
        params={"d": day, "c": connection_id},
    )
    return values


def _put_family(
    conn: Connection,
    family: summary.Family,
    *,
    connection_id: int,
    day: date,
    values: dict[tuple[str, str], float],
) -> None:
    """One family's rows for one connection, then all connections.

    The day's events go on the run's day. The counts are the current state, so they go on the
    run's day or the connection's newest counted day, whichever is later: a re-derive of an
    older load, or an older run ingested late, must not leave the newest row stale. All
    connections is then rolled up on those days and on every later day that carried this
    connection's previous counts."""
    latest = summary.latest_counted_day(conn, family, connection_id)
    state_day = max(day, latest) if latest else day
    metrics.put(
        conn,
        day=day,
        connection_id=connection_id,
        values={k: v for k, v in values.items() if k[0] == family.events},
        replace=[family.events],
    )
    metrics.put(
        conn,
        day=state_day,
        connection_id=connection_id,
        values={k: v for k, v in values.items() if k[0] != family.events},
        replace=list(family.state_metrics),
    )
    carried = metrics.carried_days(
        conn, after=state_day, metrics=[family.open_by_severity], connection_id=connection_id
    )
    for rolled in sorted({day, state_day, *carried}):
        # The marker is zero-filled (Family.zero), so it is written every time.
        metrics.rollup_family(conn, day=rolled, metrics=family.metrics, marker=family.marker)


def put_misconfiguration_metrics(conn: Connection, *, connection_id: int, day: date) -> None:
    """The Misconfigurations summary's numbers for one connection after a run that changed its
    findings or their reach (Prowler, CloudFox, a Steampipe run's reach check, a re-derive),
    then all connections."""
    _put_family(
        conn,
        summary.MISCONFIGURATIONS,
        connection_id=connection_id,
        day=day,
        values=_misconfiguration_values(conn, connection_id, day),
    )


def put_vulnerability_metrics(conn: Connection, *, connection_id: int, day: date) -> None:
    """The Vulnerabilities summary's numbers for one connection after a vulnerabilities run,
    then all connections. Vulnerabilities have no reach, so no other run changes them."""
    _put_family(
        conn,
        summary.VULNERABILITIES,
        connection_id=connection_id,
        day=day,
        values=_vulnerability_values(conn, connection_id, day),
    )
