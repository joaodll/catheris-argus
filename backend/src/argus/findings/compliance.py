"""Read side of compliance: the framework catalog and one framework's requirements on one day
(Posture → Compliance, docs/ui/screens.md E9, E10).

One connection reads its own compliance_snapshot rows; all connections read compliance_rollup,
which ingest rebuilds per day, so this module never aggregates snapshot rows at request time.
Either way the query reads one day (equality on snapshot_date) of one framework, at most a few
hundred rows.
"""

from dataclasses import dataclass
from datetime import date
from typing import Any, Literal

from sqlalchemy import Connection, text

from argus import metrics
from argus.core.db import like_contains

RequirementStatus = Literal["FAIL", "MANUAL", "PASS"]

# Both views expose the same columns. All connections: a requirement fails when any connection
# fails it, passes when none fails and one passes, and is manual otherwise (the per-connection
# rule in the Prowler adapter, applied across connections).
_ONE = """
  SELECT cr.section, cr.requirement_id, cr.title, cr.description,
         CASE cs.status WHEN 1 THEN 'FAIL' WHEN 2 THEN 'MANUAL' ELSE 'PASS' END AS status,
         cs.passed_checks, cs.failed_checks,
         NULL::integer AS fail_connections, NULL::integer AS assessed_connections
  FROM compliance_snapshot cs
  JOIN compliance_requirement cr ON cr.id = cs.requirement_id
  WHERE cs.snapshot_date = :d AND cs.connection_id = :c AND cr.framework = :f
"""
_ALL = """
  SELECT cr.section, cr.requirement_id, cr.title, cr.description,
         CASE WHEN ro.fail_connections > 0 THEN 'FAIL'
              WHEN ro.pass_connections > 0 THEN 'PASS' ELSE 'MANUAL' END AS status,
         ro.passed_checks, ro.failed_checks, ro.fail_connections,
         ro.fail_connections + ro.manual_connections + ro.pass_connections
           AS assessed_connections
  FROM compliance_rollup ro
  JOIN compliance_requirement cr ON cr.id = ro.requirement_id
  WHERE ro.snapshot_date = :d AND cr.framework = :f
"""
_FILTERS = r"""
  WHERE (CAST(:st AS text) IS NULL OR r.status = :st)
    AND (CAST(:p AS text) IS NULL
         OR (r.requirement_id || E'\n' || coalesce(r.title, '') || E'\n' || r.description)
            ILIKE :p ESCAPE '\')
"""


@dataclass(frozen=True)
class Framework:
    framework: str
    family: str | None
    name: str | None
    version: str
    provider: str


@dataclass(frozen=True)
class RequirementPage:
    items: list[dict[str, Any]]
    total: int


def framework_catalog(conn: Connection) -> dict[str, Framework]:
    """Every framework Argus has results for, by key. A few dozen rows per provider."""
    rows = conn.execute(
        text("SELECT framework, family, name, version, provider FROM compliance_framework")
    )
    return {r.framework: Framework(**r._mapping) for r in rows}


def list_requirements(
    conn: Connection,
    *,
    framework: str,
    connection_id: int,
    day: date,
    status: RequirementStatus | None = None,
    q: str | None = None,
    limit: int,
    offset: int,
) -> RequirementPage:
    """One page of a framework's requirements on `day`, ordered by section, then requirement
    id, both in natural order (1.2 before 1.10)."""
    source = _ALL if connection_id == metrics.ALL_CONNECTIONS else _ONE
    params = {
        "d": day,
        "c": connection_id,
        "f": framework,
        "st": status,
        "p": like_contains(q) if q else None,
    }
    rows = conn.execute(
        text(f"""
        SELECT * FROM ({source}) r {_FILTERS}
        ORDER BY r.section COLLATE argus_natural NULLS LAST,
                 r.requirement_id COLLATE argus_natural
        LIMIT :l OFFSET :o
    """),  # noqa: S608 - constant SQL only
        {**params, "l": limit, "o": offset},
    )
    total = conn.execute(
        text(f"SELECT count(*) FROM ({source}) r {_FILTERS}"),  # noqa: S608 - constant SQL only
        params,
    ).scalar_one()
    return RequirementPage([dict(r._mapping) for r in rows], int(total))
