"""One-off repairs of stored findings, run by a migration.

remove_compliance_items(): until 2026-10-21 the Prowler adapter also read Prowler's
compliance/<stem>_<framework>.ocsf.json files, which hold one item per finding and requirement
(uid "<finding uid>-<requirement id>", titled with the requirement id) and one "manual-<id>"
item per requirement without checks. Each became a finding. This deletes those rows with their
snapshot and event rows, rebuilds the filter options of the connections they belonged to, and
recomputes the findings metrics of every day they counted in, so the Overview's history is
right again. The check-result metrics (checks.*) of those days counted them too and cannot be
rebuilt without the raw run: they stay as they were until the connection's next Prowler run.
"""

from datetime import date

from sqlalchemy import Connection, text

from argus import metrics
from argus.findings.lifecycle import _refresh_facets
from argus.findings.metrics import ADDITIVE, put_findings_metrics, rollup_findings

# A compliance item shares its finding's check and resource but not its title, and its uid is
# the finding's uid followed by "-<requirement id>". A finding of a resource whose name extends
# another's ("alb" and "alb-2") has the same title, so it is never matched.
_COMPLIANCE_ITEMS_SQL = """
    SELECT f.id FROM finding f
    WHERE f.tool = 'prowler'
      AND (f.check_id = 'manual'
           OR EXISTS (SELECT 1 FROM finding g
                      WHERE g.tool = 'prowler' AND g.id <> f.id
                        AND g.connection_id = f.connection_id
                        AND g.check_id = f.check_id AND g.resource_uid = f.resource_uid
                        AND g.title <> f.title
                        AND starts_with(f.finding_uid, g.finding_uid || '-')))
"""


def remove_compliance_items(conn: Connection) -> int:
    """Returns the number of findings removed."""
    ids = list(conn.execute(text(_COMPLIANCE_ITEMS_SQL)).scalars())
    if not ids:
        return 0
    p = {"ids": ids}
    affected: set[tuple[int, date]] = set()
    for table, column in (("finding_snapshot", "snapshot_date"), ("finding_event", "occurred_on")):
        affected |= {
            (c, d)
            for c, d in conn.execute(
                text(f"""
                    SELECT DISTINCT f.connection_id, t.{column} FROM {table} t
                    JOIN finding f ON f.id = t.finding_id
                    WHERE t.finding_id = ANY(:ids)"""),  # noqa: S608 (fixed names)
                p,
            )
        }
    connection_ids = set(
        conn.execute(
            text("SELECT DISTINCT connection_id FROM finding WHERE id = ANY(:ids)"), p
        ).scalars()
    )
    conn.execute(text("DELETE FROM finding_event WHERE finding_id = ANY(:ids)"), p)
    conn.execute(text("DELETE FROM finding_snapshot WHERE finding_id = ANY(:ids)"), p)
    conn.execute(text("DELETE FROM finding WHERE id = ANY(:ids)"), p)
    for connection_id in connection_ids:
        _refresh_facets(conn, connection_id=connection_id)
    for connection_id, day in sorted(affected):
        put_findings_metrics(conn, connection_id=connection_id, day=day)
    # All connections carries each connection's latest day forward, so the days after one it
    # counted in summed a stale value too.
    days = {d for _, d in affected}
    later = {c for d in days for c in metrics.carried_days(conn, after=d, metrics=ADDITIVE)}
    for day in sorted(later - days):
        rollup_findings(conn, day=day)
    return len(ids)
