"""All connections: each account's latest result, not only the accounts scanned that day.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-08

Decided 2026-10-08: connection 0 in metric_daily (all connections) and compliance_rollup take,
for each enabled connection, its latest values on or before the day, at most 31 days old
(metrics.rollup and findings.lifecycle._rollup since this change). Before, a day summed only
the accounts scanned that day, so accounts scanned on different days dropped out of the latest
total. This recomputes every day that has rows, so past charts follow the same rule.

- State metrics: latest per connection, summed. findings.events (what happened that day) is
  summed for the day only, as before.
- compliance.score and threatscore.score are derived again from the summed parts, as
  findings.metrics._derive does: 100 * passed / assessed, 100 * numerator / denominator.
- compliance_rollup: per requirement, over each connection's latest requirement results.

Data only, no schema change. Downgrade recomputes with the previous same-day rule.
"""

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

WINDOW = 31
DERIVED = "ARRAY['compliance.score', 'threatscore.score']"
FLOWS = "ARRAY['findings.events']"


def _rebuild(latest: bool) -> None:
    # Which (connection, metric, day) rows stand for day d: the latest within the window, or,
    # for flows and for the previous rule, day d itself.
    pick = (
        f"""SELECT connection_id, metric,
                   CASE WHEN metric = ANY({FLOWS}) THEN d.day ELSE max(snapshot_date) END AS day
            FROM metric_daily
            WHERE connection_id > 0 AND NOT metric = ANY({DERIVED})
              AND snapshot_date <= d.day AND snapshot_date >= d.day - {WINDOW}
            GROUP BY connection_id, metric"""  # noqa: S608 - constants only
        if latest
        else f"""SELECT DISTINCT connection_id, metric, d.day AS day
            FROM metric_daily
            WHERE connection_id > 0 AND NOT metric = ANY({DERIVED})
              AND snapshot_date = d.day"""  # noqa: S608 - constants only
    )
    enabled = "AND c.enabled" if latest else ""
    op.execute(
        f"""
        CREATE TEMPORARY TABLE rollup_days AS
          SELECT DISTINCT snapshot_date AS day FROM metric_daily WHERE connection_id = 0;
        DELETE FROM metric_daily WHERE connection_id = 0;
        INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
          SELECT d.day, 0, md.metric, md.dimension, sum(md.value)
          FROM rollup_days d
          CROSS JOIN LATERAL ({pick}) l
          JOIN metric_daily md ON md.connection_id = l.connection_id AND md.metric = l.metric
                              AND md.snapshot_date = l.day
          JOIN connection c ON c.id = l.connection_id {enabled}
          GROUP BY d.day, md.metric, md.dimension;
        INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
          SELECT p.snapshot_date, 0,
                 CASE p.metric WHEN 'compliance.passed' THEN 'compliance.score'
                      ELSE 'threatscore.score' END,
                 p.dimension, 100 * p.value / a.value
          FROM metric_daily p
          JOIN metric_daily a ON a.snapshot_date = p.snapshot_date AND a.connection_id = 0
                             AND a.dimension = p.dimension
                             AND a.metric = CASE p.metric
                                              WHEN 'compliance.passed' THEN 'compliance.assessed'
                                              ELSE 'threatscore.denominator' END
          WHERE p.connection_id = 0 AND a.value <> 0
            AND p.metric IN ('compliance.passed', 'threatscore.numerator');

        CREATE TEMPORARY TABLE compliance_days AS
          SELECT DISTINCT snapshot_date AS day FROM compliance_rollup;
        DELETE FROM compliance_rollup;
        INSERT INTO compliance_rollup (snapshot_date, requirement_id, fail_connections,
                                       manual_connections, pass_connections, passed_checks,
                                       failed_checks)
          SELECT d.day, cs.requirement_id,
                 count(*) FILTER (WHERE cs.status = 1), count(*) FILTER (WHERE cs.status = 2),
                 count(*) FILTER (WHERE cs.status = 3), sum(cs.passed_checks),
                 sum(cs.failed_checks)
          FROM compliance_days d
          CROSS JOIN LATERAL (
            SELECT connection_id, max(snapshot_date) AS day FROM compliance_snapshot
            WHERE snapshot_date <= d.day
              AND snapshot_date >= {"d.day - " + str(WINDOW) if latest else "d.day"}
            GROUP BY connection_id) l
          JOIN compliance_snapshot cs ON cs.connection_id = l.connection_id
                                     AND cs.snapshot_date = l.day
          JOIN connection c ON c.id = l.connection_id {enabled}
          GROUP BY d.day, cs.requirement_id;
        DROP TABLE rollup_days, compliance_days;
        """  # noqa: S608 - constants only
    )


def upgrade() -> None:
    _rebuild(latest=True)


def downgrade() -> None:
    _rebuild(latest=False)
