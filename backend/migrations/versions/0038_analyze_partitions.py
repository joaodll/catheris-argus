"""Ingest can ANALYZE a day's partitions.

Revision ID: 0038
Revises: 0037
Create Date: 2026-11-03

The design says ingest runs ANALYZE after each load, and no code did: autovacuum got to the
partitions some time later, so queries right after a load could be planned on old statistics.

argus_worker does not own the partitions, so like the two partition functions this one runs as the
owner, and only the worker may call it. It is fixed to those seven tables and one month, so the
worker gains no right to ANALYZE anything else. A new partitioned table is added here too, as in
the other two.
"""

from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE FUNCTION argus_analyze_partitions(day date) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
DECLARE
  parent text;
  part text;
  analyzed integer := 0;
BEGIN
  FOREACH parent IN ARRAY ARRAY['resource_snapshot', 'edge_snapshot', 'finding_snapshot',
                                'finding_event', 'compliance_snapshot', 'metric_daily',
                                'compliance_rollup'] LOOP
    part := format('%s_%s', parent, to_char(day, 'YYYYMM'));
    IF to_regclass(part) IS NOT NULL THEN
      EXECUTE format('ANALYZE %I', part);
      analyzed := analyzed + 1;
    END IF;
  END LOOP;
  RETURN analyzed;
END
$fn$;
REVOKE EXECUTE ON FUNCTION argus_analyze_partitions(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION argus_analyze_partitions(date) TO argus_worker;
""")


def downgrade() -> None:
    op.execute("DROP FUNCTION argus_analyze_partitions(date)")
