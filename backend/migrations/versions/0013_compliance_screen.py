"""Posture → Compliance: framework names, and requirement status across all connections.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-07

The Compliance screen lists every Prowler framework and, per framework, its requirements
(decided by the user, 2026-10-07; docs/ui/screens.md E9, E10).

- compliance_framework: one row per framework key (`cis_6.0_aws`), with the name and family
  Prowler writes in its compliance CSV (NAME, FRAMEWORK). Ingest upserts it; frameworks
  loaded before this migration get their key alone, and their name on the next Prowler run.
- compliance_rollup: per day and requirement, how many connections fail, need a manual check
  or pass it, and the checks summed. Ingest rebuilds a day after each Prowler load, so "All
  connections" reads one day of pre-aggregated rows: the API never aggregates snapshot rows
  (CLAUDE.md, Queries). Integer ids only, partitioned by month like every snapshot table.
- argus_natural: an ICU collation with numeric ordering, so requirement 1.2 sorts before 1.10
  and section "2. Attack Surface" before "10. ...".
- Two indexes on metric_daily. Its key leads with the date, so a six-month read of one
  connection scanned whole partitions: fine with a dozen metrics, not with real Prowler, which
  writes six rows per framework a day for about 40 frameworks (the query budget found the
  Overview at 1.4 s). metric_daily_by_connection serves the Overview and the Compliance pages
  (one connection, named metrics and, for one framework, named dimensions, a date range);
  metric_daily_by_metric serves the accounts panel (one metric and dimension, every
  connection).
- The two partition functions are replaced to include compliance_rollup.
- Existing days are backfilled, so the screen works before the next run.
"""

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

_PARENTS_0001 = (
    "'resource_snapshot', 'edge_snapshot', 'finding_snapshot', "
    "'finding_event', 'compliance_snapshot', 'metric_daily'"
)
_PARENTS_0013 = _PARENTS_0001 + ", 'compliance_rollup'"


def _functions(parents: str) -> str:
    return f"""
CREATE OR REPLACE FUNCTION argus_ensure_partitions(from_date date, to_date date)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
DECLARE
  parent text;
  month_start date;
  created integer := 0;
  part text;
BEGIN
  FOREACH parent IN ARRAY ARRAY[{parents}] LOOP
    month_start := date_trunc('month', from_date)::date;
    WHILE month_start <= to_date LOOP
      part := format('%s_%s', parent, to_char(month_start, 'YYYYMM'));
      IF to_regclass(part) IS NULL THEN
        EXECUTE format(
          'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
          part, parent, month_start, (month_start + interval '1 month')::date
        );
        created := created + 1;
      END IF;
      month_start := (month_start + interval '1 month')::date;
    END LOOP;
  END LOOP;
  RETURN created;
END
$fn$;

CREATE OR REPLACE FUNCTION argus_drop_partitions_before(cutoff date) RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
DECLARE
  rec record;
BEGIN
  FOR rec IN
    SELECT c.relname AS part
    FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_class p ON p.oid = i.inhparent
    WHERE p.relname IN ({parents})
      AND c.relname ~ '_[0-9]{{6}}$'
      AND (to_date(right(c.relname, 6), 'YYYYMM') + interval '1 month')::date <= cutoff
  LOOP
    EXECUTE format('DROP TABLE %I', rec.part);
    RETURN NEXT rec.part;
  END LOOP;
END
$fn$;
"""  # noqa: S608 - the table list is a constant of this file


def upgrade() -> None:
    op.execute(
        """
        CREATE COLLATION IF NOT EXISTS argus_natural (provider = icu, locale = 'und-u-kn');

        CREATE TABLE compliance_framework (
          framework   text PRIMARY KEY CHECK (length(framework) <= 200),
          family      text CHECK (length(family) <= 200),
          name        text CHECK (length(name) <= 500),
          version     text NOT NULL DEFAULT '',
          provider    text NOT NULL
        );
        INSERT INTO compliance_framework (framework, version, provider)
        SELECT DISTINCT ON (framework) framework, framework_version,
               CASE WHEN position('_' IN framework) > 0
                    THEN regexp_replace(framework, '^.*_', '') ELSE '' END
        FROM compliance_requirement ORDER BY framework, framework_version DESC;

        CREATE TABLE compliance_rollup (
          snapshot_date       date NOT NULL,
          requirement_id      bigint NOT NULL REFERENCES compliance_requirement (id),
          fail_connections    integer NOT NULL CHECK (fail_connections >= 0),
          manual_connections  integer NOT NULL CHECK (manual_connections >= 0),
          pass_connections    integer NOT NULL CHECK (pass_connections >= 0),
          passed_checks       integer NOT NULL CHECK (passed_checks >= 0),
          failed_checks       integer NOT NULL CHECK (failed_checks >= 0),
          PRIMARY KEY (snapshot_date, requirement_id)
        ) PARTITION BY RANGE (snapshot_date);

        CREATE INDEX metric_daily_by_connection
          ON metric_daily (connection_id, metric, dimension, snapshot_date);
        CREATE INDEX metric_daily_by_metric ON metric_daily (metric, dimension, snapshot_date);
        """
    )
    op.execute(_functions(_PARENTS_0013))
    op.execute(
        """
        SELECT argus_ensure_partitions(
          least((current_date - interval '7 months')::date,
                coalesce((SELECT min(snapshot_date) FROM compliance_snapshot), current_date)),
          (current_date + interval '2 months')::date);

        INSERT INTO compliance_rollup (snapshot_date, requirement_id, fail_connections,
                                       manual_connections, pass_connections, passed_checks,
                                       failed_checks)
        SELECT snapshot_date, requirement_id,
               count(*) FILTER (WHERE status = 1), count(*) FILTER (WHERE status = 2),
               count(*) FILTER (WHERE status = 3), sum(passed_checks), sum(failed_checks)
        FROM compliance_snapshot GROUP BY snapshot_date, requirement_id;

        GRANT SELECT ON compliance_framework, compliance_rollup TO argus_api;
        GRANT SELECT, INSERT, UPDATE ON compliance_framework TO argus_worker;
        GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_rollup TO argus_worker;
        """
    )


def downgrade() -> None:
    op.execute(_functions(_PARENTS_0001))
    op.execute(
        """
        DROP INDEX metric_daily_by_connection, metric_daily_by_metric;
        DROP TABLE compliance_rollup, compliance_framework;
        DROP COLLATION IF EXISTS argus_natural;
        """
    )
