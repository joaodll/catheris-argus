"""Flow mode on the Resource map (ADR-0036).

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-09

A flow is everything traffic and events reach from one internet entry: the chain Route53 ->
CloudFront -> API Gateway -> Lambda -> DynamoDB, with its branches. Ingest computes it after the
day's edges; the map reads it by id.

- `flow`: one row per entry and connection (`flow_key` = sha256 of the connection and the
  entry's uid), with first and last seen.
- `flow_shape`: a flow's drawing, stored once per content hash, like `resource_config`: an
  unchanged flow on the next day points to the same shape.
- `flow_step`: a shape's steps in order: source -> target at a column, the edges behind it, and
  for a group step how many targets of one type it stands for. `via_uid` is the role a function
  uses to reach data (RUNS_AS then ACCESSES, drawn as one step).
- `flow_chip`: what a node carries without being a node of the flow: its security groups, its
  role, a WAF.
- `flow_snapshot`: which shape each flow had on a day. Integer ids only, monthly partitions, kept
  like every snapshot table. The two partition functions are replaced to include it.
"""

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

_PARENTS_0013 = (
    "'resource_snapshot', 'edge_snapshot', 'finding_snapshot', "
    "'finding_event', 'compliance_snapshot', 'metric_daily', 'compliance_rollup'"
)
_PARENTS_0019 = _PARENTS_0013 + ", 'flow_snapshot'"


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
    op.execute("""
        CREATE TABLE flow (
          id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          flow_key       bytea NOT NULL UNIQUE CHECK (length(flow_key) = 32),
          connection_id  bigint NOT NULL REFERENCES connection (id),
          entry_uid      text NOT NULL,
          first_seen     date NOT NULL,
          last_seen      date NOT NULL
        );
        CREATE INDEX flow_connection ON flow (connection_id);

        CREATE TABLE flow_shape (
          id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          shape_hash   bytea NOT NULL UNIQUE CHECK (length(shape_hash) = 32),
          reach        text NOT NULL CHECK (reach IN ('open', 'restricted')),
          node_count   integer NOT NULL CHECK (node_count > 0),
          depth        integer NOT NULL CHECK (depth >= 0),
          truncated    boolean NOT NULL,
          created_on   date NOT NULL
        );

        CREATE TABLE flow_step (
          shape_id     bigint NOT NULL REFERENCES flow_shape (id) ON DELETE CASCADE,
          ord          integer NOT NULL,
          col          integer NOT NULL CHECK (col >= 0),
          kind         text NOT NULL CHECK (kind IN ('edge', 'dns', 'uses', 'group')),
          source_uid   text NOT NULL,
          target_uid   text,
          via_uid      text,
          edge_ids     bigint[] NOT NULL,
          group_type   text,
          group_count  integer CHECK (group_count > 0),
          PRIMARY KEY (shape_id, ord),
          CHECK ((kind = 'group') = (group_count IS NOT NULL AND target_uid IS NULL))
        );

        CREATE TABLE flow_chip (
          shape_id     bigint NOT NULL REFERENCES flow_shape (id) ON DELETE CASCADE,
          node_uid     text NOT NULL,
          kind         text NOT NULL CHECK (kind IN ('security_group', 'role', 'waf')),
          chip_uid     text NOT NULL,
          edge_id      bigint NOT NULL,
          PRIMARY KEY (shape_id, node_uid, kind, chip_uid)
        );

        CREATE TABLE flow_snapshot (
          snapshot_date  date NOT NULL,
          flow_id        bigint NOT NULL,
          shape_id       bigint NOT NULL,
          PRIMARY KEY (snapshot_date, flow_id)
        ) PARTITION BY RANGE (snapshot_date);

        GRANT SELECT ON flow, flow_shape, flow_step, flow_chip, flow_snapshot TO argus_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON flow, flow_shape, flow_step, flow_chip,
              flow_snapshot TO argus_worker;
    """)
    op.execute(_functions(_PARENTS_0019))
    op.execute("""
        SELECT argus_ensure_partitions((current_date - interval '7 months')::date,
                                       (current_date + interval '2 months')::date)
    """)


def downgrade() -> None:
    op.execute(_functions(_PARENTS_0013))
    op.execute("DROP TABLE flow_snapshot, flow_chip, flow_step, flow_shape, flow")
