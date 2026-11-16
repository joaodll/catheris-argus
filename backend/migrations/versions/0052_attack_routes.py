"""Attack paths as stored routes (ADR-0052): the route tables, and the `paths` role.

Revision ID: 0052
Revises: 0051
Create Date: 2026-11-15

One row per (kind, entry) in `route`, with First seen and Last seen only (owner, 2026-11-15:
no event table). Its worst LIST_N targets are `route_target` rows, each carrying its own steps
as parallel plain arrays: a step that is an edge names it, and a step the walk makes (a
foothold, a cross-account link, an authentication step) has no edge and is stored whole.
Arrays, not JSONB, because the API never reads JSONB; arrays, not a step table, because a
target's steps are always read and written together, so one row per target keeps the write the
size W3.2 measured. `route_node` lists the resources on the listed targets' steps, for "routes
through this resource" (an index read). `route_evaluation` records each evaluation: when, which
loads, how it ended (ADR-0052 §9 M2).

`crossed_connection_ids` is every connection any target found crosses, listed or not, the
entry's first (§9 H1): the resolve rule checks each of them.

Roles (§9 M1):
- `argus_paths` is the `paths` Job's role on Kubernetes. It reads the edges, the inventory's
  ids, names and types (never a configuration), the runs, the findings and vulnerability facts
  a step reads, and three columns of the connection directory; it writes the route tables only.
  NOLOGIN until migrate is given its password, as argus_reports.
- `argus_worker` writes the route tables too: the Compose worker's paths thread (ADR-0052 §1).
- `argus_api` reads them; `argus_reports` gets nothing (§9 L2).
- `argus_scheduler` reads no scan data (tests/scheduling/test_job.py). It decides whether an
  evaluation is due from `argus_route_inputs()`, a hash of the inputs a walk reads (each
  connection's enabled flag, its latest edge loads with their rule set, its newest ingested run
  of each tool), and the last `route_evaluation`. SECURITY DEFINER, so the hash is all a caller
  learns; the worker and the paths Job compute the evaluation's digest with the same function.

New tables only: no lock on an existing table.
"""

from alembic import op

revision = "0052"
down_revision = "0051"
branch_labels = None
depends_on = None

SEVERITIES = "'informational', 'low', 'medium', 'high', 'critical'"
CLASSES = "'confirmed', 'conditional', 'potential', 'unknown', 'blocked'"
LEVELS = "'blocked', 'unknown', 'candidate', 'supported', 'confirmed'"
ROUTE_TABLES = "route, route_target, route_node, route_evaluation"


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE route_evaluation (
          id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          started_at      timestamptz NOT NULL DEFAULT now(),
          finished_at     timestamptz,
          status          text NOT NULL DEFAULT 'running'
                            CHECK (status IN ('running', 'complete', 'failed')),
          -- sha256 over the loads it read (edge loads with their ruleset, the newest runs).
          loads_digest    bytea,
          -- The newest load it read: "routes are behind the scans since ..." compares with it.
          newest_load_at  timestamptz,
          routes          integer,
          opened          integer,
          resolved        integer,
          error           text,
          CHECK ((status = 'running') = (finished_at IS NULL))
        );
        CREATE INDEX route_evaluation_recent ON route_evaluation (started_at DESC, id DESC);

        CREATE TABLE route (
          id                      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          kind                    text NOT NULL CHECK (kind ~ '^[a-z0-9][a-z0-9-]*$'),
          entry_uid               text NOT NULL,
          entry_resource_id       bigint REFERENCES resource (id) ON DELETE SET NULL,
          connection_id           bigint NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
          crossed_connection_ids  bigint[] NOT NULL,
          severity                text NOT NULL CHECK (severity IN ({SEVERITIES})),
          worst_class             text NOT NULL CHECK (worst_class IN ({CLASSES})),
          target_count            integer NOT NULL CHECK (target_count >= 1),
          listed_count            integer NOT NULL
                                    CHECK (listed_count BETWEEN 1 AND target_count),
          first_seen              date NOT NULL,
          last_seen               date NOT NULL,
          resolved_on             date,
          state                   text NOT NULL CHECK (state IN ('open', 'reopened', 'resolved')),
          digest                  bytea NOT NULL,
          UNIQUE (kind, entry_uid),
          CHECK ((state = 'resolved') = (resolved_on IS NOT NULL)),
          CHECK (crossed_connection_ids[1] = connection_id)
        );
        -- The list: open or fixed, one connection or all, worst first.
        CREATE INDEX route_by_connection ON route (connection_id, state);
        -- "Include routes that cross it".
        CREATE INDEX route_crossing ON route USING gin (crossed_connection_ids);

        CREATE TABLE route_target (
          route_id            bigint NOT NULL REFERENCES route (id) ON DELETE CASCADE,
          seq                 smallint NOT NULL CHECK (seq >= 1),
          target_uid          text NOT NULL,
          target_resource_id  bigint REFERENCES resource (id) ON DELETE SET NULL,
          severity            text NOT NULL CHECK (severity IN ({SEVERITIES})),
          class               text NOT NULL CHECK (class IN ({CLASSES})),
          likelihood          text NOT NULL CHECK (likelihood IN ('higher', 'lower', 'unknown')),
          -- One element per step, in order. edge_id is null for a step the walk made.
          step_type           text[] NOT NULL,
          step_source_uid     text[] NOT NULL,
          step_target_uid     text[] NOT NULL,
          step_source_id      bigint[] NOT NULL,
          step_target_id      bigint[] NOT NULL,
          step_edge_id        bigint[] NOT NULL,
          step_origin         text[] NOT NULL,
          step_connection_id  bigint[] NOT NULL,
          step_day            date[] NOT NULL,
          step_level          text[] NOT NULL,
          step_reason         text[] NOT NULL,
          -- An evidence reference, never a value: a CVE id, or the edge ids a walk-time step
          -- joined ("123/456").
          step_ref            text[] NOT NULL,
          PRIMARY KEY (route_id, seq),
          CHECK (cardinality(step_type) BETWEEN 1 AND 16),
          CHECK (cardinality(step_source_uid) = cardinality(step_type)
             AND cardinality(step_target_uid) = cardinality(step_type)
             AND cardinality(step_source_id) = cardinality(step_type)
             AND cardinality(step_target_id) = cardinality(step_type)
             AND cardinality(step_edge_id) = cardinality(step_type)
             AND cardinality(step_origin) = cardinality(step_type)
             AND cardinality(step_connection_id) = cardinality(step_type)
             AND cardinality(step_day) = cardinality(step_type)
             AND cardinality(step_level) = cardinality(step_type)
             AND cardinality(step_reason) = cardinality(step_type)
             AND cardinality(step_ref) = cardinality(step_type)),
          CHECK (step_level <@ ARRAY[{LEVELS}]::text[])
        );

        CREATE TABLE route_node (
          route_id     bigint NOT NULL REFERENCES route (id) ON DELETE CASCADE,
          resource_id  bigint NOT NULL REFERENCES resource (id) ON DELETE CASCADE,
          PRIMARY KEY (route_id, resource_id)
        );
        CREATE INDEX route_node_by_resource ON route_node (resource_id);

        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_paths') THEN
            CREATE ROLE argus_paths NOLOGIN;
          END IF;
        END $$;
        -- One evaluation is one REPEATABLE READ transaction: reads, then the walk in Python
        -- (idle in the transaction), then the write. Sized from R1's 300k measurement.
        ALTER ROLE argus_paths SET statement_timeout = '10min';
        ALTER ROLE argus_paths SET idle_in_transaction_session_timeout = '15min';

        GRANT USAGE ON SCHEMA public TO argus_paths;
        GRANT SELECT ON alembic_version TO argus_paths;
        -- connections: is an account scanned (ADR-0052 §6 A3), and its id. Never a credential.
        GRANT SELECT (id, account_id, enabled) ON connection TO argus_paths;
        -- relationships.EFFECTIVE_EDGES_SQL and the loads.
        GRANT SELECT ON edge, edge_snapshot, edge_load TO argus_paths;
        -- inventory: ids, uids, names and types on a day, never a configuration or tags (L3).
        GRANT SELECT (id, resource_uid, connection_id, type, name, deleted_on) ON resource
          TO argus_paths;
        GRANT SELECT (snapshot_date, resource_id) ON resource_snapshot TO argus_paths;
        GRANT SELECT ON resource_load TO argus_paths;
        -- ingest.NEWEST_RUNS_SQL
        GRANT SELECT (id, connection_id, tool, snapshot_date, status, ingested_at) ON scan_run
          TO argus_paths;
        -- The kinds' targets (env-var secrets, data exposure), the footholds (a public exploit,
        -- IMDSv1).
        GRANT SELECT (id, connection_id, tool, check_id, resource_uid, resource_id, severity,
                      state, muted, status) ON finding TO argus_paths;
        GRANT SELECT (finding_id, vulnerability_id, exploit_available) ON finding_vulnerability
          TO argus_paths;
        GRANT SELECT, INSERT, UPDATE, DELETE ON {ROUTE_TABLES} TO argus_paths;

        GRANT SELECT, INSERT, UPDATE, DELETE ON {ROUTE_TABLES} TO argus_worker;
        GRANT SELECT ON {ROUTE_TABLES} TO argus_api;

        -- What an evaluation reads, as one hash: the due check compares it with the last one's.
        CREATE FUNCTION argus_route_inputs() RETURNS bytea
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
          SELECT sha256(convert_to(coalesce(string_agg(x, ';' ORDER BY x), ''), 'UTF8'))
          FROM (
            SELECT format('C%s,%s', id, enabled) AS x FROM connection
            UNION ALL
            (SELECT DISTINCT ON (connection_id, family)
                    format('L%s,%s,%s,%s', connection_id, family, snapshot_date, ruleset)
             FROM edge_load ORDER BY connection_id, family, snapshot_date DESC)
            UNION ALL
            (SELECT DISTINCT ON (connection_id, tool)
                    format('R%s,%s,%s,%s', connection_id, tool, id, status)
             FROM scan_run
             WHERE ingested_at IS NOT NULL AND status IN ('complete', 'partial')
             ORDER BY connection_id, tool, id DESC)
          ) inputs
        $fn$;
        REVOKE ALL ON FUNCTION argus_route_inputs() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION argus_route_inputs()
          TO argus_scheduler, argus_worker, argus_paths;
        GRANT SELECT ON route_evaluation TO argus_scheduler;
    """)  # noqa: S608 - constants only


def downgrade() -> None:
    # The role is kept, as 0050 keeps argus_reports: it may hold grants in another database.
    op.execute("""
        DROP FUNCTION argus_route_inputs();
        REVOKE ALL ON finding_vulnerability, finding, scan_run, resource_load, resource_snapshot,
          resource, edge_load, edge_snapshot, edge, connection, alembic_version FROM argus_paths;
        REVOKE USAGE ON SCHEMA public FROM argus_paths;
        DROP TABLE route_node, route_target, route, route_evaluation;
    """)
