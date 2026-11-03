"""The Resource map, Attack paths and Memgraph leave the product (ADR-0045, 2026-11-03).

Revision ID: 0039
Revises: 0038
Create Date: 2026-11-03

The owner's decision of 2026-11-03. Nothing reads or writes these any more, so this revision:
- drops `attack_path` and `graph_projection`
- deletes the `attack_paths.*` rows from `metric_daily`, the only metrics no screen reads
- takes back the TEMPORARY privilege 0038 gave `argus_worker` by name: its staged table was the
  only temporary table in the code

What is lost: path history, which began on 2026-11-01, and the metric rows. `attack_path` held no
human-entered data (no mute, no accepted risk), and `graph_projection` only described Memgraph,
which is gone. Edges stay: reach verdicts and the Resources panel read them.

The metric rows are few (a handful per connection and day) and only the worker writes them, so
the delete runs inside the migration's transaction, in seconds.

The downgrade recreates both tables empty, in the shape they had at 0038, with their grants, and
returns the privilege. It can't restore the rows: an older release's next evaluation finds the
paths again from the edges, and its graph sync rebuilds `graph_projection`.
"""

from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def _on_database(statement: str) -> None:
    op.execute(f"""
        DO $$ BEGIN
          EXECUTE format('{statement}', current_database());
        END $$
    """)


def upgrade() -> None:
    op.execute("DROP TABLE attack_path, graph_projection")
    op.execute("DELETE FROM metric_daily WHERE metric LIKE 'attack_paths.%'")
    _on_database("REVOKE TEMPORARY ON DATABASE %I FROM argus_worker")


def downgrade() -> None:
    _on_database("GRANT TEMPORARY ON DATABASE %I TO argus_worker")
    op.execute("""
        CREATE TABLE attack_path (
          id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          path_id          bytea NOT NULL UNIQUE CHECK (length(path_id) = 32),
          rule_id          text NOT NULL,
          rule_version     integer NOT NULL,
          category         text NOT NULL,
          severity         text NOT NULL
                             CHECK (severity IN ('critical', 'high', 'medium', 'low',
                                                 'informational')),
          connection_id    bigint NOT NULL REFERENCES connection (id),
          entry_uid        text NOT NULL,
          target_uid       text NOT NULL,
          node_uids        text[] NOT NULL,
          edge_ids         bigint[] NOT NULL,
          state            text NOT NULL CHECK (state IN ('open', 'resolved')),
          first_seen       date NOT NULL,
          last_seen        date NOT NULL,
          resolved_on      date,
          base_severity    text
                             CHECK (base_severity IN ('critical', 'high', 'medium', 'low',
                                                      'informational')),
          entry_confirmed  boolean,
          has_failing      boolean,
          confidence       text
                             CHECK (confidence IN ('confirmed', 'supported', 'candidate',
                                                   'unknown', 'blocked')),
          connection_ids   bigint[] NOT NULL,
          CHECK ((state = 'resolved') = (resolved_on IS NOT NULL)),
          CONSTRAINT attack_path_connection_ids_check
            CHECK (cardinality(connection_ids) >= 1 AND connection_ids[1] = connection_id)
        );
        CREATE INDEX attack_path_connection_state ON attack_path (connection_id, state);
        CREATE INDEX attack_path_nodes ON attack_path USING gin (node_uids);
        CREATE INDEX attack_path_connections ON attack_path USING gin (connection_ids);
        GRANT SELECT ON attack_path TO argus_api;
        GRANT SELECT, INSERT, UPDATE ON attack_path TO argus_worker;

        CREATE TABLE graph_projection (
          connection_id       bigint PRIMARY KEY REFERENCES connection (id) ON DELETE CASCADE,
          source_run_id       bigint,
          ruleset             text NOT NULL,
          rule_day            date,
          cloudfox_day        date,
          resource_day        date,
          node_count          integer NOT NULL CHECK (node_count >= 0),
          edge_count          integer NOT NULL CHECK (edge_count >= 0),
          checksum            bytea NOT NULL CHECK (length(checksum) = 32),
          status              text NOT NULL CHECK (status IN ('synced', 'failed')),
          error               text,
          synced_at           timestamptz NOT NULL DEFAULT now(),
          paths_run_id        bigint,
          paths_evaluated_at  timestamptz,
          CHECK ((status = 'failed') = (error IS NOT NULL)),
          CONSTRAINT graph_projection_paths_check
            CHECK ((paths_run_id IS NULL) = (paths_evaluated_at IS NULL))
        );
        GRANT SELECT ON graph_projection TO argus_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON graph_projection TO argus_worker;
    """)
