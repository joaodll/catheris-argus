"""Graph projection: what the Memgraph read model holds for each connection (ADR-0044,
2026-10-31).

Revision ID: 0034
Revises: 0033
Create Date: 2026-10-31

- graph_projection: one row per connection whose current state is in Memgraph, written by the
  graph sync (argus_worker) after each Memgraph transaction. It is the version marker of the read
  model: the latest ingested run and the rule set the connection was projected from, the days
  each edge family and the inventory stood on, how many nodes and edges went in, and a checksum
  of what went in, which the integrity check compares with what Memgraph returns.
  `status` is `synced` or `failed` (a sync that raised, or drift found by the integrity check
  until the connection is re-synced); `error` is redacted before it is written.
- The API may read it, to say "as of" for graph answers; it never writes it.

Downgrade drops the table; Memgraph is rebuilt from Postgres on the next start of the sync.
"""

from alembic import op

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE graph_projection (
          connection_id  bigint PRIMARY KEY REFERENCES connection (id) ON DELETE CASCADE,
          source_run_id  bigint,
          ruleset        text NOT NULL,
          rule_day       date,
          cloudfox_day   date,
          resource_day   date,
          node_count     integer NOT NULL CHECK (node_count >= 0),
          edge_count     integer NOT NULL CHECK (edge_count >= 0),
          checksum       bytea NOT NULL CHECK (length(checksum) = 32),
          status         text NOT NULL CHECK (status IN ('synced', 'failed')),
          error          text,
          synced_at      timestamptz NOT NULL DEFAULT now(),
          CHECK ((status = 'failed') = (error IS NOT NULL))
        );
        GRANT SELECT ON graph_projection TO argus_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON graph_projection TO argus_worker;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE graph_projection")
