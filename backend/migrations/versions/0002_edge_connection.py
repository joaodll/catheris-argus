"""Edges record the connection whose data produced them.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-02

Re-ingesting a day replaces that day's derived edges for one connection. Without the
connection on the edge, the replacement could not be scoped: a role trust can point from
another account into this one, so neither endpoint identifies the producing connection.
Manual edges (later phases) keep the column NULL: they belong to no collection run.

The edge table is empty when this runs (no ingest existed before it), so the NOT NULL check
needs no backfill.
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE edge ADD COLUMN connection_id bigint REFERENCES connection (id);
        ALTER TABLE edge ADD CONSTRAINT edge_connection_unless_manual
          CHECK ((origin = 'manual') = (connection_id IS NULL));
        -- Replacing a day's edges: the edges this connection's rules or CloudFox produced.
        CREATE INDEX edge_connection_origin ON edge (connection_id, origin);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX edge_connection_origin;
        ALTER TABLE edge DROP CONSTRAINT edge_connection_unless_manual;
        ALTER TABLE edge DROP COLUMN connection_id;
        """
    )
