"""Attack paths across accounts: the search runs over the Memgraph read model (ADR-0044, round
M2, 2026-11-01).

Revision ID: 0035
Revises: 0034
Create Date: 2026-11-01

- `attack_path.connection_ids`: every connection (account) the path passes through, the entry's
  first. `connection_id` stays the entry's: a path belongs to the account where the attacker
  gets in, and is counted once there on the Overview (owner's decision, 2026-10-31). A CHECK
  keeps the two in step. Existing rows were found inside one account: backfilled with
  `ARRAY[connection_id]`. Connections are disabled, never deleted, so an id here always names
  a connection.
- `attack_path_connections` GIN on `connection_ids`: Attack paths "passing through" a
  connection (`connection_ids @> ARRAY[:c]`; GIN serves `@>`, not `= ANY`).
- `attack_path.last_seen_at`: when an evaluation last found the path, set to the evaluating
  transaction's now(). One evaluation covers every connection, so a path is resolved when the
  evaluation that just ran did not find it (`last_seen_at < now()` in the same transaction),
  not when it was last seen on an earlier day: another account's scan earlier the same day
  must not delay a fix to the next day. Backfilled with midnight UTC of `last_seen`; defaults
  to now() (an inserted path was just found).
- `graph_projection.paths_run_id`, `paths_evaluated_at`: the projected run each connection's
  paths were last evaluated from, and when. The API compares them with the connection's newest
  ingested run to say that paths are behind the scans (owner's decision, 2026-11-01). NULL until
  the first evaluation.

attack_path holds at most MAX_PATHS (5000) rows per connection and the worker is its only
writer, so the backfill and the index run inside the migration's transaction, in seconds.
Downgrade drops the columns and the index: the next evaluation of an older release finds the
paths again per connection.
"""

from alembic import op

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE attack_path
          ADD COLUMN connection_ids bigint[],
          ADD COLUMN last_seen_at timestamptz
    """)
    op.execute("""
        UPDATE attack_path
        SET connection_ids = ARRAY[connection_id],
            last_seen_at = last_seen::timestamp AT TIME ZONE 'UTC'
    """)
    op.execute("""
        ALTER TABLE attack_path
          ALTER COLUMN connection_ids SET NOT NULL,
          ALTER COLUMN last_seen_at SET DEFAULT now(),
          ALTER COLUMN last_seen_at SET NOT NULL,
          ADD CONSTRAINT attack_path_connection_ids_check
            CHECK (cardinality(connection_ids) >= 1 AND connection_ids[1] = connection_id)
    """)
    op.execute("CREATE INDEX attack_path_connections ON attack_path USING gin (connection_ids)")
    op.execute("""
        ALTER TABLE graph_projection
          ADD COLUMN paths_run_id bigint,
          ADD COLUMN paths_evaluated_at timestamptz,
          ADD CONSTRAINT graph_projection_paths_check
            CHECK ((paths_run_id IS NULL) = (paths_evaluated_at IS NULL))
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE graph_projection
          DROP CONSTRAINT graph_projection_paths_check,
          DROP COLUMN paths_evaluated_at,
          DROP COLUMN paths_run_id
    """)
    op.execute("DROP INDEX attack_path_connections")
    op.execute("""
        ALTER TABLE attack_path
          DROP CONSTRAINT attack_path_connection_ids_check,
          DROP COLUMN last_seen_at,
          DROP COLUMN connection_ids
    """)
