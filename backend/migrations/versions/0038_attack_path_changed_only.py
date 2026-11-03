"""Attack paths: an evaluation writes only what changed (ADR-0044, amended 2026-11-02).

Revision ID: 0038
Revises: 0037
Create Date: 2026-11-02

- `attack_path.last_seen_at` goes. It existed so resolve could tell which open paths the running
  evaluation had found, which rewrote every path on every evaluation. Resolve now compares with a
  staged table of the paths kept, in the same transaction.
- `argus_worker` gets TEMPORARY on the database by name: that staged table needs it, and until now
  the role had it only through PUBLIC's default, which a hardened install may revoke.

The cap (MAX_PATHS) no longer bounds rows per connection: it limits new rows, and every path found
that has a row stays. Rows per connection are bounded by what the evaluation finds (0035's note is
history).

Nothing unique is lost: `last_seen` keeps the day. The downgrade restores the column from it, as
0035 backfilled it, and returns the privilege to PUBLIC's default.
"""

from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def _on_database(statement: str) -> None:
    op.execute(f"""
        DO $$ BEGIN
          EXECUTE format('{statement}', current_database());
        END $$
    """)


def upgrade() -> None:
    op.execute("ALTER TABLE attack_path DROP COLUMN last_seen_at")
    _on_database("GRANT TEMPORARY ON DATABASE %I TO argus_worker")


def downgrade() -> None:
    _on_database("REVOKE TEMPORARY ON DATABASE %I FROM argus_worker")
    op.execute("ALTER TABLE attack_path ADD COLUMN last_seen_at timestamptz")
    op.execute("UPDATE attack_path SET last_seen_at = last_seen::timestamp AT TIME ZONE 'UTC'")
    op.execute("""
        ALTER TABLE attack_path
          ALTER COLUMN last_seen_at SET DEFAULT now(),
          ALTER COLUMN last_seen_at SET NOT NULL
    """)
