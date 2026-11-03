"""Each account's latest scan, however old: the inventory's loads (owner's decision, 2026-11-01).

Revision ID: 0036
Revises: 0033
Create Date: 2026-11-01

- `resource_load`: one row per connection and day an inventory was loaded, with its resource
  count, written by every Steampipe ingest, even with no resource. `inventory.effective_day` (the
  day a screen shows for an account) reads its newest row on or before the day: a primary-key read.
  Until now it was a max() over `resource_snapshot` within 31 days. Scans may run 15 to 60 days
  apart, and the owner decided that every screen shows each account's latest scan however old.
  Without the 31-day bound, the max() would read back through every monthly partition, past other
  accounts' newer rows, for an account scanned long ago. `edge_load` (migration 0016) does the
  same for edges.
- Backfill:
  - one row per connection and day that has snapshot rows, with their count
  - plus the days of ingested Steampipe runs with no snapshot rows (an account whose resources
    all went away), within the history kept, with 0
  - so an empty load reads as empty, not as the last non-empty day, as `edge_load` records it
- The API reads it (Resources and the map "as of" a day); the worker writes it, and retention
  deletes rows older than the history kept, as for `edge_load`.

Built inside the migration's transaction: one aggregate over the kept snapshots (at most the
history's resource rows), seconds at the budget's 300,000 resources.
"""

from alembic import op

revision = "0036"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE resource_load (
          connection_id  bigint NOT NULL REFERENCES connection (id),
          snapshot_date  date NOT NULL,
          resources      integer NOT NULL CHECK (resources >= 0),
          PRIMARY KEY (connection_id, snapshot_date)
        )
    """)
    op.execute("""
        INSERT INTO resource_load (connection_id, snapshot_date, resources)
        SELECT r.connection_id, s.snapshot_date, count(*)
        FROM resource_snapshot s JOIN resource r ON r.id = s.resource_id
        GROUP BY r.connection_id, s.snapshot_date
    """)
    op.execute("""
        INSERT INTO resource_load (connection_id, snapshot_date, resources)
        SELECT DISTINCT connection_id, snapshot_date, 0 FROM scan_run
        WHERE tool = 'steampipe' AND status IN ('complete', 'partial')
          AND ingested_at IS NOT NULL
          AND snapshot_date >= (SELECT min(snapshot_date) FROM resource_snapshot)
        ON CONFLICT (connection_id, snapshot_date) DO NOTHING
    """)
    op.execute("GRANT SELECT ON resource_load TO argus_api")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON resource_load TO argus_worker")


def downgrade() -> None:
    op.execute("DROP TABLE resource_load")
