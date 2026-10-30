"""The Resource map and Attack paths screens (ADR-0033).

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-08

- `edge_load`: one row per connection, edge family (our rules, CloudFox) and day an edge
  snapshot was loaded, with its edge count. `relationships.effective_days` read the latest
  day from `edge_snapshot` itself: a max() over every snapshot row of the connection in the
  31-day window, about 30,000 edges x 31 days per account, once per connection the map
  touches. It is now a primary-key range read. A load with no edges is recorded too, so an
  account whose edges all went away shows none instead of the last non-empty day. Backfilled
  from `edge_snapshot`.
- `edge (source_uid)`, `edge (target_uid)`: the map walks the graph by uid, because the
  pseudo-nodes (`internet`, `admin:<account>`, `external:<host>`) and resources of another
  account have no `resource_id`. The existing indexes on the resource ids stay for the
  resource sheet.
- `attack_path (node_uids)` GIN: "attack paths through this resource" (`node_uids @> {uid}`).
- `attack_path.base_severity`, `entry_confirmed`, `has_failing`: why a path has its severity
  (the rule's level, raised when the entry is confirmed, lowered when nothing on the path
  fails), shown on the path page. NULL for paths not evaluated since this migration; the next
  CloudFox ingest fills them.

The indexes are built inside the migration's transaction (not CONCURRENTLY): edge and
attack_path hold thousands of rows per account, built in seconds, and the worker is the only
writer.
"""

from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE edge_load (
          connection_id  bigint NOT NULL REFERENCES connection (id),
          family         text NOT NULL CHECK (family IN ('rule', 'cloudfox')),
          snapshot_date  date NOT NULL,
          edges          integer NOT NULL CHECK (edges >= 0),
          PRIMARY KEY (connection_id, family, snapshot_date)
        )
    """)
    op.execute("""
        INSERT INTO edge_load (connection_id, family, snapshot_date, edges)
        SELECT e.connection_id,
               CASE WHEN starts_with(e.origin, 'rule:') THEN 'rule' ELSE 'cloudfox' END,
               s.snapshot_date, count(*)
        FROM edge_snapshot s JOIN edge e ON e.id = s.edge_id
        WHERE e.origin = 'cloudfox' OR starts_with(e.origin, 'rule:')
        GROUP BY 1, 2, 3
    """)
    op.execute("GRANT SELECT ON edge_load TO argus_api")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON edge_load TO argus_worker")
    op.execute("CREATE INDEX edge_source_uid ON edge (source_uid)")
    op.execute("CREATE INDEX edge_target_uid ON edge (target_uid)")
    op.execute("""
        ALTER TABLE attack_path
          ADD COLUMN base_severity text
            CHECK (base_severity IN ('critical', 'high', 'medium', 'low', 'informational')),
          ADD COLUMN entry_confirmed boolean,
          ADD COLUMN has_failing boolean
    """)
    op.execute("CREATE INDEX attack_path_nodes ON attack_path USING gin (node_uids)")


def downgrade() -> None:
    op.execute("DROP INDEX attack_path_nodes")
    op.execute(
        "ALTER TABLE attack_path DROP COLUMN base_severity, DROP COLUMN entry_confirmed, "
        "DROP COLUMN has_failing"
    )
    op.execute("DROP INDEX edge_target_uid")
    op.execute("DROP INDEX edge_source_uid")
    op.execute("DROP TABLE edge_load")
