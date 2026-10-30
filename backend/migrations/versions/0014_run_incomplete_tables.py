"""The Steampipe tables a run left out of its scope.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-08

argus_v8: the inventory collects every configuration table of the plugin (~400, ADR-0012
amended), and completeness is per table. A table that failed, or whose export logged a denied
call or throttling, resolves nothing; every other table of the run is complete.

- `scan_run.incomplete_tables`: those tables, from the manifest, so the Runs page can say which
  types were carried forward instead of updated. Empty for complete runs, for Prowler and
  CloudFox, and for runs before this migration.

A NOT NULL column with a constant default is a catalog change in PostgreSQL 17: no table
rewrite, no long lock. The grants on scan_run are table-wide (0001), so none change.
"""

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE scan_run ADD COLUMN incomplete_tables text[] NOT NULL DEFAULT '{}'")


def downgrade() -> None:
    op.execute("ALTER TABLE scan_run DROP COLUMN incomplete_tables")
