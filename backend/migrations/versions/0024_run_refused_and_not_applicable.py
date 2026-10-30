"""What a run could not read, told apart (ADR-0012, second amendment).

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-21

A real member account showed three things as one "denied": a service the account does not use,
a resource whose own policy refuses the scanner, and a permission the role lacks. Only the last
is the operator's to fix, and only it (with failures and throttling) makes a run partial.

- `scan_run.refused_actions`: actions a resource's own policy refused, any tool.
- `scan_run.not_applicable_tables`, `scan_run.refused_tables`: Steampipe tables, all also in
  `incomplete_tables` (carried forward), whose errors said the service does not apply here, or
  were a resource's refusal.

NOT NULL columns with a constant default: catalog changes only. The grants on scan_run are
table-wide (0001), so none change.
"""

from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE scan_run
          ADD COLUMN refused_actions text[] NOT NULL DEFAULT '{}',
          ADD COLUMN not_applicable_tables text[] NOT NULL DEFAULT '{}',
          ADD COLUMN refused_tables text[] NOT NULL DEFAULT '{}'
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE scan_run
          DROP COLUMN refused_tables,
          DROP COLUMN not_applicable_tables,
          DROP COLUMN refused_actions
    """)
