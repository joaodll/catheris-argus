"""What blocked a run outside the role, and why each table was left out (owner, 2026-11-05).

Revision ID: 0042
Revises: 0041
Create Date: 2026-11-05

The first scan of a real estate showed two gaps in what a run records:

- A VPC endpoint policy refused S3, DynamoDB and ECR calls the role allowed, and the Runs page said
  "Missing from the role". `scan_run.blocked_actions` holds the actions refused by a policy outside
  the role: a service or resource control policy, a permissions boundary, a session policy or a VPC
  endpoint policy. Each entry is "<action> (<policy type>)". Like denied_actions, they make the run
  partial; unlike them, the fix is not in the role.
- 41 tables failed and the reason for 29 of them was lost with the run's temporary log.
  `scan_run.table_errors` holds one entry per table the run left out, "<table>: <first error
  line>", redacted and cut to 300 characters by collection. A table name never holds a colon, so
  the first ": " splits the entry.

NOT NULL columns with a constant default: catalog changes only. The grants on scan_run are
table-wide (0001), so none change.
"""

from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE scan_run
          ADD COLUMN blocked_actions text[] NOT NULL DEFAULT '{}',
          ADD COLUMN table_errors text[] NOT NULL DEFAULT '{}'
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE scan_run
          DROP COLUMN table_errors,
          DROP COLUMN blocked_actions
    """)
