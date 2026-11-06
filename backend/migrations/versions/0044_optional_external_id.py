"""An assume-role connection may have no ExternalId (owner, 2026-11-05, ADR-0024 amended).

Revision ID: 0044
Revises: 0043
Create Date: 2026-11-05

A role that trusts Argus's platform identity without an ExternalId condition can now be a
connection. The CHECK from 0001 required one; this one still requires the role ARN and no stored
access-key secret. `external_id_set` (0005) already reads false when the column is NULL, and the
grants on the column do not change.

The table holds one row per connection: replacing the constraint is a short lock.

Downgrade restores the old CHECK. It fails while an assume-role connection without an ExternalId
exists: give it one or disable and remove it first. That is deliberate: dropping the rows would
lose the history that references them.
"""

from alembic import op

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE connection
          DROP CONSTRAINT connection_assume_role_fields,
          ADD CONSTRAINT connection_assume_role_fields CHECK (
            auth_method <> 'assume_role'
            OR (role_arn IS NOT NULL AND secret_ciphertext IS NULL)
          )
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE connection
          DROP CONSTRAINT connection_assume_role_fields,
          ADD CONSTRAINT connection_assume_role_fields CHECK (
            auth_method <> 'assume_role'
            OR (role_arn IS NOT NULL AND external_id IS NOT NULL AND secret_ciphertext IS NULL)
          )
    """)
