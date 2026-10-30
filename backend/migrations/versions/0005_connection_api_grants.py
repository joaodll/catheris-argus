"""The API role can no longer delete connections or read their External ID.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-03

Connections are disabled, never deleted: their history references them (M8 review SA-5).

The External ID is not a secret to AWS, but nothing in the API needs its value: the UI only
shows whether one is set (M8 review SC-3). `external_id_set` is a stored generated column, so
the API reads that fact without any privilege on the value itself. The worker keeps its
table-wide SELECT; it passes the External ID to sts:AssumeRole.
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        REVOKE DELETE ON connection FROM argus_api;
        ALTER TABLE connection ADD COLUMN external_id_set boolean
          GENERATED ALWAYS AS (external_id IS NOT NULL) STORED;
        REVOKE SELECT (external_id) ON connection FROM argus_api;
        GRANT SELECT (external_id_set) ON connection TO argus_api;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE SELECT (external_id_set) ON connection FROM argus_api;
        GRANT SELECT (external_id) ON connection TO argus_api;
        ALTER TABLE connection DROP COLUMN external_id_set;
        GRANT DELETE ON connection TO argus_api;
        """
    )
