"""Role use: each IAM role's creation date beside its last use.

Revision ID: 0055
Revises: 0054
Create Date: 2026-11-18

AWS records no use of a role in two cases: an old role not used in its tracking window (the
trailing 400 days), and a new role never used. Argus said "Not used in 400 days" for both
(review 2026-11-18, palace reviews/1383eadafdb6). The owner chose to tell them apart and to keep
new roles in the Role use filter (palace decisions, 2026-11-18).

`role_last_used.created_at` is the role's creation date (IAM CreateDate, Steampipe's
aws_iam_role.create_date). It is in the role's configuration already, but the API never reads
a configuration (JSONB is read by rules inside ingest only), so ingest writes it here with the
last use, from a complete role table only. Null: not read yet.

Backfill: every row from its role's current configuration, in this transaction. A few thousand
roles at 300,000 resources; the configuration is found by the resource's config_id. A value that
is not an ISO timestamp with a zone is left null rather than failing the migration. The next
Steampipe run writes every role's value anyway.
"""

from alembic import op

revision = "0055"
down_revision = "0054"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(r"""
        ALTER TABLE role_last_used ADD COLUMN created_at timestamptz;

        UPDATE role_last_used rl
        SET created_at = CAST(rc.config ->> 'create_date' AS timestamptz)
        FROM resource r JOIN resource_config rc ON rc.id = r.config_id
        WHERE r.id = rl.resource_id
          AND rc.config ->> 'create_date'
              ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$';
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE role_last_used DROP COLUMN created_at")
