"""Temporary access keys: a sealed session token next to the sealed secret.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-05

A temporary key (ASIA..., from SSO or STS) only works with its session token (ADR-0024). The
token is sealed like the secret, at the same moment and so under the same key: the row's
`secret_key_id` covers both. The API role keeps no SELECT on either table's sealed columns
(its grants are per column, 0001), so the new columns are unreadable to it without any grant
here; the worker reads them through its table-wide SELECT.
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE connection ADD COLUMN session_token_ciphertext bytea;
        ALTER TABLE connection ADD CONSTRAINT connection_session_token_needs_access_key CHECK (
          session_token_ciphertext IS NULL
          OR (auth_method = 'access_key' AND secret_ciphertext IS NOT NULL)
        );
        ALTER TABLE platform_setting ADD COLUMN session_token_ciphertext bytea;
        ALTER TABLE platform_setting ADD CONSTRAINT platform_setting_session_token_needs_secret
          CHECK (session_token_ciphertext IS NULL OR secret_ciphertext IS NOT NULL);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE platform_setting DROP COLUMN session_token_ciphertext;
        ALTER TABLE connection DROP COLUMN session_token_ciphertext;
        """
    )
