"""Latent attack paths: a fifth confidence, blocked (ADR-0037, amended 2026-10-21).

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-21

A Restricted door (PUBLIC_RESTRICTED) now seeds the attack-path search. Its paths are what one
change would open, so they take the lowest confidence, blocked, and stay out of the default list
and the Overview's counts.

The CHECK is replaced, not widened in place: PostgreSQL validates the new one against the
existing rows, which all hold one of the four old values.
"""

from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE attack_path DROP CONSTRAINT attack_path_confidence_check;
        ALTER TABLE attack_path ADD CONSTRAINT attack_path_confidence_check
          CHECK (confidence IN ('confirmed', 'supported', 'candidate', 'unknown', 'blocked'))
    """)


def downgrade() -> None:
    op.execute("""
        DELETE FROM attack_path WHERE confidence = 'blocked';
        ALTER TABLE attack_path DROP CONSTRAINT attack_path_confidence_check;
        ALTER TABLE attack_path ADD CONSTRAINT attack_path_confidence_check
          CHECK (confidence IN ('confirmed', 'supported', 'candidate', 'unknown'))
    """)
