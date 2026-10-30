"""How sure Argus is of an attack path (ADR-0037).

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-10

One search replaces the attack-path rules: from every internet entry, the shortest chain of
attacker steps to what matters. Each step has a confidence (confirmed, supported, candidate,
unknown) and a path takes its weakest step's. Paths found by the old rules keep NULL until
they are resolved by the first complete evaluation after this change.
"""

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE attack_path ADD COLUMN confidence text
          CHECK (confidence IN ('confirmed', 'supported', 'candidate', 'unknown'))
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE attack_path DROP COLUMN confidence")
