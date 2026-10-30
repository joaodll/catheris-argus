"""The rule set each rule edge load was derived with (ADR-0035, fifth amendment, point 6).

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-21

`edge_load.ruleset`: a SHA-256 (hex) of every relationship rule's and attack-path kind's id
and version, written with each rule load (family 'rule'). When the worker starts, a connection
whose latest rule load has another rule set, or none, is derived again on that day's
inventory, so a rule upgrade shows at once instead of after the next Steampipe and CloudFox
runs. NULL: a load before this migration (re-derived once after the upgrade) or a CloudFox
load (its edges are the tool's, not the rules').

A nullable column without a default: a catalogue change only, no table rewrite.
"""

from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE edge_load ADD COLUMN ruleset text
          CONSTRAINT edge_load_ruleset_check
          CHECK (ruleset IS NULL OR (family = 'rule' AND ruleset ~ '^[0-9a-f]{64}$'))
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE edge_load DROP COLUMN ruleset")
