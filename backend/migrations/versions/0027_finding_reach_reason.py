"""Why Argus gives a finding its reach (ADR-0035, sixth amendment).

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-22

`finding.reach` (migrations 0018 and 0020) now covers Prowler's exposure checks as well as
CloudFox's public endpoints. `finding.reach_reason` says why, as a code the UI puts in words:
the door's own reason (`not_running`, `nacl_blocks`, `no_internet_route`, `no_public_address`,
`sg_no_public_source`, ...), `no_door` (a Prowler exposure finding on a resource the internet
rules judged and gave no door) or `not_in_inventory` (on a resource they had nothing of). NULL
when the door gives no reason, and on every finding without a reach.

A nullable column without a default: a catalogue change, no rewrite. The check constraint
scans the table once under the ALTER's lock to validate it; every row is NULL, so it passes.

`finding_reach`, partial on the findings that have a reach, serves the Findings list's Reach
filter. Without it, a filter that matches few findings (an account with no disagreement) walks
every finding in severity order: 1.05 s, 400,000 rows removed, on the budget estate. Only
CloudFox's public endpoints and Prowler's exposure checks are in it, so other writes pay
nothing.
"""

from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE finding ADD COLUMN reach_reason text
          CONSTRAINT finding_reach_reason_check
          CHECK (reach_reason IS NULL
                 OR (reach IS NOT NULL AND reach_reason ~ '^[a-z][a-z0-9_]{0,63}$'));
        CREATE INDEX finding_reach ON finding (reach, connection_id) WHERE reach IS NOT NULL;
    """)


def downgrade() -> None:
    op.execute("""
        DROP INDEX finding_reach;
        ALTER TABLE finding DROP COLUMN reach_reason;
    """)
