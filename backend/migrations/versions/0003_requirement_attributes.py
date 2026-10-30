"""Compliance requirements carry the attributes ThreatScore is computed from.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-02

Prowler's ThreatScore (api/src/backend/tasks/jobs/threatscore.py at 5.44.0) weights each
requirement's pass rate by its level of risk and weight, and groups scores by section (the
pillars on the Overview). Storing those once per requirement lets metrics compute ThreatScore
per connection and across all of them from compliance_snapshot, for any past day.

compliance_requirement is still empty when this runs, so the new columns need no backfill.
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE compliance_requirement
          ADD COLUMN title text,
          ADD COLUMN section text,
          ADD COLUMN level_of_risk smallint CHECK (level_of_risk BETWEEN 0 AND 5),
          ADD COLUMN weight smallint CHECK (weight >= 0);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE compliance_requirement
          DROP COLUMN weight, DROP COLUMN level_of_risk, DROP COLUMN section, DROP COLUMN title;
        """
    )
