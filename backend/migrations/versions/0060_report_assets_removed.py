"""A PDF report no longer shows its accounts' assets: the report role stops reading metric_daily.

Revision ID: 0060
Revises: 0059
Create Date: 2026-11-20

The owner removed "Assets by category" from every PDF (2026-11-20, palace decisions/81e03621;
ADR-0047 section 3a amended). 0058 gave `argus_reports` SELECT on `metric_daily` for that block
alone, and nothing else the role builds reads the table, so the grant goes: the Kubernetes report
Job reads only what a report prints.

Downgrade gives the grant back, as 0058 wrote it.
"""

from alembic import op

revision = "0060"
down_revision = "0059"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        REVOKE SELECT (snapshot_date, connection_id, metric, dimension, value)
          ON metric_daily FROM argus_reports;
    """)


def downgrade() -> None:
    op.execute("""
        GRANT SELECT (snapshot_date, connection_id, metric, dimension, value)
          ON metric_daily TO argus_reports;
    """)
