"""A PDF report's summary shows its accounts' assets by category (reports round set 2, round 1).

Revision ID: 0058
Revises: 0057
Create Date: 2026-11-19

The owner chose to put the Overview's "Assets by category" on every PDF's summary (2026-11-19,
palace decisions/9dc28f56; ADR-0047 section 3a amended). The counts come from the `assets.by_type`
rows of `metric_daily`, at each of the report's accounts' latest inventory day, as the Overview
reads them (metrics.asset_types_of); a report counts nothing itself.

The Kubernetes report Job reads as `argus_reports` (0050). It gets SELECT on `metric_daily`'s
five columns. The grant covers every metric, not only the assets: a column grant cannot narrow
rows, and the rows are daily counts by severity, type, region, check or account that the role
could already count from the findings and resources it reads. No name, configuration, tag or
secret lives in this table. The partitions are read through the parent.

On Docker Compose the worker builds reports as `argus_worker`, which reads it already.
"""

from alembic import op

revision = "0058"
down_revision = "0057"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        GRANT SELECT (snapshot_date, connection_id, metric, dimension, value)
          ON metric_daily TO argus_reports;
    """)


def downgrade() -> None:
    op.execute("""
        REVOKE SELECT (snapshot_date, connection_id, metric, dimension, value)
          ON metric_daily FROM argus_reports;
    """)
