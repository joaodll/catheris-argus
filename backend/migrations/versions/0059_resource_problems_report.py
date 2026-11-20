"""The by-resource report: a resource's misconfigurations and vulnerabilities together.

Revision ID: 0059
Revises: 0058
Create Date: 2026-11-20

The owner asked for a resource's misconfigurations and vulnerabilities in one report (2026-11-19,
palace decisions/9dc28f56; ADR-0047 section 3d). It is a fourth kind, `resource-problems`, shown
as "Misconfigurations and vulnerabilities": the Resources list's filters choose the resources,
and each one's open misconfigurations and open CVEs are listed with it, as a CSV (a row per
problem) or a PDF (a block per resource). CHECKs hold the pairs whatever writes the row: the kind
is a CSV or a PDF; JSON Lines stays a Resources report's (0056).

No grant: `argus_reports` already reads what the kind reads (`finding`, `finding_vulnerability`,
`finding_check_text` since 0050, `resource_tag` since 0051, the resource's list columns since 0054,
`metric_daily` since 0058).

Downgrade deletes these requests first (0054's precedent), so the narrower CHECK holds again;
their files then belong to no report, and the worker's report thread removes them when it next
starts.
"""

from alembic import op

revision = "0059"
down_revision = "0058"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE report_request
          DROP CONSTRAINT report_request_kind_check,
          ADD CONSTRAINT report_request_kind_check
            CHECK (kind IN ('misconfigurations', 'vulnerabilities', 'resources',
                            'resource-problems')),
          ADD CONSTRAINT report_request_resource_problems_format
            CHECK (kind <> 'resource-problems' OR format IN ('csv', 'pdf'));
    """)


def downgrade() -> None:
    op.execute("""
        DELETE FROM report_request WHERE kind = 'resource-problems';
        ALTER TABLE report_request
          DROP CONSTRAINT report_request_resource_problems_format,
          DROP CONSTRAINT report_request_kind_check,
          ADD CONSTRAINT report_request_kind_check
            CHECK (kind IN ('misconfigurations', 'vulnerabilities', 'resources'));
    """)
