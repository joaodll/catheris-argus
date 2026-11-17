"""Resources reports: a third report kind, the Resources list as CSV.

Revision ID: 0054
Revises: 0053
Create Date: 2026-11-17

The owner asked for an export of the Resources list (2026-11-17, palace decisions/156b6e38;
ADR-0047 amended). A Resources report is CSV only: a CHECK refuses a Resources PDF, whatever
the API lets through.

The Kubernetes report Job reads as `argus_reports` (0050). It gets only what the Resources list
and its columns read:
- `resource`: the list's own columns (inventory.list_resources and its search), added to the
  id, name and native_id 0050 granted. Never `tags` or anything of the configuration: the CSV
  has neither, like the other kinds.
- `role_last_used`, `role_workload` (0053): the role-use columns and the Role use and No
  workload filters.
- `vulnerability_coverage` (resource_id, active): the "not scanned" verdict of the
  vulnerabilities cell (findings.scanned_resources).
`finding`, `finding_vulnerability`, `connection` and `scan_run` are already granted (0050).
Nothing on `edge`: workload counts come from `role_workload`.

On Docker Compose the worker builds reports as `argus_worker`, which reads all of these already.

Downgrade deletes the Resources requests first (0048's precedent), so the narrower CHECK holds
again; their files then belong to no report, and the worker's report thread removes them when it
next starts.
"""

from alembic import op

revision = "0054"
down_revision = "0053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE report_request
          DROP CONSTRAINT report_request_kind_check,
          ADD CONSTRAINT report_request_kind_check
            CHECK (kind IN ('misconfigurations', 'vulnerabilities', 'resources')),
          ADD CONSTRAINT report_request_resources_csv
            CHECK (kind <> 'resources' OR format = 'csv');

        -- Beyond 0050's (id, name, native_id); downgrade revokes these only.
        GRANT SELECT (resource_uid, connection_id, provider, region, type, vpc_id,
                      first_seen, last_seen, deleted_on, asset)
          ON resource TO argus_reports;
        GRANT SELECT ON role_last_used, role_workload TO argus_reports;
        GRANT SELECT (resource_id, active) ON vulnerability_coverage TO argus_reports;
    """)


def downgrade() -> None:
    op.execute("""
        REVOKE SELECT (resource_id, active) ON vulnerability_coverage FROM argus_reports;
        REVOKE SELECT ON role_last_used, role_workload FROM argus_reports;
        REVOKE SELECT (resource_uid, connection_id, provider, region, type, vpc_id,
                       first_seen, last_seen, deleted_on, asset)
          ON resource FROM argus_reports;

        DELETE FROM report_request WHERE kind = 'resources';
        ALTER TABLE report_request
          DROP CONSTRAINT report_request_resources_csv,
          DROP CONSTRAINT report_request_kind_check,
          ADD CONSTRAINT report_request_kind_check
            CHECK (kind IN ('misconfigurations', 'vulnerabilities'));
    """)
