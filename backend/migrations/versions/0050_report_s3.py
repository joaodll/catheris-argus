"""Reports on Kubernetes: the report Job's role, and where an S3 report lives (ADR-0047 round 5).

Revision ID: 0050
Revises: 0049
Create Date: 2026-11-12

- `argus_reports` is the role of the report Job (ADR-0047 §6). It reads what the report's
  exported queries read (findings, their vulnerability facts and check texts, resource names, the
  connection directory and the runs that give each account's data-through) and writes the build's
  columns of `report_request`, as `argus_worker` does on Docker Compose. It can't read a sealed
  credential, the platform identity, a setting, a configuration or the audit log. Like
  `argus_scheduler`, it stays NOLOGIN until migrate is given its password: an install that never
  runs a report Job (Docker Compose) has a role nobody can sign in as.
- `storage_bucket` and `storage_region` record, at request time, the bucket a report on S3 is
  written to and read from. The API sets them from Raw output storage. The Job writes there, the
  download reads from there, and a later settings change can't redirect an old download. A report
  on the local store has neither. Same patterns as Raw output storage (settings/topics.py).
- The scheduler reads `status` and `started_at` to count queued reports and start report Jobs.

Adds two nullable columns without a default to a small table: a catalog change only.
"""

from alembic import op

revision = "0050"
down_revision = "0049"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_reports') THEN
            CREATE ROLE argus_reports NOLOGIN;
          END IF;
        END $$;
        -- A report reads in batches; no single statement should run for minutes. A PDF closes its
        -- read transaction before drawing (reports/build.py), so idle time stays short.
        ALTER ROLE argus_reports SET statement_timeout = '5min';
        ALTER ROLE argus_reports SET idle_in_transaction_session_timeout = '5min';

        GRANT USAGE ON SCHEMA public TO argus_reports;
        GRANT SELECT ON alembic_version TO argus_reports;
        -- connections.DIRECTORY_SQL and nothing else of the table.
        GRANT SELECT (id, name, kind, provider, account_id, enabled) ON connection
          TO argus_reports;
        GRANT SELECT ON finding, finding_vulnerability, finding_check_text TO argus_reports;
        -- inventory.resource_names
        GRANT SELECT (id, name, native_id) ON resource TO argus_reports;
        -- ingest.data_through_by_connection
        GRANT SELECT (connection_id, snapshot_date, tool, status, ingested_at) ON scan_run
          TO argus_reports;
        -- The build's columns, as argus_worker has them (0047).
        GRANT SELECT,
              UPDATE (status, started_at, finished_at, expires_at, file_deleted_at, storage_key,
                      size_bytes, sha256, row_count, truncated, data_through, error)
          ON report_request TO argus_reports;

        ALTER TABLE report_request
          ADD COLUMN storage_bucket text
            CHECK (storage_bucket ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'),
          ADD COLUMN storage_region text CHECK (storage_region ~ '^[a-z]{2}(-[a-z]+)+-[0-9]$'),
          ADD CONSTRAINT report_request_bucket_with_region
            CHECK ((storage_bucket IS NULL) = (storage_region IS NULL));
        GRANT INSERT (storage_bucket, storage_region) ON report_request TO argus_api;

        GRANT SELECT (status, started_at) ON report_request TO argus_scheduler;
    """)


def downgrade() -> None:
    # The role is kept, as 0030 keeps argus_scheduler: it may hold grants in another database.
    op.execute("""
        REVOKE SELECT (status, started_at) ON report_request FROM argus_scheduler;
        ALTER TABLE report_request
          DROP CONSTRAINT report_request_bucket_with_region,
          DROP COLUMN storage_region,
          DROP COLUMN storage_bucket;
        REVOKE ALL ON report_request, scan_run, resource, finding_check_text,
          finding_vulnerability, finding, connection, alembic_version FROM argus_reports;
        REVOKE USAGE ON SCHEMA public FROM argus_reports;
    """)
