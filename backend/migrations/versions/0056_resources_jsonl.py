"""Resources with links and configuration: a JSON Lines format of the Resources report.

Revision ID: 0056
Revises: 0055
Create Date: 2026-11-19

The owner asked to export what a resource's panel shows, its links and its configuration, and
the linked resources' configuration too (2026-11-19, palace decisions/bf984633; ADR-0047 amended,
section 3c). It is a second format of the `resources` kind, `jsonl` (a gzip-compressed JSON
Lines file); the CSV of 0054 is unchanged. CHECKs hold the pairs whatever writes the row: a
Resources report is CSV or JSON Lines, and JSON Lines is a Resources report only. Its key ends
`.jsonl` (0048's report_request_key_matches_format: a key ends in its format), though the file is
gzip-compressed; the download names it `.jsonl.gz`.

The Kubernetes report Job reads as `argus_reports` (0050, 0054). It gets only what the panel reads
for a resource, by batch:
- the configuration at each account's standing inventory day: `resource_load` (the day),
  `resource_snapshot` (the day's config id), `resource_config` (the redacted configuration;
  never `config_hash` or `created_on`, which nothing here reads);
- the links at each account's standing edge loads: `edge_load`, `edge_snapshot`, and `edge`'s
  columns the panel lists. Never `author` or `reason` (a manual edge's note), `edge_key`,
  `created_at` or `stale`.
Grants on the partitioned snapshot tables cover their partitions: the Job reads through the
parent only. Still never `resource.tags` (the configuration holds its own masked copy of a
table's tags column, as the panel shows it).

On Docker Compose the worker builds reports as `argus_worker`, which reads all of these already.

Downgrade deletes the JSON Lines requests first (0054's precedent), so the narrower CHECKs hold
again; their files then belong to no report, and the worker's report thread removes them when it
next starts.
"""

from alembic import op

revision = "0056"
down_revision = "0055"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE report_request
          DROP CONSTRAINT report_request_format_check,
          ADD CONSTRAINT report_request_format_check CHECK (format IN ('csv', 'pdf', 'jsonl')),
          DROP CONSTRAINT report_request_storage_key_check,
          ADD CONSTRAINT report_request_storage_key_check
            CHECK (storage_key ~ '^reports/[0-9]+-[0-9a-f]{32}\\.(csv|pdf|jsonl)$'),
          DROP CONSTRAINT report_request_resources_csv,
          ADD CONSTRAINT report_request_resources_format
            CHECK (kind <> 'resources' OR format IN ('csv', 'jsonl')),
          ADD CONSTRAINT report_request_jsonl_resources
            CHECK (format <> 'jsonl' OR kind = 'resources');

        GRANT SELECT (connection_id, snapshot_date) ON resource_load TO argus_reports;
        GRANT SELECT (snapshot_date, resource_id, config_id) ON resource_snapshot TO argus_reports;
        GRANT SELECT (id, config) ON resource_config TO argus_reports;
        GRANT SELECT (connection_id, family, snapshot_date) ON edge_load TO argus_reports;
        GRANT SELECT (snapshot_date, edge_id) ON edge_snapshot TO argus_reports;
        GRANT SELECT (id, source_uid, target_uid, source_resource_id, target_resource_id, type,
                      origin, attributes, first_seen, last_seen)
          ON edge TO argus_reports;
    """)


def downgrade() -> None:
    op.execute("""
        REVOKE SELECT (id, source_uid, target_uid, source_resource_id, target_resource_id, type,
                       origin, attributes, first_seen, last_seen)
          ON edge FROM argus_reports;
        REVOKE SELECT (snapshot_date, edge_id) ON edge_snapshot FROM argus_reports;
        REVOKE SELECT (connection_id, family, snapshot_date) ON edge_load FROM argus_reports;
        REVOKE SELECT (id, config) ON resource_config FROM argus_reports;
        REVOKE SELECT (snapshot_date, resource_id, config_id) ON resource_snapshot
          FROM argus_reports;
        REVOKE SELECT (connection_id, snapshot_date) ON resource_load FROM argus_reports;

        DELETE FROM report_request WHERE format = 'jsonl';
        ALTER TABLE report_request
          DROP CONSTRAINT report_request_jsonl_resources,
          DROP CONSTRAINT report_request_resources_format,
          ADD CONSTRAINT report_request_resources_csv
            CHECK (kind <> 'resources' OR format = 'csv'),
          DROP CONSTRAINT report_request_storage_key_check,
          ADD CONSTRAINT report_request_storage_key_check
            CHECK (storage_key ~ '^reports/[0-9]+-[0-9a-f]{32}\\.(csv|pdf)$'),
          DROP CONSTRAINT report_request_format_check,
          ADD CONSTRAINT report_request_format_check CHECK (format IN ('csv', 'pdf'));
    """)
