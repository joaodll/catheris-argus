"""What a run left out, and schedules that cover several tools.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-05

From the first real scans (2026-10-05):

- `scan_run.raw_encryption`: the server-side encryption S3 reported for the run's raw output
  (the weakest seen across its objects). Raw output encryption is the operator's choice
  (ADR-0031); the UI flags runs stored without KMS. NULL for the local volume (Demo).
- `scan_run.denied_actions`: the actions the scanning identity was refused (for example
  `ec2:GetLaunchTemplateData`), so the UI can say which data is missing and why.
- `schedule.tools` replaces `schedule.tool`: one schedule queues each of its tools, in tool
  order. The occurrence index gains the tool, or a second tool of the same occurrence would
  collide with the first.

The API's SELECT on scan_run and schedule is table-wide (0001), so no grant changes.
"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE scan_run ADD COLUMN raw_encryption text;
        ALTER TABLE scan_run ADD COLUMN denied_actions text[] NOT NULL DEFAULT '{}';

        ALTER TABLE schedule ADD COLUMN tools text[];
        UPDATE schedule SET tools = ARRAY[tool];
        ALTER TABLE schedule ALTER COLUMN tools SET NOT NULL;
        ALTER TABLE schedule ADD CONSTRAINT schedule_tools_valid CHECK (
          cardinality(tools) BETWEEN 1 AND 3
          AND tools <@ ARRAY['steampipe', 'prowler', 'cloudfox']
          -- No duplicates (a CHECK cannot hold a subquery): each tool at most once.
          AND cardinality(array_positions(tools, 'steampipe')) <= 1
          AND cardinality(array_positions(tools, 'prowler')) <= 1
          AND cardinality(array_positions(tools, 'cloudfox')) <= 1
        );
        ALTER TABLE schedule DROP COLUMN tool;

        DROP INDEX run_request_one_per_occurrence;
        CREATE UNIQUE INDEX run_request_one_per_occurrence
          ON run_request (schedule_id, connection_id, tool, occurrence_at)
          WHERE schedule_id IS NOT NULL AND occurrence_at IS NOT NULL;
        """
    )


def downgrade() -> None:
    # A schedule keeps its first tool; requests that now share an occurrence keep one per
    # connection, the earliest.
    op.execute(
        """
        DELETE FROM run_request r USING run_request e
          WHERE r.schedule_id = e.schedule_id AND r.connection_id = e.connection_id
            AND r.occurrence_at = e.occurrence_at AND r.id > e.id;
        DROP INDEX run_request_one_per_occurrence;
        CREATE UNIQUE INDEX run_request_one_per_occurrence
          ON run_request (schedule_id, connection_id, occurrence_at)
          WHERE schedule_id IS NOT NULL AND occurrence_at IS NOT NULL;

        ALTER TABLE schedule ADD COLUMN tool text
          CHECK (tool IN ('steampipe', 'prowler', 'cloudfox'));
        UPDATE schedule SET tool = tools[1];
        ALTER TABLE schedule ALTER COLUMN tool SET NOT NULL;
        ALTER TABLE schedule DROP COLUMN tools;

        ALTER TABLE scan_run DROP COLUMN denied_actions;
        ALTER TABLE scan_run DROP COLUMN raw_encryption;
        """
    )
