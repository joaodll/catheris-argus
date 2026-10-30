"""The command each run executed, and the lookup from a run to the request that started it.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-07

The Runs page says what started a run and what it ran (argus_v7, 2026-10-07). Before this,
runs that started after a schedule was disabled showed no hint of why they ran.

- scan_run.command: the tool's command line as the worker ran it, taken from the manifest. It
  holds no credential (the tools read them from a private profile). Runs from before this
  migration keep '' and the page says the command was not recorded. A constant default is
  metadata-only on PostgreSQL 17: no table rewrite.
- run_request_scan_run: the Runs page reads the trigger of the 20 runs on a page with
  `scan_run_id = ANY(:ids)`. Without it, that is a sequential scan of every request ever made.
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE scan_run ADD COLUMN command text NOT NULL DEFAULT ''
          CHECK (length(command) <= 1000);
        CREATE INDEX run_request_scan_run ON run_request (scan_run_id)
          WHERE scan_run_id IS NOT NULL;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX run_request_scan_run;
        ALTER TABLE scan_run DROP COLUMN command;
        """
    )
