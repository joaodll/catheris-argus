"""Test connection: a request the API writes and the worker answers.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-07

An administrator tests a connection (can Argus reach that account?) or the platform identity
(can Argus sign in and write raw output?) from the UI (ADR-0024, amended 2026-10-07). The API
has no route out (ADR-0019), so it queues the test here; the worker runs it within seconds and
writes the result. Only one open test per target: asking again returns the open one.

- caller_arn: who AWS says Argus signed in as (sts:GetCallerIdentity).
- message: what passed or why it failed, redacted by the worker. Plain text: the API never
  reads JSONB.
"""

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE connection_test (
          id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          target         text NOT NULL CHECK (target IN ('connection', 'identity')),
          connection_id  bigint REFERENCES connection (id) ON DELETE CASCADE,
          status         text NOT NULL DEFAULT 'queued'
                           CHECK (status IN ('queued', 'running', 'passed', 'failed')),
          requested_by   text NOT NULL,
          requested_at   timestamptz NOT NULL DEFAULT now(),
          started_at     timestamptz,
          finished_at    timestamptz,
          caller_arn     text CHECK (length(caller_arn) <= 2048),
          message        text CHECK (length(message) <= 2000),
          CHECK ((target = 'connection') = (connection_id IS NOT NULL)),
          CHECK ((status IN ('passed', 'failed')) = (finished_at IS NOT NULL))
        );
        -- One open test per target, however often the button is pressed.
        CREATE UNIQUE INDEX connection_test_one_open
          ON connection_test (target, coalesce(connection_id, 0))
          WHERE status IN ('queued', 'running');
        CREATE INDEX connection_test_queued ON connection_test (requested_at)
          WHERE status = 'queued';

        -- The API asks and reads; only the worker writes a result, so the API cannot record a
        -- test as passed.
        GRANT SELECT, INSERT (target, connection_id, requested_by) ON connection_test
          TO argus_api;
        GRANT SELECT, UPDATE ON connection_test TO argus_worker;
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE connection_test;")
