"""The scheduler's own database role (ADR-0039).

Revision ID: 0030
Revises: 0029
Create Date: 2026-10-24

On Kubernetes the scheduler is the one process that can start Jobs. It never runs work, so it
gets only what its loop needs: tick schedules into run requests, release lost claims, cancel
what a disabled schedule queued, expire Test connection requests, and count claimable work. It
cannot read a connection's sealed secret or ExternalId, the sealed platform identity, or any
scanned data. Compose leaves the role without LOGIN: there the worker does the same work as
argus_worker.

The app roles may read alembic_version, so a process can wait for the schema its image expects
(`migrate --wait`) under its own role, never the owner's.
"""

from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_scheduler') THEN
            CREATE ROLE argus_scheduler NOLOGIN;
          END IF;
        END $$;
        ALTER ROLE argus_scheduler SET statement_timeout = '30s';
        ALTER ROLE argus_scheduler SET idle_in_transaction_session_timeout = '60s';

        GRANT USAGE ON SCHEMA public TO argus_scheduler;
        -- connections.DIRECTORY_SQL and nothing else of the table.
        GRANT SELECT (id, name, kind, provider, account_id, enabled) ON connection
          TO argus_scheduler;
        GRANT SELECT ON schedule, schedule_connection TO argus_scheduler;
        GRANT SELECT (topic, value) ON platform_setting TO argus_scheduler;
        GRANT SELECT, INSERT ON run_request TO argus_scheduler;
        GRANT UPDATE (status, claimed_by, claimed_at, heartbeat_at, finished_at, error, lost)
          ON run_request TO argus_scheduler;
        -- Expiry of tests no Job answered (connections.checks.expire_tests) and their count.
        GRANT SELECT (id, status, requested_at, started_at) ON connection_test
          TO argus_scheduler;
        GRANT UPDATE (status, finished_at, message) ON connection_test TO argus_scheduler;

        GRANT SELECT ON alembic_version TO argus_api, argus_worker, argus_scheduler;
        """
    )


def downgrade() -> None:
    # The role is kept, as 0001 keeps the others: it may hold grants in another database.
    op.execute(
        """
        REVOKE SELECT ON alembic_version FROM argus_api, argus_worker, argus_scheduler;
        REVOKE ALL ON connection_test, run_request, platform_setting, schedule,
          schedule_connection, connection FROM argus_scheduler;
        REVOKE USAGE ON SCHEMA public FROM argus_scheduler;
        """
    )
