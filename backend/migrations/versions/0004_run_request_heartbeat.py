"""Run requests carry a heartbeat, so a dead worker's claim is released.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-02

run_request_one_claimed_per_connection allows one claimed request per connection. Without a
heartbeat, a worker killed mid-run would hold its claim forever and that account would never
be collected again, silently (catheris-lutur-access hit exactly this with its single-in-flight
constraint). The worker refreshes heartbeat_at while a run executes; a reaper releases claims
whose heartbeat is stale. `error` records why a request ended without a usable run.
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE run_request ADD COLUMN heartbeat_at timestamptz;
        ALTER TABLE run_request ADD COLUMN error text;
        -- The reaper: claimed requests ordered by how long ago they last showed life.
        CREATE INDEX run_request_claimed_heartbeat ON run_request (heartbeat_at)
          WHERE status = 'claimed';
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX run_request_claimed_heartbeat;
        ALTER TABLE run_request DROP COLUMN error;
        ALTER TABLE run_request DROP COLUMN heartbeat_at;
        """
    )
