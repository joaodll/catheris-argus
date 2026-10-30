"""Run requests count how often their claim was lost (ADR-0039).

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-24

The reaper requeues a claim whose heartbeat stopped. A run that kills its worker (out of
memory, a pod evicted or past its deadline) was requeued forever, killing a worker each time.
`lost` counts those requeues; at two the run ends as a failed run with the reason, and is not
run again. `attempt` is not reused: it counts retries of failed runs, is checked 1 to 3, and
picks the retry delay.
"""

from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE run_request ADD COLUMN lost smallint NOT NULL DEFAULT 0 CHECK (lost >= 0)"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE run_request DROP COLUMN lost")
