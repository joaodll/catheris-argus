"""A running request can be asked to stop (owner, 2026-11-09).

Revision ID: 0046
Revises: 0045
Create Date: 2026-11-09

Until now only a queued request could be cancelled: the API moved it to `cancelled` itself. A
claimed one is some worker's, so the API cannot end it. It records the ask instead, and the
worker that holds the claim sees it on its next heartbeat, stops the tool and ends the request
as `cancelled`:

- `cancel_requested_at`, `cancel_requested_by`: both set or both NULL. Who asked is kept on the
  row so the run can say it without reading the audit log (which the worker cannot).
- The API may write these two columns and nothing more of a claimed request: its grant from
  0001 stays `status` and `finished_at`.
- The scheduler's reaper ends a lost claim that was asked to stop as `cancelled` instead of
  queueing it again. It reads the columns (its SELECT is on the table) and writes `status` and
  `finished_at`, which 0030 already grants.

Both columns are nullable with no default: the ALTER changes the catalog only. The CHECK scans
the table once under the ALTER's lock; run_request holds one row per requested run, thousands at
most between retention passes.

Downgrade drops the columns. A request asked to stop at that moment is no longer told to: it
runs to its end.
"""

from alembic import op

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE run_request
          ADD COLUMN cancel_requested_at timestamptz,
          ADD COLUMN cancel_requested_by text,
          ADD CONSTRAINT run_request_cancel_requested CHECK (
            (cancel_requested_at IS NULL) = (cancel_requested_by IS NULL)
          );
        GRANT UPDATE (cancel_requested_at, cancel_requested_by) ON run_request TO argus_api;
    """)


def downgrade() -> None:
    op.execute("""
        REVOKE UPDATE (cancel_requested_at, cancel_requested_by) ON run_request FROM argus_api;
        ALTER TABLE run_request
          DROP CONSTRAINT run_request_cancel_requested,
          DROP COLUMN cancel_requested_at,
          DROP COLUMN cancel_requested_by;
    """)
