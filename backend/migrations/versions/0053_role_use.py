"""Role use: each IAM role's last use and the workloads that run as it, for the Resources list.

Revision ID: 0053
Revises: 0052
Create Date: 2026-11-17

The owner asked to find roles nobody uses (2026-11-17, palace decisions/156b6e38). Two small
tables, one per owning module, each holding the latest value only (no history):

- `role_last_used` (inventory): AWS's own record of the role's last use (IAM RoleLastUsed,
  Steampipe's role_last_used_date and role_last_used_region). The columns stay out of the
  configuration and its hash (inventory.steampipe.VOLATILE), so a role used every day does not
  get a new configuration every day. A null `last_used_at` is AWS saying no use in its tracking
  window (the trailing 400 days), not "never". `observed_on` is the inventory day the value was
  read; the filter's cutoffs count back from it, since scans run every 15 or 30 days. A row is
  written only from a run in which aws_iam_role was complete, so a failed, denied or throttled
  table keeps the previous value. No row: not collected yet ("not covered", never a zero).
- `role_workload` (relationships): how many resources run as the role (RUNS_AS edges of the
  connection's rule load), rewritten for the connection in the same transaction as each rule
  load. No row: no rule load since this revision.

Both are read by resource id, for one page, or scanned whole for a filter: at 300,000 resources
an estate has some thousands of roles, so the primary key is the only index.

No backfill: the raw last-used values were never stored, and the workload counts are written by
the next rule load (a rule-set change re-derives every connection, ingest.rederive).
"""

from alembic import op

revision = "0053"
down_revision = "0052"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE role_last_used (
          resource_id       bigint PRIMARY KEY REFERENCES resource (id) ON DELETE CASCADE,
          last_used_at      timestamptz,
          last_used_region  text CHECK (last_used_region <> ''),
          observed_on       date NOT NULL,
          CHECK (last_used_at IS NOT NULL OR last_used_region IS NULL)
        );

        CREATE TABLE role_workload (
          resource_id    bigint PRIMARY KEY REFERENCES resource (id) ON DELETE CASCADE,
          connection_id  bigint NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
          workloads      integer NOT NULL CHECK (workloads >= 0),
          rule_day       date NOT NULL
        );
        -- A rule load rewrites one connection's rows.
        CREATE INDEX role_workload_connection ON role_workload (connection_id);

        GRANT SELECT ON role_last_used, role_workload TO argus_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON role_last_used, role_workload TO argus_worker;
    """)


def downgrade() -> None:
    op.execute("""
        DROP TABLE role_workload;
        DROP TABLE role_last_used;
    """)
