"""Regions are chosen per schedule and per Run now, not once in Settings (owner, 2026-11-19).

Revision ID: 0057
Revises: 0056
Create Date: 2026-11-19

Until now Collection settings held one region list (`aws_regions`, empty meaning every enabled
region) that every AWS run of Prowler, Steampipe and the vulnerability scanner read when it
started. The owner chose to pick regions where a run is asked for instead (palace decisions,
2026-11-19, reversing 2026-10-03's "a region list in Settings"):

- `schedule.aws_regions`: the regions each of the schedule's runs scans.
- `run_request.aws_regions`: the regions this run scans, copied from its schedule by the tick,
  from the Run now form, or from the failed run a retry repeats. The worker reads it when it
  claims the request. Empty, in both: every region enabled in the account, as before.
- The API may write `run_request.aws_regions` and nothing more of it than 0001 and 0046 grant:
  a schedule's edit applies its regions to the runs it still has queued.

Each list holds region names only (the pattern Settings used) and at most 40, so nothing that
could read as a tool flag reaches a command line, whoever writes the row. NULL elements are
refused too: array_to_string would skip them.

Data: the stored setting is copied into every schedule and into every request not finished yet
(queued or running, so a retry of a running one keeps its regions), then removed from the
stored settings, whose model refuses unknown keys. A request that finished before the upgrade
keeps the empty list: the Run now cooldown then reads it as every region, so for at most one
cooldown it may refuse a Run now it would otherwise queue.

Both columns get a constant default, so the ALTER changes the catalog only. The CHECKs scan each
table once under the ALTER's lock: schedules are a handful, and run_request holds one row per
requested run, thousands at most between retention passes.

Downgrade writes the regions back into the stored settings only as an empty list (every region):
which schedule's list would be the one to keep is not knowable, so a downgrade scans every region
until an administrator sets the list again. That loss is accepted.
"""

from alembic import op

revision = "0057"
down_revision = "0056"
branch_labels = None
depends_on = None

_REGION = r"[a-z]{2}(-[a-z]+)+-[0-9]"


def _check(table: str) -> str:
    return f"""
        ALTER TABLE {table}
          ADD COLUMN aws_regions text[] NOT NULL DEFAULT '{{}}',
          ADD CONSTRAINT {table}_aws_regions CHECK (
            cardinality(aws_regions) <= 40
            AND array_position(aws_regions, NULL) IS NULL
            AND (cardinality(aws_regions) = 0
                 OR array_to_string(aws_regions, ' ') ~ '^{_REGION}( {_REGION})*$')
          );
    """


def upgrade() -> None:
    op.execute(_check("schedule") + _check("run_request"))
    op.execute("""
        GRANT UPDATE (aws_regions) ON run_request TO argus_api;

        WITH setting AS (
          SELECT COALESCE(ARRAY(SELECT jsonb_array_elements_text(value -> 'aws_regions')),
                          '{}') AS regions
          FROM platform_setting
          WHERE topic = 'collection' AND jsonb_typeof(value -> 'aws_regions') = 'array'
        )
        UPDATE schedule SET aws_regions = setting.regions FROM setting;

        WITH setting AS (
          SELECT COALESCE(ARRAY(SELECT jsonb_array_elements_text(value -> 'aws_regions')),
                          '{}') AS regions
          FROM platform_setting
          WHERE topic = 'collection' AND jsonb_typeof(value -> 'aws_regions') = 'array'
        )
        UPDATE run_request SET aws_regions = setting.regions FROM setting
        WHERE run_request.status IN ('queued', 'claimed');

        UPDATE platform_setting SET value = value - 'aws_regions'
        WHERE topic = 'collection' AND value ? 'aws_regions';
    """)


def downgrade() -> None:
    op.execute("""
        UPDATE platform_setting SET value = value || '{"aws_regions": []}'::jsonb
        WHERE topic = 'collection';
        REVOKE UPDATE (aws_regions) ON run_request FROM argus_api;
        ALTER TABLE run_request
          DROP CONSTRAINT run_request_aws_regions, DROP COLUMN aws_regions;
        ALTER TABLE schedule DROP CONSTRAINT schedule_aws_regions, DROP COLUMN aws_regions;
    """)
