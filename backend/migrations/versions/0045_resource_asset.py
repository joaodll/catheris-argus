"""Whether a resource counts as an asset, stored; and an index on the day it was removed.

Revision ID: 0045
Revises: 0044
Create Date: 2026-11-06

The Resources list gains filters that reproduce the Resources summary's numbers (owner's
decisions 2026-11-06, round 3 of the Investigate summaries):

- **`resource.asset`**, a stored generated column: the Overview counts asset types only
  (inventory.is_asset: parts, settings and links are stored and searchable, not counted), and the
  list's Assets only filter must keep exactly those. Evaluated per row in a query, the predicate
  (13 names and a suffix regex) cost about 450 ms of a count at 300,000 resources (the budget,
  2026-11-06); stored, it is a boolean read. It depends on the type alone, which never changes,
  so it is computed once per row.
  The expression is is_asset() as of this revision, written out: a migration never imports
  application code. `tests/ingest/test_steampipe_any_table.py` checks the column against
  is_asset() for every collected table, so a change to NON_ASSET_TYPES or NON_ASSET_SUFFIXES fails
  until a new migration changes this expression (ALTER COLUMN ... SET EXPRESSION).
- **`resource_removed`**, a partial index on `deleted_on`: the Removed filter (the summary's
  weekly removed bars) keeps few rows, which the list's name order otherwise found by walking the
  whole name index (about 550 ms at 300,000).

Adding a stored column rewrites `resource` under an exclusive lock: a few seconds at 300,000 rows,
in the migrate step, before the API and worker start. Downgrade drops both.
"""

from alembic import op

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None

# inventory.is_asset() on 2026-11-06 (NON_ASSET_TYPES, NON_ASSET_SUFFIXES).
_ASSET = """
  type <> ALL (ARRAY[
    'aws_account_alternate_contact', 'aws_account_contact', 'aws_api_gateway_method',
    'aws_api_gatewayv2_integration', 'aws_api_gatewayv2_route',
    'aws_ec2_load_balancer_listener_rule', 'aws_ec2_managed_prefix_list_entry',
    'aws_ec2_regional_settings', 'aws_ec2_transit_gateway_route', 'aws_iam_access_key',
    'aws_kms_key_rotation', 'aws_vpc_route', 'aws_vpc_security_group_rule'])
  AND type !~ ('(_attachment|_association|_association_authorization|_settings|_setting'
                '|_configuration|_options|_member|_permission|_version)$')
"""


def upgrade() -> None:
    op.execute(
        f"ALTER TABLE resource ADD COLUMN asset boolean GENERATED ALWAYS AS ({_ASSET}) STORED"
    )
    op.execute(
        "CREATE INDEX resource_removed ON resource (deleted_on) WHERE deleted_on IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX resource_removed")
    op.execute("ALTER TABLE resource DROP COLUMN asset")
