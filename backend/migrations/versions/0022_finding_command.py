"""CloudFox's loot commands, shown on a finding and the resource sheet (ADR-0038).

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-14

CloudFox's loot files hold the commands a person would run to follow up what it found. Argus
shows them, labelled and never run (ADR-0038). A command belongs to the resource it names,
keyed by `resource_uid` (and the connection that owns that uid, ADR-0034). `resource_id` is the
resolved inventory row when there is one; a command whose resource is not in the inventory keeps
it NULL and the reference is recorded in `unresolved_ref` by the loader.

This is current state, not history: a complete CloudFox run replaces its connection's rows
(delete then insert in one transaction), and a failed or partial run changes nothing. So there
is no snapshot table and no first/last seen. Reads are always for one `resource_uid`, so that
column is indexed; the per-connection replace is indexed on `connection_id`.

`label` is the adapter's classification: a read-only check, a command that reads data, or one
that acts on the target (the fail-closed default). `source` is the loot file the command came
from; `note` keeps CloudFox's own comment lines (its warnings included); `ordinal` orders the
commands of one resource as the files list them.
"""

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE finding_command (
          id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          connection_id  bigint NOT NULL REFERENCES connection (id),
          resource_uid   text NOT NULL,
          resource_id    bigint REFERENCES resource (id),
          label          text NOT NULL
                           CHECK (label IN ('check', 'reads_data', 'acts_on_target')),
          command        text NOT NULL,
          note           text,
          source         text NOT NULL,
          ordinal        integer NOT NULL CHECK (ordinal >= 0),
          scan_run_id    bigint NOT NULL REFERENCES scan_run (id)
        );
        -- Reads are per resource_uid (a finding's resource, the sheet's resource).
        CREATE INDEX finding_command_resource ON finding_command (resource_uid);
        -- A complete run deletes its connection's rows before inserting the fresh set.
        CREATE INDEX finding_command_connection ON finding_command (connection_id);

        GRANT SELECT ON finding_command TO argus_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON finding_command TO argus_worker;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE finding_command")
