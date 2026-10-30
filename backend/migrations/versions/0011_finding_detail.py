"""What a finding says about its resource, and what each check says about itself.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-07

The Findings page showed a title and the remediation text only (argus_v7, 2026-10-07). Prowler
also says, for each result, what is wrong with that resource (status_extended), and, for each
check, what it evaluates, the risk, more links, and remediation code (CLI, CloudFormation,
Terraform, console steps).

- finding.detail: Prowler's status_extended (OCSF `message`), redacted by ingest. NULL for
  CloudFox and for findings not seen since this migration.
- finding.resource_name: the name the tool reported for the resource. The page prefers the
  inventory's name and falls back to this one when the resource is not in the inventory.
- finding_check_text: one row per (tool, check_id), replaced by every load of that tool. The
  text is the same for every result of a check, so it is stored once, not on each of the
  finding rows that share it. Plain text columns, not JSONB: the API never reads JSONB (CLAUDE.md,
  Queries). `links` holds http(s) URLs only; ingest drops anything else.

The API reads finding_check_text only for one finding at a time (its primary key), so it
needs no other index.
"""

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE finding
          ADD COLUMN detail        text CHECK (length(detail) <= 4000),
          ADD COLUMN resource_name text CHECK (length(resource_name) <= 1000);

        CREATE TABLE finding_check_text (
          tool            text NOT NULL CHECK (tool IN ('prowler', 'cloudfox')),
          check_id        text NOT NULL,
          tool_version    text NOT NULL,
          description     text CHECK (length(description) <= 20000),
          risk            text CHECK (length(risk) <= 20000),
          links           text[] NOT NULL DEFAULT '{}' CHECK (cardinality(links) <= 20),
          code_cli        text CHECK (length(code_cli) <= 20000),
          code_native_iac text CHECK (length(code_native_iac) <= 20000),
          code_terraform  text CHECK (length(code_terraform) <= 20000),
          code_other      text CHECK (length(code_other) <= 20000),
          notes           text CHECK (length(notes) <= 20000),
          updated_at      timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (tool, check_id)
        );

        GRANT SELECT ON finding_check_text TO argus_api;
        GRANT SELECT, INSERT, UPDATE ON finding_check_text TO argus_worker;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE finding_check_text;
        ALTER TABLE finding DROP COLUMN resource_name, DROP COLUMN detail;
        """
    )
