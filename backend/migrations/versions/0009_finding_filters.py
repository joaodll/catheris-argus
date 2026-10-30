"""Service, resource type and categories on findings, for the Findings filters.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-07

The Findings page filters like Prowler App (2026-10-07): by service, resource type, category
and check, for Prowler and CloudFox findings alike. Prowler's OCSF carries the first three; the
CloudFox adapter tags its findings with the same vocabulary. They are plain columns, because the
API never reads JSONB.

Backfill: a Prowler check id starts with its service (`s3_bucket_...`, `awslambda_...`), so
existing Prowler rows get it now. Resource type and categories arrive with each finding's next
scan; a resolved finding that never returns keeps them empty, and the filter options leave
empty values out.

finding_facet holds each connection's filter options (regions, services, resource types,
categories, checks), rebuilt by ingest after every findings load. Reading them with DISTINCT
over the finding table took a second on 400,000 findings, four times the query budget; this
table has a few hundred rows per connection. Findings are never deleted, so a load is the only
time the options change.
"""

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE finding
          ADD COLUMN service       text,
          ADD COLUMN resource_type text,
          ADD COLUMN categories    text[] NOT NULL DEFAULT '{}';

        UPDATE finding SET service = split_part(check_id, '_', 1) WHERE tool = 'prowler';

        CREATE INDEX finding_service ON finding (service);
        CREATE INDEX finding_resource_type ON finding (resource_type);
        CREATE INDEX finding_check ON finding (check_id);
        CREATE INDEX finding_categories ON finding USING gin (categories);

        CREATE TABLE finding_facet (
          connection_id  bigint NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
          facet          text NOT NULL
                           CHECK (facet IN ('region', 'service', 'resource_type', 'category',
                                            'check')),
          tool           text NOT NULL CHECK (tool IN ('prowler', 'cloudfox')),
          value          text NOT NULL,
          PRIMARY KEY (connection_id, facet, tool, value)
        );
        INSERT INTO finding_facet (connection_id, facet, tool, value)
        SELECT DISTINCT f.connection_id, v.facet, f.tool, v.value
        FROM finding f,
             LATERAL (VALUES ('region', f.region), ('service', f.service),
                             ('resource_type', f.resource_type),
                             ('check', f.check_id)) v(facet, value)
        WHERE v.value IS NOT NULL;
        GRANT SELECT ON finding_facet TO argus_api;
        GRANT SELECT, INSERT, DELETE ON finding_facet TO argus_worker;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE finding_facet;
        DROP INDEX finding_categories;
        DROP INDEX finding_check;
        DROP INDEX finding_resource_type;
        DROP INDEX finding_service;
        ALTER TABLE finding DROP COLUMN categories, DROP COLUMN resource_type,
          DROP COLUMN service;
        """
    )
