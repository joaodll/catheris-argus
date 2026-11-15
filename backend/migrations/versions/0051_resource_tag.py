"""Tags as plain rows, for the Tag filter on Misconfigurations, Vulnerabilities and reports.

Revision ID: 0051
Revises: 0050
Create Date: 2026-11-14

The owner asked to filter by tag (2026-11-14, palace decisions/6a24b2b5). The API never reads
JSONB, and UI filters read plain indexed columns (CLAUDE.md, Queries), so `resource.tags` stays
the panel's copy and three tables hold what the filter reads:

- `resource_tag` (inventory): one row per tag of a resource, the already-redacted value, so it is
  no new secret surface. Each inventory load replaces a resource's whole set, so a tag removed in
  the cloud stops matching. Deleting a resource removes its tags (ON DELETE CASCADE).
  Index (key, value, resource_id): the filter's EXISTS looks a pair up and reads the resource id
  from the index alone.
- `finding_tag_key` and `finding_tag_value` (findings): the picker's options, per connection and
  tool, from the tags of the resources that have findings of that tool, so a picker offers only
  tags that match something in its list. Rebuilt by ingest after a findings load and after an
  inventory load, like `finding_facet` (0009): no request aggregates live. A masked value is
  never an option. A key with more values than findings.TAG_VALUES_LISTED keeps `listed =
  false` and no value rows: its value is typed, matched exactly (a Name tag has one value per
  resource).

A new collector tool must join the tool CHECK of both facet tables, as 0033 does for
finding_facet.

Backfill: `resource_tag` from `resource.tags` (objects only), then the options as
findings.refresh_tag_facets builds them (its SQL as of this revision, `********` being
core.redaction.REDACTED, 500 TAG_VALUES_LISTED), each in one statement. Not timed at 300,000
resources: the budget estate fills these tables itself, after migrating.
"""

from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None

TOOLS = "'prowler', 'cloudfox', 'vulnerabilities'"


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE resource_tag (
          resource_id  bigint NOT NULL REFERENCES resource (id) ON DELETE CASCADE,
          key          text NOT NULL CHECK (key <> ''),
          value        text NOT NULL,
          PRIMARY KEY (resource_id, key)
        );
        CREATE INDEX resource_tag_pair ON resource_tag (key, value, resource_id);

        INSERT INTO resource_tag (resource_id, key, value)
        SELECT r.id, t.key, t.value
        FROM resource r, jsonb_each_text(r.tags) t
        WHERE jsonb_typeof(r.tags) = 'object' AND t.key <> '' AND t.value IS NOT NULL;
        ANALYZE resource_tag;

        CREATE TABLE finding_tag_key (
          connection_id  bigint NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
          tool           text NOT NULL CHECK (tool IN ({TOOLS})),
          key            text NOT NULL,
          listed         boolean NOT NULL,
          PRIMARY KEY (connection_id, tool, key)
        );
        CREATE TABLE finding_tag_value (
          connection_id  bigint NOT NULL,
          tool           text NOT NULL,
          key            text NOT NULL,
          value          text NOT NULL,
          PRIMARY KEY (connection_id, tool, key, value),
          FOREIGN KEY (connection_id, tool, key)
            REFERENCES finding_tag_key (connection_id, tool, key) ON DELETE CASCADE
        );
        -- The values picker reads one key over any set of connections.
        CREATE INDEX finding_tag_value_key ON finding_tag_value (key, value);

        WITH pairs AS (
          SELECT DISTINCT f.connection_id, f.tool, t.key, t.value
          FROM finding f JOIN resource_tag t ON t.resource_id = f.resource_id
          WHERE strpos(t.value, '********') = 0
        ),
        keys AS (
          INSERT INTO finding_tag_key (connection_id, tool, key, listed)
          SELECT connection_id, tool, key, count(*) <= 500 FROM pairs
          GROUP BY connection_id, tool, key
          RETURNING connection_id, tool, key, listed
        )
        INSERT INTO finding_tag_value (connection_id, tool, key, value)
        SELECT p.connection_id, p.tool, p.key, p.value
        FROM pairs p JOIN keys k USING (connection_id, tool, key)
        WHERE k.listed;

        GRANT SELECT ON resource_tag, finding_tag_key, finding_tag_value TO argus_api;
        GRANT SELECT, INSERT, DELETE ON resource_tag, finding_tag_key, finding_tag_value
          TO argus_worker;
        -- The report Job's filter (findings' clause over inventory.TAGGED_RESOURCES_SQL).
        GRANT SELECT ON resource_tag TO argus_reports;
    """)  # noqa: S608 - constants only


def downgrade() -> None:
    op.execute("""
        DROP TABLE finding_tag_value;
        DROP TABLE finding_tag_key;
        DROP TABLE resource_tag;
    """)
