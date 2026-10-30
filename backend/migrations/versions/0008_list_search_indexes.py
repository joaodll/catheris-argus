"""Indexes for the Findings and Resources lists.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-06

The Investigate pages (2026-10-06) search findings by title, check id or resource uid, and
resources by name, native id or uid, as a contains match in any case (`ILIKE '%text%'`). A
B-tree cannot serve that, and a scan of 300,000 rows misses the 300 ms query budget, so each
table gets one trigram index over the searched columns joined by a newline. The queries use the
same expression (findings.queries, inventory.queries); change both together. Patterns shorter
than three characters cannot use a trigram index and fall back to a scan.

The sort orders get their own indexes (`finding_severity_order`, `finding_last_seen`,
`resource_name_order`), matching the ORDER BY expressions exactly. Walking one, Postgres stops
after a page of matches, which keeps a broad search (one that matches most rows, where the
trigram index narrows little) fast too.

pg_trgm is a trusted extension (PostgreSQL 13+), so the owner role creates it. Its operator
functions are executable by PUBLIC, so the API role needs no new grant.
"""

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE EXTENSION IF NOT EXISTS pg_trgm;

        CREATE INDEX finding_search ON finding USING gin (
          (title || E'\\n' || check_id || E'\\n' || resource_uid) gin_trgm_ops
        );
        CREATE INDEX finding_last_seen ON finding (last_seen, id);
        CREATE INDEX finding_severity_order ON finding (
          (array_position(ARRAY['critical','high','medium','low','informational'], severity)),
          last_seen DESC, id
        );

        CREATE INDEX resource_search ON resource USING gin (
          (coalesce(name, '') || E'\\n' || native_id || E'\\n' || resource_uid) gin_trgm_ops
        );
        CREATE INDEX resource_name_order ON resource ((coalesce(name, native_id)), id);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX resource_name_order;
        DROP INDEX resource_search;
        DROP INDEX finding_severity_order;
        DROP INDEX finding_last_seen;
        DROP INDEX finding_search;
        DROP EXTENSION IF EXISTS pg_trgm;
        """
    )
