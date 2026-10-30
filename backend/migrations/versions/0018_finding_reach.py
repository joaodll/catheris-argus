"""CloudFox's public endpoints, checked against Argus's reachability (ADR-0035).

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-09

CloudFox's endpoints module calls a load balancer public from its scheme, whatever its security
groups admit (argus_v10). `finding.reach` records what Argus's internet rules say about the
same resource: `confirmed` (internet-entry: traffic can arrive), `restricted`
(internet-restricted: public settings, but security groups, auth or an address list keep the
internet out) or `not_covered` (no rule judges this kind of resource). Ingest sets it on
CloudFox's `cloudfox_public_endpoint` findings only; every other finding keeps NULL.
"""

from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE finding ADD COLUMN reach text "
        "CHECK (reach IN ('confirmed', 'restricted', 'not_covered'))"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE finding DROP COLUMN reach")
