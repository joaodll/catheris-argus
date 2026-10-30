"""Reach can be unknown (ADR-0035, second amendment).

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-10

The internet rules now read route tables and network ACLs and judge IPv4 and IPv6 apart. When
a piece the verdict needs is not in the inventory (a security group, route table or network ACL
never collected, a resource with no subnet), internet-unverified draws PUBLIC_UNVERIFIED and the
reach is `unknown`: missing data is shown, never read as open or closed. A flow can start from
such a door, and a CloudFox public endpoint on it is marked unknown.
"""

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE finding DROP CONSTRAINT finding_reach_check;
        ALTER TABLE finding ADD CONSTRAINT finding_reach_check
          CHECK (reach IN ('confirmed', 'restricted', 'unknown', 'not_covered'));
        ALTER TABLE flow_shape DROP CONSTRAINT flow_shape_reach_check;
        ALTER TABLE flow_shape ADD CONSTRAINT flow_shape_reach_check
          CHECK (reach IN ('open', 'restricted', 'unknown'));
    """)


def downgrade() -> None:
    # Before this revision an unknown door was judged by its security groups alone; the next
    # ingest recomputes it. Until then, no rule judges it (findings) and its flow is kept out.
    op.execute("""
        UPDATE finding SET reach = 'not_covered' WHERE reach = 'unknown';
        UPDATE flow_shape SET reach = 'restricted' WHERE reach = 'unknown';
        ALTER TABLE finding DROP CONSTRAINT finding_reach_check;
        ALTER TABLE finding ADD CONSTRAINT finding_reach_check
          CHECK (reach IN ('confirmed', 'restricted', 'not_covered'));
        ALTER TABLE flow_shape DROP CONSTRAINT flow_shape_reach_check;
        ALTER TABLE flow_shape ADD CONSTRAINT flow_shape_reach_check
          CHECK (reach IN ('open', 'restricted'));
    """)
