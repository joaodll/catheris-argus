"""Findings that were Prowler compliance items, removed.

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-21

Prowler 5.44.0 always writes compliance/<stem>_<framework>.ocsf.json for its universal
frameworks (CIS Controls, CMMC, CSA CCM, ...): one item per finding and requirement, titled
with the requirement id, plus a "manual-<id>" item per requirement without checks. The adapter
read them as findings until 2026-10-21, so the Findings list showed one row per requirement.
The adapter now reads only the top-level OCSF file; this removes the rows already stored and
recomputes the findings metrics of the days they counted in (findings.repair).

The deleted rows were wrong, so the downgrade restores nothing.
"""

from alembic import op

from argus.findings import remove_compliance_items

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    remove_compliance_items(op.get_bind())


def downgrade() -> None:
    pass
