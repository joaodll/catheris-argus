"""Reports may be PDFs (ADR-0047, round 2; owner 2026-11-11).

Revision ID: 0048
Revises: 0047
Create Date: 2026-11-11

A report's `format` takes `pdf` as well as `csv`, and its file key ends in the matching extension:
`reports/<id>-<32 hex>.csv` or `.pdf`, and nothing else. A third CHECK ties the two together, so a
row can never name a PDF file as its CSV or the other way round.

0047 is not edited: it was pushed and has run on a development database.

The CHECKs are replaced by name in one ALTER; report_request holds a few rows per user and day.

Downgrade deletes the PDF requests first (0033's precedent), so the narrower CHECKs hold again.
Their files then belong to no report, and the worker's report thread removes them when it next
starts.
"""

from alembic import op

revision = "0048"
down_revision = "0047"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE report_request
          DROP CONSTRAINT report_request_format_check,
          DROP CONSTRAINT report_request_storage_key_check,
          ADD CONSTRAINT report_request_format_check CHECK (format IN ('csv', 'pdf')),
          ADD CONSTRAINT report_request_storage_key_check
            CHECK (storage_key ~ '^reports/[0-9]+-[0-9a-f]{32}\\.(csv|pdf)$'),
          ADD CONSTRAINT report_request_key_matches_format
            CHECK (storage_key IS NULL OR storage_key LIKE '%.' || format);
    """)


def downgrade() -> None:
    op.execute("""
        DELETE FROM report_request WHERE format = 'pdf';
        ALTER TABLE report_request
          DROP CONSTRAINT report_request_key_matches_format,
          DROP CONSTRAINT report_request_format_check,
          DROP CONSTRAINT report_request_storage_key_check,
          ADD CONSTRAINT report_request_format_check CHECK (format IN ('csv')),
          ADD CONSTRAINT report_request_storage_key_check
            CHECK (storage_key ~ '^reports/[0-9]+-[0-9a-f]{32}\\.csv$');
    """)
