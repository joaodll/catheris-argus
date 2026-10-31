"""Vulnerabilities: a fourth tool, and what a vulnerability adds to a finding (ADR-0042,
2026-10-30, amended 2026-10-31).

Revision ID: 0033
Revises: 0032
Create Date: 2026-10-30

- Every tool CHECK accepts `vulnerabilities`: scan_run, run_request and schedule.tools (it is a
  collector, run like the others) and finding, finding_facet and finding_check_text (its CVEs are
  findings, with the lifecycle every finding has). The tool is provider-neutral: each provider's
  own scanner sits behind it, named per row in `scanner` (`aws-inspector` today).
- finding_vulnerability: one row per vulnerability finding, what Prowler and CloudFox findings
  do not have (the package and its fixed version, CVSS, EPSS, exploit and fix available, the
  scanner's own score, the image of a container finding). Plain columns: the API filters on them
  and never reads JSONB. A finding lists its first vulnerable package; the scanners report one in
  almost every case. The worker rewrites the row on every load of the finding.
- vulnerability_coverage: what the scanner scans and why not, per resource, scanner and scan
  type (package, code), as of the connection's last vulnerabilities run. Current state only, no
  history: the worker replaces a connection's rows on a complete run. `active` is the scanner
  adapter's verdict; status codes stay in the scanner's own words for display, so they are
  checked for shape only (a new value from a cloud must not fail an ingest).
- finding_open_vulnerability: the Resources list counts open, unmuted CVEs per resource (one page
  of ids) and filters resources by them (a semi-join). Partial, so Prowler and CloudFox writes
  never touch it.
- The raw-storage setting: a folder stored under the tool's earlier name, `inspector` (this
  migration's first version, never released), moves to `vulnerabilities`.

Downgrade deletes every vulnerabilities run, request, finding and its history, drops the tool
from schedules (a schedule left with no tool is deleted) and from the raw-storage setting, and
restores the three-tool CHECKs. Reversible at the cost of the vulnerability data.
"""

from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None

TOOL = "vulnerabilities"


def _tools_check(tools: list[str]) -> str:
    listed = ", ".join(f"'{t}'" for t in tools)
    once = "\n".join(f"  AND cardinality(array_positions(tools, '{t}')) <= 1" for t in tools)
    return f"""
        ALTER TABLE schedule DROP CONSTRAINT schedule_tools_valid;
        ALTER TABLE schedule ADD CONSTRAINT schedule_tools_valid CHECK (
          cardinality(tools) BETWEEN 1 AND {len(tools)}
          AND tools <@ ARRAY[{listed}]
          -- No duplicates (a CHECK cannot hold a subquery): each tool at most once.
        {once}
        );
    """


def _tool_checks(collectors: list[str], finding_tools: list[str]) -> str:
    runs = ", ".join(f"'{t}'" for t in collectors)
    found = ", ".join(f"'{t}'" for t in finding_tools)
    statements = [
        f"ALTER TABLE {table} DROP CONSTRAINT {table}_tool_check;"
        f" ALTER TABLE {table} ADD CONSTRAINT {table}_tool_check CHECK (tool IN ({tools}));"
        for table, tools in (
            ("scan_run", runs),
            ("run_request", runs),
            ("finding", found),
            ("finding_facet", found),
            ("finding_check_text", found),
        )
    ]
    return "\n".join(statements) + _tools_check(collectors)


def upgrade() -> None:
    op.execute(
        _tool_checks(["steampipe", "prowler", "cloudfox", TOOL], ["prowler", "cloudfox", TOOL])
    )
    op.execute(f"""
        CREATE TABLE finding_vulnerability (
          finding_id          bigint PRIMARY KEY REFERENCES finding (id) ON DELETE CASCADE,
          scanner             text NOT NULL CHECK (scanner ~ '^[a-z0-9-]{{1,40}}$'),
          kind                text NOT NULL CHECK (kind IN ('package', 'code')),
          vulnerability_id    text,
          package_name        text,
          package_manager     text,
          installed_version   text,
          fixed_version       text,
          cvss_score          numeric(3, 1) CHECK (cvss_score BETWEEN 0 AND 10),
          epss_score          double precision CHECK (epss_score BETWEEN 0 AND 1),
          scanner_score       numeric(3, 1) CHECK (scanner_score BETWEEN 0 AND 10),
          exploit_available   boolean NOT NULL DEFAULT false,
          fix_available       text CHECK (fix_available IN ('YES', 'NO', 'PARTIAL')),
          image_digest        text,
          image_tags          text[] NOT NULL DEFAULT '{{}}',
          reference_url       text CHECK (reference_url ~ '^https?://'),
          -- A package finding names its CVE; a code finding has none (ADR-0042).
          CHECK (kind = 'code' OR vulnerability_id IS NOT NULL)
        );

        CREATE TABLE vulnerability_coverage (
          resource_id         bigint NOT NULL REFERENCES resource (id),
          scanner             text NOT NULL CHECK (scanner ~ '^[a-z0-9-]{{1,40}}$'),
          scan_type           text NOT NULL CHECK (scan_type IN ('package', 'code')),
          connection_id       bigint NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
          active              boolean NOT NULL,
          status_code         text NOT NULL CHECK (status_code ~ '^[A-Z0-9_]{{1,40}}$'),
          status_reason       text CHECK (status_reason ~ '^[A-Z0-9_]{{1,80}}$'),
          last_scanned_at     timestamptz,
          scan_run_id         bigint REFERENCES scan_run (id) ON DELETE SET NULL,
          PRIMARY KEY (resource_id, scanner, scan_type)
        );
        -- The worker replaces one connection's rows per complete run.
        CREATE INDEX vulnerability_coverage_connection ON vulnerability_coverage (connection_id);

        CREATE INDEX finding_open_vulnerability ON finding (resource_id, severity)
          WHERE tool = '{TOOL}' AND state IN ('open', 'reopened') AND NOT muted
            AND resource_id IS NOT NULL;

        GRANT SELECT ON finding_vulnerability, vulnerability_coverage TO argus_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON finding_vulnerability, vulnerability_coverage
          TO argus_worker;

        -- The folder kept under the first name moves to the tool's name; the earlier default
        -- becomes the new default.
        UPDATE platform_setting
          SET value = jsonb_set(
                value #- '{{prefixes,inspector}}', '{{prefixes,{TOOL}}}',
                CASE WHEN value #>> '{{prefixes,inspector}}' = 'raw/inspector'
                     THEN to_jsonb('raw/{TOOL}'::text)
                     ELSE value #> '{{prefixes,inspector}}' END)
          WHERE topic = 'raw_storage' AND value #> '{{prefixes,inspector}}' IS NOT NULL;
    """)  # noqa: S608 - constants only


def downgrade() -> None:
    op.execute(f"""
        DROP INDEX finding_open_vulnerability;
        DROP TABLE vulnerability_coverage;
        DROP TABLE finding_vulnerability;

        DELETE FROM finding_snapshot
          WHERE finding_id IN (SELECT id FROM finding WHERE tool = '{TOOL}');
        DELETE FROM finding_event
          WHERE finding_id IN (SELECT id FROM finding WHERE tool = '{TOOL}');
        DELETE FROM finding WHERE tool = '{TOOL}';
        DELETE FROM finding_facet WHERE tool = '{TOOL}';
        DELETE FROM finding_check_text WHERE tool = '{TOOL}';
        DELETE FROM unresolved_ref WHERE tool = '{TOOL}';
        DELETE FROM run_request WHERE tool = '{TOOL}';
        DELETE FROM scan_run WHERE tool = '{TOOL}';

        -- An empty tool list fails the check, so a schedule of this tool alone goes first.
        DELETE FROM schedule WHERE tools = ARRAY['{TOOL}'];
        UPDATE schedule SET tools = array_remove(tools, '{TOOL}')
          WHERE '{TOOL}' = ANY(tools);

        -- The settings model before this migration refuses an unknown folder.
        UPDATE platform_setting SET value = value #- '{{prefixes,{TOOL}}}'
          WHERE topic = 'raw_storage';
    """)  # noqa: S608 - constants only
    op.execute(_tool_checks(["steampipe", "prowler", "cloudfox"], ["prowler", "cloudfox"]))
