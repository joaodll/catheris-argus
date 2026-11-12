"""The query budget (design: "Database load and query rules"): every API query stays under
300 ms at p95 on a synthetic estate of 300,000 resources, and snapshot-range queries prune
partitions. The dataset is generated in SQL from a fixed seed, never committed.

Shape (the design's "large" scenario, 36 accounts): 300,000 resources, 300,000 open findings,
180 days of metric_daily for 36 accounts plus the rollup, 36 x 3 x 180 scan runs.
Edges (ADR-0033): about 940,000, two days of snapshots, with hubs: `internet` reaching 5,000
resources of one account, a VPC holding 20,000, and an AWS-managed policy attached to 10,000
principals across accounts.
Compliance as real Prowler on AWS: 40 frameworks of 100 requirements, 180 days of scores and
counts per account, and two days of requirement results per account plus their rollup.
Vulnerabilities (ADR-0042, in AWS Inspector's shape): 50,000 CVE findings on connection 1's
instances and functions (15 each, one in five resolved), with their vulnerability facts and
coverage (one in seven not scanned).
The Investigate summaries' rows (misconfigurations.*, vulnerabilities.*) for every account and
the rollup, every day for 180 days: the worst case, as real accounts are counted on scan days.
"""

import json
import math
import resource
import time
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Connection, Engine, text

from argus import (
    connections,
    findings,
    ingest,
    inventory,
    metrics,
    relationships,
    reports,
    scheduling,
)
from argus.metrics.series import calendar_months
from argus.reports import pdf as report_pdf

pytestmark = [pytest.mark.db, pytest.mark.budget]
BUDGET_MS = 300.0
# p95 by nearest rank over 20 runs: the 19th fastest, so one stray run (a checkpoint, a cold
# page) is tolerated and two are not. Never interpolated past the slowest run (2026-10-09).
RUNS = 20
TODAY = date(2026, 10, 3)
ACCOUNTS = 36
# The account last scanned 90 days ago (owner's decision, 2026-11-01: every screen shows each
# account's latest scan, however old); every other account was scanned today.
STALE = ACCOUNTS
STALE_DAY = TODAY - timedelta(days=90)
FRAMEWORKS = 40
REQUIREMENTS = 100
FRAMEWORK = "fw_7_aws"
SEVERITIES = ("critical", "high", "medium", "low", "informational")


def _generate(conn: Connection) -> None:
    conn.execute(text("SELECT setseed(0.42)"))
    conn.execute(
        text("SELECT argus_ensure_partitions(:a, :b)"),
        {"a": TODAY - timedelta(days=200), "b": TODAY},
    )
    conn.execute(
        text("""
        INSERT INTO connection (name, kind, account_id, auth_method, demo_seed, created_by,
                                updated_by)
        SELECT 'acct-' || g, 'demo', lpad((200000000000 + g)::text, 12, '0'), 'none', g, 'b', 'b'
        FROM generate_series(1, :n) g
    """),
        {"n": ACCOUNTS},
    )
    conn.execute(
        text("""
        INSERT INTO resource (resource_uid, connection_id, region, type, native_id, name,
                              first_seen, last_seen, deleted_on)
        SELECT 'arn:aws:ec2:us-east-1:' || (200000000000 + 1 + g % :n) || ':' || 'instance/i-' || g,
               1 + g % :n, 'us-east-1',
               (ARRAY['aws_ec2_instance','aws_lambda_function','aws_s3_bucket','aws_iam_role',
                      'aws_vpc_security_group'])[1 + g % 5],
               'i-' || g, 'r' || g,
               -- First seen over the history kept; one in 100 removed in the last 30 days.
               CAST(:d AS date) - g % 180, :d,
               CASE WHEN g % 100 = 7 THEN CAST(:d AS date) - g % 30 END
        FROM generate_series(1, 300000) g
    """),
        {"n": ACCOUNTS, "d": TODAY},
    )
    # Every resource's inventory row: today's, or STALE's 90 days ago, with its load.
    conn.execute(
        text("""
        INSERT INTO resource_config (config_hash, config, created_on)
        VALUES (sha256('budget'::bytea), '{}', :d)
    """),
        {"d": TODAY},
    )
    conn.execute(
        text("""
        INSERT INTO resource_snapshot (snapshot_date, resource_id, config_id)
        SELECT CASE WHEN r.connection_id = :stale THEN CAST(:old AS date) ELSE :d END, r.id,
               (SELECT id FROM resource_config WHERE config_hash = sha256('budget'::bytea))
        FROM resource r
    """),
        {"stale": STALE, "old": STALE_DAY, "d": TODAY},
    )
    conn.execute(
        text("""
        INSERT INTO resource_load (connection_id, snapshot_date, resources)
        SELECT connection_id, CASE WHEN connection_id = :stale THEN CAST(:old AS date) ELSE :d END,
               count(*)
        FROM resource GROUP BY connection_id
    """),
        {"stale": STALE, "old": STALE_DAY, "d": TODAY},
    )
    conn.execute(
        text("""
        INSERT INTO finding (finding_uid, tool, check_id, connection_id, region, resource_uid,
                             severity, status, muted, title, service, resource_type, categories,
                             state, first_seen, last_seen, resolved_on, reach, reach_reason,
                             resource_id)
        SELECT 'f-' || g, CASE WHEN g % 10 = 0 THEN 'cloudfox' ELSE 'prowler' END,
               -- One in 50 is a Prowler exposure check, with Argus's reach (ADR-0035, sixth
               -- amendment).
               CASE WHEN g % 50 = 1 THEN 'ec2_instance_port_ssh_exposed_to_internet'
                    ELSE 'check_' || (g % 150) END, 1 + g % :n,
               (ARRAY['us-east-1','eu-west-1','sa-east-1','global'])[1 + g % 4],
               'arn:aws:ec2:us-east-1:x:' || 'instance/i-' || g,
               (ARRAY['critical','high','medium','low','informational'])[1 + (random()*4)::int],
               CASE WHEN g % 20 = 0 THEN 'MANUAL' ELSE 'FAIL' END, g % 33 = 0, 'title ' || g,
               (ARRAY['ec2','iam','s3','cloudwatch','rds','awslambda','kms','vpc'])[1 + g % 8],
               (ARRAY['AwsEc2Instance','AwsIamRole','AwsS3Bucket','AwsEc2SecurityGroup',
                      'Other'])[1 + g % 5],
               CASE g % 5 WHEN 0 THEN ARRAY['internet-exposed']
                          WHEN 1 THEN ARRAY['identity-access', 'privilege-escalation']
                          WHEN 2 THEN ARRAY['logging', 'forensics-ready']
                          WHEN 3 THEN ARRAY['encryption'] ELSE ARRAY['secrets'] END,
               CASE WHEN g % 4 = 0 THEN 'resolved' ELSE 'open' END,
               :d - (g % 40), :d, CASE WHEN g % 4 = 0 THEN CAST(:d AS date) END,
               CASE WHEN g % 50 = 1
                    THEN (ARRAY['confirmed','restricted','unknown','not_covered'])[1 + g / 50 % 4]
               END,
               CASE WHEN g % 50 = 1 AND g / 50 % 4 = 1 THEN 'nacl_blocks' END,
               -- Three in four are on an inventoried resource (the Resources list's
               -- Misconfigurations and Internet reachable filters).
               r.id
        FROM generate_series(1, 400000) g
        LEFT JOIN resource r ON r.native_id = 'i-' || g AND r.connection_id = 1 + g % :n
        ORDER BY g
    """),
        {"n": ACCOUNTS, "d": TODAY},
    )
    conn.execute(
        text("""
        INSERT INTO finding_facet (connection_id, facet, tool, value)
        SELECT DISTINCT f.connection_id, v.facet, f.tool, v.value
        FROM finding f,
             LATERAL (VALUES ('region', f.region), ('service', f.service),
                             ('resource_type', f.resource_type), ('check', f.check_id)
                      UNION ALL SELECT 'category', unnest(f.categories)) v(facet, value)
        WHERE v.value IS NOT NULL
    """)
    )
    conn.execute(
        text("""
        INSERT INTO scan_run (run_uid, connection_id, tool, tool_version, source, snapshot_date,
                              status, started_at, finished_at, raw_path)
        SELECT gen_random_uuid(), c, t, '1', 'synthetic', :d - day, 'complete',
               (:d - day)::timestamptz, (:d - day)::timestamptz + interval '5 minutes', 'raw'
        FROM generate_series(1, :n) c, unnest(ARRAY['steampipe','prowler','cloudfox']) t,
             generate_series(0, 179) day
    """),
        {"n": ACCOUNTS, "d": TODAY},
    )
    conn.execute(
        text("""
        INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
        SELECT :d - day, c, m, dim, random() * 1000
        FROM generate_series(0, 179) day, generate_series(0, :n) c,
             (VALUES ('assets.total', ''), ('threatscore.score', ''),
                     ('threatscore.score', '1. IAM'), ('threatscore.score', '2. Attack Surface'),
                     ('checks.status', 'PASS'), ('checks.status', 'FAIL'),
                     ('checks.status', 'MUTED'), ('checks.status', 'MANUAL'),
                     ('findings.open_by_severity', 'critical'),
                     ('findings.open_by_severity', 'high'),
                     ('findings.open_by_severity', 'medium'),
                     ('findings.open_by_severity', 'low'),
                     ('findings.open_by_severity', 'informational'),
                     ('assets.by_type', 'aws_ec2_instance'), ('assets.by_type', 'aws_s3_bucket'),
                     ('assets.by_type', 'aws_iam_role')) AS m(m, dim)
    """),
        {"n": ACCOUNTS, "d": TODAY},
    )
    _generate_misconfiguration_metrics(conn)
    _generate_vulnerability_metrics(conn)
    _generate_asset_metrics(conn)
    _generate_edges(conn)
    _generate_compliance(conn)
    _generate_vulnerabilities(conn)
    conn.execute(text("ANALYZE"))


def _generate_misconfiguration_metrics(conn: Connection) -> None:
    """The Misconfigurations summary's rows (metrics.summary), as if every account and the
    rollup were counted every day for 180 days: real accounts are counted on scan days only, so
    this is the worst case. About 400 rows per account and day: 40 services, 10 regions, 10
    categories, 12 first-seen days, the reach verdicts and the day's events."""
    conn.execute(
        text("""
        INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
        SELECT :d - day, c, m.metric, m.dim, floor(random() * 500)
        FROM generate_series(0, 179) day, generate_series(0, :n) c,
             (SELECT 'misconfigurations.open_by_severity', s
                FROM unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'misconfigurations.open_by_tool', t || '|' || s
                FROM unnest(ARRAY['prowler', 'cloudfox']) t, unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'misconfigurations.open_by_service', 'svc' || g || '|' || s
                FROM generate_series(1, 40) g, unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'misconfigurations.open_by_region', 'region-' || g || '|' || s
                FROM generate_series(1, 10) g, unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'misconfigurations.open_by_category', 'category-' || g || '|' || s
                FROM generate_series(1, 10) g, unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'misconfigurations.open_by_first_seen',
                               to_char(CAST(:d AS date) - g * 30, 'YYYY-MM-DD') || '|' || s
                FROM generate_series(0, 11) g, unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'misconfigurations.reach', r || '|' || s
                FROM unnest(ARRAY['confirmed', 'restricted', 'unknown', 'not_covered']) r,
                     unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'misconfigurations.resources', k
                FROM unnest(ARRAY['critical_high', 'reachable']) k
              UNION ALL SELECT 'misconfigurations.events', e
                FROM unnest(ARRAY['opened', 'reopened', 'resolved']) e) AS m(metric, dim)
    """),
        {"n": ACCOUNTS, "d": TODAY, "sev": list(SEVERITIES)},
    )


def _generate_vulnerability_metrics(conn: Connection) -> None:
    """The Vulnerabilities summary's rows (metrics.summary), like the Misconfigurations ones:
    about 170 rows per account and day: 3 resource types, 10 regions, 12 first-seen days, the
    fix and exploit buckets, the suppressed ones and the day's events."""
    conn.execute(
        text("""
        INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
        SELECT :d - day, c, m.metric, m.dim, floor(random() * 500)
        FROM generate_series(0, 179) day, generate_series(0, :n) c,
             (SELECT 'vulnerabilities.open_by_severity', s FROM unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'vulnerabilities.suppressed_by_severity', s
                FROM unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'vulnerabilities.open_by_resource_type', t || '|' || s
                FROM unnest(ARRAY['AwsEc2Instance', 'AwsLambdaFunction', 'AwsEcrContainerImage']) t,
                     unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'vulnerabilities.open_by_region', 'region-' || g || '|' || s
                FROM generate_series(1, 10) g, unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'vulnerabilities.open_by_first_seen',
                               to_char(CAST(:d AS date) - g * 30, 'YYYY-MM-DD') || '|' || s
                FROM generate_series(0, 11) g, unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'vulnerabilities.open_by_fix', f || '|' || s
                FROM unnest(ARRAY['available', 'none', 'unknown']) f,
                     unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'vulnerabilities.open_exploitable_by_fix', f || '|' || s
                FROM unnest(ARRAY['available', 'none', 'unknown']) f,
                     unnest(CAST(:sev AS text[])) s
              UNION ALL SELECT 'vulnerabilities.resources', 'exploitable'
              UNION ALL SELECT 'vulnerabilities.events', e
                FROM unnest(ARRAY['opened', 'reopened', 'resolved']) e) AS m(metric, dim)
    """),
        {"n": ACCOUNTS, "d": TODAY, "sev": list(SEVERITIES)},
    )


def _generate_asset_metrics(conn: Connection) -> None:
    """The Resources summary's rows (metrics.summary.ASSETS) besides the total: as if every
    account were loaded every day for 180 days, with 400 asset types (the real table list holds
    about that many), 17 regions and the day's events. About 420 rows per account and day."""
    conn.execute(
        text("""
        INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
        SELECT :d - day, c, m.metric, m.dim, floor(random() * 500)
        FROM generate_series(0, 179) day, generate_series(0, :n) c,
             (SELECT 'assets.by_type', 'aws_type_' || g FROM generate_series(1, 400) g
              UNION ALL SELECT 'assets.by_region', 'region-' || g FROM generate_series(1, 17) g
              UNION ALL SELECT 'assets.events', e
                FROM unnest(ARRAY['added', 'removed', 'baseline']) e) AS m(metric, dim)
    """),
        {"n": ACCOUNTS, "d": TODAY},
    )


def _generate_vulnerabilities(conn: Connection) -> None:
    conn.execute(
        text("""
        INSERT INTO finding (finding_uid, tool, check_id, connection_id, region, resource_uid,
                             resource_id, severity, status, muted, title, service,
                             resource_type, categories, state, first_seen, last_seen,
                             resolved_on)
        SELECT 'insp-' || r.id || '-' || k, 'vulnerabilities', 'CVE-2024-' || (1000 + k * 37 % 900),
               1, 'us-east-1', r.resource_uid, r.id,
               (ARRAY['critical','high','medium','low','informational'])[1 + (random()*4)::int],
               'FAIL', k % 11 = 0, 'CVE ' || k, 'ec2', 'AwsEc2Instance', ARRAY['vulnerability'],
               CASE WHEN k % 5 = 0 THEN 'resolved' ELSE 'open' END, :d - k, :d,
               CASE WHEN k % 5 = 0 THEN CAST(:d AS date) END
        FROM (SELECT id, resource_uid FROM resource WHERE connection_id = 1
                AND type IN ('aws_ec2_instance', 'aws_lambda_function') ORDER BY id) r,
             generate_series(1, 15) k
        LIMIT 50000
    """),
        {"d": TODAY},
    )
    conn.execute(
        text("""
        INSERT INTO finding_vulnerability (finding_id, scanner, kind, vulnerability_id,
                                           package_name, installed_version, fixed_version,
                                           cvss_score, epss_score, exploit_available,
                                           fix_available)
        SELECT id, 'aws-inspector', 'package', check_id, 'pkg', '1.0', '1.1',
               round((random() * 10)::numeric, 1), random(), id % 4 = 0, 'YES'
        FROM finding WHERE tool = 'vulnerabilities'
    """)
    )
    conn.execute(
        text("""
        INSERT INTO vulnerability_coverage (resource_id, scanner, scan_type, connection_id,
                                            active, status_code, status_reason, last_scanned_at)
        SELECT DISTINCT resource_id, 'aws-inspector', 'package', 1, resource_id % 7 <> 0,
               CASE WHEN resource_id % 7 = 0 THEN 'INACTIVE' ELSE 'ACTIVE' END,
               CASE WHEN resource_id % 7 = 0 THEN 'UNMANAGED_EC2_INSTANCE' ELSE 'SUCCESSFUL' END,
               CAST(:d AS timestamptz)
        FROM finding WHERE tool = 'vulnerabilities'
    """),
        {"d": TODAY},
    )


HUB_VPC = "arn:aws:ec2:us-east-1:200000000001:vpc/vpc-hub"
HUB_POLICY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
# Connection 1's instances (resource ids are the generator's g; g % 36 == 0, g % 5 == 0): one
# page of the Resources list, each with 15 CVEs.
VULNERABLE_PAGE = [180 * i for i in range(1, 21)]


def _vulnerability_cells(c: Connection) -> Any:
    return (
        findings.vulnerability_counts(c, VULNERABLE_PAGE),
        findings.scanned_resources(c, VULNERABLE_PAGE),
    )


# A literal ':word' would read as a bind parameter in text(): the colon is concatenated.
RESOURCE_UID = (
    "'arn:aws:ec2:us-east-1:' || (200000000000 + 1 + {g} % :n) || ':' || 'instance/i-' || {g}"
)


def _generate_edges(conn: Connection) -> None:
    """Every resource g: ROUTES_TO g+36 and RUNS_AS g+72 (same account), IN_NETWORK its
    account's VPC; plus the hubs. Snapshots today and yesterday, with their edge_load rows."""
    params = {"n": ACCOUNTS, "d": TODAY}
    target = RESOURCE_UID.format(g="t.dst")
    conn.execute(
        text(f"""
        INSERT INTO edge (edge_key, source_uid, target_uid, source_resource_id,
                          target_resource_id, type, origin, first_seen, last_seen,
                          connection_id)
        SELECT sha256((t.kind || '|' || s.g)::bytea), {RESOURCE_UID.format(g="s.g")}, {target},
               s.g, CASE WHEN t.dst <= 300000 THEN t.dst END, t.type, t.origin, :d - 30, :d,
               1 + s.g % :n
        FROM generate_series(1, 300000) s(g),
             LATERAL (VALUES ('route', s.g + 36, 'ROUTES_TO', 'rule:route@1'),
                             ('run', s.g + 72, 'RUNS_AS', 'rule:run@1')) t(kind, dst, type, origin)
    """),  # noqa: S608 - constant fragments
        params,
    )
    conn.execute(
        text(f"""
        INSERT INTO edge (edge_key, source_uid, target_uid, source_resource_id, type, origin,
                          first_seen, last_seen, connection_id)
        SELECT sha256(('net|' || g)::bytea), {RESOURCE_UID.format(g="g")},
               CASE WHEN g % 15 = 0 THEN :hub_vpc
                    ELSE 'arn:aws:ec2:us-east-1:' || (200000000000 + 1 + g % :n)
                         || ':' || 'vpc/vpc-' || (g % :n) END,
               g, 'IN_NETWORK', 'rule:net@1', :d - 30, :d, 1 + g % :n
        FROM generate_series(1, 300000) g
        UNION ALL
        SELECT sha256(('pol|' || g)::bytea), {RESOURCE_UID.format(g="g")}, :hub_policy,
               g, 'HAS_POLICY', 'rule:pol@1', :d - 30, :d, 1 + g % :n
        FROM generate_series(1, 300000, 30) g
        UNION ALL
        SELECT sha256((o.kind || '|' || g)::bytea), 'internet', {RESOURCE_UID.format(g="g")},
               NULL, o.type, o.origin, :d - 30, :d, 1
        FROM generate_series(36, 180000, 36) g,
             (VALUES ('in', 'ROUTES_TO', 'rule:in@1'),
                     ('cf', 'INTERNET_REACHABLE', 'cloudfox')) o(kind, type, origin)
        UNION ALL
        -- Every tenth resource on the hub's chains is an administrator (CloudFox).
        SELECT sha256(('adm|' || g)::bytea), {RESOURCE_UID.format(g="g")},
               'admin:' || (200000000000 + 1), g, 'IS_ADMIN', 'cloudfox', :d - 30, :d, 1
        FROM generate_series(360, 300000, 360) g
    """),  # noqa: S608 - constant fragments
        {**params, "hub_vpc": HUB_VPC, "hub_policy": HUB_POLICY},
    )
    conn.execute(
        text("""
        UPDATE edge SET target_resource_id = substring(target_uid from '/i-([0-9]+)$')::bigint
        WHERE source_uid = 'internet'
    """)
    )
    conn.execute(
        text("""
        INSERT INTO edge_snapshot (snapshot_date, edge_id)
        SELECT day, id FROM edge, unnest(ARRAY[CAST(:d AS date), CAST(:d AS date) - 1]) day
    """),
        params,
    )
    conn.execute(
        text("""
        INSERT INTO edge_load (connection_id, family, snapshot_date, edges)
        SELECT e.connection_id,
               CASE WHEN e.origin = 'cloudfox' THEN 'cloudfox' ELSE 'rule' END, s.snapshot_date,
               count(*)
        FROM edge_snapshot s JOIN edge e ON e.id = s.edge_id
        GROUP BY 1, 2, 3
    """)
    )


def _generate_compliance(conn: Connection) -> None:
    params = {"n": ACCOUNTS, "d": TODAY, "fw": FRAMEWORKS, "req": REQUIREMENTS}
    conn.execute(
        text("""
        INSERT INTO compliance_framework (framework, family, name, version, provider)
        SELECT 'fw_' || f || '_aws', 'FW', 'Framework number ' || f, '', 'aws'
        FROM generate_series(1, :fw) f
    """),
        params,
    )
    conn.execute(
        text("""
        INSERT INTO compliance_requirement (framework, framework_version, requirement_id,
                                            description, title, section)
        SELECT 'fw_' || f || '_aws', '', (r % 10) || '.' || r, 'requirement ' || r,
               'title ' || r, (r % 10) || '. Section'
        FROM generate_series(1, :fw) f, generate_series(1, :req) r
    """),
        params,
    )
    conn.execute(
        text("""
        INSERT INTO compliance_snapshot (snapshot_date, connection_id, requirement_id,
                                         scan_run_id, status, passed_checks, failed_checks)
        SELECT day, c, cr.id, 1, 1 + (random() * 2)::int, (random() * 5)::int,
               (random() * 3)::int
        FROM unnest(ARRAY[CAST(:d AS date), CAST(:d AS date) - 40]) day,
             generate_series(1, :n) c, compliance_requirement cr
    """),
        params,
    )
    conn.execute(
        text("""
        INSERT INTO compliance_rollup (snapshot_date, requirement_id, fail_connections,
                                       manual_connections, pass_connections, passed_checks,
                                       failed_checks)
        SELECT snapshot_date, requirement_id, count(*) FILTER (WHERE status = 1),
               count(*) FILTER (WHERE status = 2), count(*) FILTER (WHERE status = 3),
               sum(passed_checks), sum(failed_checks)
        FROM compliance_snapshot GROUP BY snapshot_date, requirement_id
    """)
    )
    conn.execute(
        text("""
        INSERT INTO metric_daily (snapshot_date, connection_id, metric, dimension, value)
        SELECT :d - day, c, m, 'fw_' || f || '_aws' || dim, random() * 100
        FROM generate_series(0, 179) day, generate_series(0, :n) c, generate_series(1, :fw) f,
             (VALUES ('compliance.score', ''), ('compliance.passed', ''),
                     ('compliance.assessed', ''), ('compliance.requirements', '|PASS'),
                     ('compliance.requirements', '|FAIL'),
                     ('compliance.requirements', '|MANUAL')) AS m(m, dim)
    """),
        params,
    )


@pytest.fixture(scope="module")
def estate(migrated: Engine) -> Engine:
    with migrated.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE connection, scan_run, resource, resource_config, edge, "
                "audit_log, metric_daily, compliance_requirement, schedule, "
                "platform_setting, report_request RESTART IDENTITY CASCADE"
            )
        )
        _generate(conn)
        _reports(conn)
    # A steady-state database: the first reads of freshly inserted rows would otherwise pay
    # for setting their hint bits and flushing the load, and time that instead of the query.
    with migrated.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("VACUUM (ANALYZE)"))
        conn.execute(text("CHECKPOINT"))
    return migrated


def _reports(conn: Connection) -> int:
    """Reports (ADR-0047): 20,000 requests over the estate's life, 2,000 of them one Operator's
    (the rest from users since deleted). Returns that Operator's id."""
    operator: int = conn.execute(
        text("""
        INSERT INTO app_user (username, password_hash, role, created_by, updated_by)
        VALUES ('budget-operator', 'x', 'operator', 'b', 'b')
        ON CONFLICT (username) DO UPDATE SET role = 'operator'
        RETURNING id
    """)
    ).scalar_one()
    conn.execute(
        text("""
        INSERT INTO report_request (kind, format, filters, connection_ids, requested_by_id,
                                    requested_by, status, requested_at, started_at,
                                    finished_at, error)
        SELECT (ARRAY['misconfigurations','vulnerabilities'])[1 + g % 2], 'csv', '{}',
               ARRAY[1 + g % :n], CASE WHEN g % 10 = 0 THEN CAST(:u AS bigint) END,
               'someone', 'failed', ts, ts, ts, 'old'
        FROM generate_series(1, 20000) g,
             LATERAL (SELECT now() - make_interval(mins => g * 13) AS ts) t
    """),
        {"n": ACCOUNTS, "u": operator},
    )
    return operator


def _p95_ms(engine: Engine, query: Callable[[Connection], Any]) -> float:
    timings = []
    with engine.connect() as conn:
        query(conn)  # warm
        for _ in range(RUNS):
            start = time.perf_counter()
            query(conn)
            timings.append((time.perf_counter() - start) * 1000)
    return sorted(timings)[math.ceil(0.95 * len(timings)) - 1]


# The Misconfigurations list's tools: every finding but a CVE (api/routes/findings.TOOLS).
MISCONFIGURATIONS = ("prowler", "cloudfox")

# What every summary number counts (metrics.summary): open, FAIL, not muted, both tools.
SUMMARY_FILTERS = findings.FindingFilters(tools=MISCONFIGURATIONS, statuses=("FAIL",), muted="hide")
# What every Vulnerabilities summary number counts: open, not suppressed.
VULNERABILITY_SUMMARY_FILTERS = findings.FindingFilters(tools=("vulnerabilities",), muted="hide")

QUERIES: dict[str, Callable[[Connection], Any]] = {
    "overview, all accounts": lambda c: metrics.build_overview(c, connection_id=0, as_of=TODAY),
    "overview, one account": lambda c: metrics.build_overview(c, connection_id=7, as_of=TODAY),
    "overview, 30 days back": lambda c: metrics.build_overview(
        c, connection_id=0, as_of=TODAY - timedelta(days=30), severity_range="1M"
    ),
    "context: last runs": lambda c: ingest.last_runs(c, connection_id=0),
    "connections": connections.list_views,
    "runs, first page and count": lambda c: ingest.list_runs(
        c, limit=20, offset=0, connection_id=None, tool=None, status=None
    ),
    "runs, oldest first, a later page": lambda c: ingest.list_runs(
        c, limit=20, offset=2000, connection_id=None, tool=None, status=None, order="started_asc"
    ),
    "runs, one account": lambda c: ingest.list_runs(
        c, limit=20, offset=0, connection_id=7, tool="prowler", status=None
    ),
    "runs, missing permissions": lambda c: ingest.list_runs(
        c, limit=20, offset=0, connection_id=None, tool=None, status=None, missing_permissions=True
    ),
    "schedules, search": lambda c: scheduling.list_schedules(c, q="night", limit=20, offset=0),
    "findings, first page and count": lambda c: findings.list_findings(c, limit=20, offset=0),
    "findings, critical": lambda c: findings.list_findings(
        c, limit=20, offset=0, filters=findings.FindingFilters(severities=("critical",))
    ),
    "findings, one account": lambda c: findings.list_findings(
        c,
        limit=20,
        offset=0,
        filters=findings.FindingFilters(connection_ids=(7,), tools=("prowler",)),
    ),
    "findings, search": lambda c: findings.list_findings(
        c, limit=20, offset=0, filters=findings.FindingFilters(q="public")
    ),
    "findings, search matching a third": lambda c: findings.list_findings(
        c, limit=20, offset=0, filters=findings.FindingFilters(q="title 1")
    ),
    "findings, last seen, a later page": lambda c: findings.list_findings(
        c, limit=20, offset=2000, order="last_seen_asc"
    ),
    "findings, least severe first, a later page": lambda c: findings.list_findings(
        c, limit=20, offset=2000, order="severity_asc"
    ),
    "findings, one provider": lambda c: findings.list_findings(
        c, limit=20, offset=0, filters=findings.FindingFilters(providers=("aws",))
    ),
    "one finding, its own link": lambda c: findings.get_finding(c, 1234),
    "findings, one resource": lambda c: findings.list_findings(
        c, limit=5, offset=0, filters=findings.FindingFilters(resource_id=1234)
    ),
    "findings, several severities and services": lambda c: findings.list_findings(
        c,
        limit=20,
        offset=0,
        filters=findings.FindingFilters(
            severities=("critical", "high"), services=("iam", "s3"), regions=("us-east-1",)
        ),
    ),
    "findings, a category": lambda c: findings.list_findings(
        c, limit=20, offset=0, filters=findings.FindingFilters(categories=("secrets",))
    ),
    "findings, two checks, new, muted hidden": lambda c: findings.list_findings(
        c,
        limit=20,
        offset=0,
        filters=findings.FindingFilters(check_ids=("check_7", "check_42"), new=True, muted="hide"),
    ),
    "findings, cloudfox manual on a resource type": lambda c: findings.list_findings(
        c,
        limit=20,
        offset=0,
        filters=findings.FindingFilters(
            tools=("cloudfox",), statuses=("MANUAL",), resource_types=("AwsIamRole",)
        ),
    ),
    "findings, the disagreements: Prowler, Argus restricted": lambda c: findings.list_findings(
        c,
        limit=20,
        offset=0,
        filters=findings.FindingFilters(tools=("prowler",), reaches=("restricted",)),
    ),
    # Connection 7 has none: the worst case, the whole table in severity order without an index.
    "findings, any reach, an account with none": lambda c: findings.list_findings(
        c,
        limit=20,
        offset=0,
        filters=findings.FindingFilters(
            connection_ids=(7,), reaches=("confirmed", "restricted", "unknown", "not_covered")
        ),
    ),
    "findings by check, no filter": lambda c: findings.finding_groups(c, limit=20, offset=0),
    "findings by check, past the last page": lambda c: findings.finding_groups(
        c, limit=20, offset=10000
    ),
    "findings by check, one account": lambda c: findings.finding_groups(
        c, limit=20, offset=0, filters=findings.FindingFilters(connection_ids=(7,))
    ),
    "findings, facets": lambda c: findings.finding_facets(c, tools=MISCONFIGURATIONS),
    "findings, facets, two accounts": lambda c: findings.finding_facets(
        c, tools=MISCONFIGURATIONS, connection_ids=(7, 8)
    ),
    "misconfigurations: the default list": lambda c: findings.list_findings(
        c, limit=20, offset=0, filters=findings.FindingFilters(tools=MISCONFIGURATIONS)
    ),
    "misconfigurations: by check": lambda c: findings.finding_groups(
        c, limit=20, offset=0, filters=findings.FindingFilters(tools=MISCONFIGURATIONS)
    ),
    "misconfigurations: summary, all accounts": lambda c: metrics.misconfiguration_summary(
        c, connection_id=0, today=TODAY
    ),
    "misconfigurations: summary, one account": lambda c: metrics.misconfiguration_summary(
        c, connection_id=7, today=TODAY
    ),
    # The summary's Top failing checks: the list by check with the summary's filters.
    "misconfigurations: summary, top checks": lambda c: findings.finding_groups(
        c, limit=10, offset=0, filters=SUMMARY_FILTERS
    ),
    # An age column's link: the list with the summary's filters and a first-seen range.
    "misconfigurations: first seen 30 to 90 days ago": lambda c: findings.list_findings(
        c,
        limit=20,
        offset=0,
        filters=replace(
            SUMMARY_FILTERS,
            first_seen_from=TODAY - timedelta(days=89),
            first_seen_to=TODAY - timedelta(days=30),
        ),
    ),
    "findings, counts for a page of resources": lambda c: findings.open_finding_counts(
        c, list(range(1000, 1020))
    ),
    "compliance, every framework": lambda c: (
        metrics.compliance_scores(c, connection_id=0, as_of=TODAY),
        findings.framework_catalog(c),
    ),
    "compliance, one framework, one account": lambda c: metrics.compliance_history(
        c, framework=FRAMEWORK, connection_id=7, as_of=TODAY, rng="3M"
    ),
    "compliance, accounts month over month": lambda c: metrics.compliance_by_account(
        c, framework=FRAMEWORK, as_of=TODAY
    ),
    "compliance, requirements, all accounts": lambda c: findings.list_requirements(
        c, framework=FRAMEWORK, connection_id=0, day=TODAY, limit=50, offset=0
    ),
    "compliance, requirements, one account, filtered": lambda c: findings.list_requirements(
        c,
        framework=FRAMEWORK,
        connection_id=7,
        day=TODAY,
        status="FAIL",
        q="1.",
        limit=50,
        offset=0,
    ),
    "resources, first page and count": lambda c: inventory.list_resources(c, limit=20, offset=0),
    "resources, one type": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=0,
        filters=inventory.ResourceFilters(connection_ids=(7,), resource_types=("aws_s3_bucket",)),
    ),
    "resources, one type, all accounts": lambda c: inventory.list_resources(
        c, limit=20, offset=0, filters=inventory.ResourceFilters(resource_types=("aws_s3_bucket",))
    ),
    "resources, one type, all accounts, a later page": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=2000,
        filters=inventory.ResourceFilters(resource_types=("aws_s3_bucket",)),
    ),
    "resources, search": lambda c: inventory.list_resources(
        c, limit=20, offset=0, filters=inventory.ResourceFilters(q="i-4242")
    ),
    "resources, search matching a third": lambda c: inventory.list_resources(
        c, limit=20, offset=0, filters=inventory.ResourceFilters(q="i-1")
    ),
    "resources, last seen, a later page": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=2000,
        order="last_seen_desc",
        filters=inventory.ResourceFilters(include_deleted=True),
    ),
    "resources, facets": inventory.resource_facets,
    "resources, names for a page": lambda c: inventory.resource_names(c, list(range(1000, 1020))),
    "resource as of a day": lambda c: inventory.resource_at(c, resource_id=1234, day=TODAY),
    # Resource 35 belongs to STALE (connection 1 + 35 % 36): its latest scan is 90 days old.
    "resource as of a day, scanned 90 days ago": lambda c: inventory.resource_at(
        c, resource_id=35, day=TODAY
    ),
    "edges as of a day": lambda c: relationships.edges_at(
        c, resource_id=1234, connection_id=1234 % ACCOUNTS + 1, day=TODAY
    ),
    "resources: the Vulnerabilities cells of a page": _vulnerability_cells,
    "resources: with an exploitable CVE, one account": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=0,
        filters=inventory.ResourceFilters(
            connection_ids=(1,), within=(findings.VULNERABLE_RESOURCES_SQL["exploitable"],)
        ),
    ),
    "resources: with a critical or high CVE, all accounts": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=0,
        filters=inventory.ResourceFilters(within=(findings.VULNERABLE_RESOURCES_SQL["high"],)),
    ),
    # The Resources filters behind the Resources summary's numbers (2026-11-06).
    "resources: with a critical or high misconfiguration, all accounts": lambda c: (
        inventory.list_resources(
            c,
            limit=20,
            offset=0,
            filters=inventory.ResourceFilters(
                assets=True, within=(findings.MISCONFIGURED_RESOURCES_SQL["high"],)
            ),
        )
    ),
    "resources: with a critical or high misconfiguration, one account": lambda c: (
        inventory.list_resources(
            c,
            limit=20,
            offset=0,
            filters=inventory.ResourceFilters(
                connection_ids=(7,),
                assets=True,
                within=(findings.MISCONFIGURED_RESOURCES_SQL["high"],),
            ),
        )
    ),
    "resources: reachable from the internet, all accounts": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=0,
        filters=inventory.ResourceFilters(
            assets=True, within=(findings.INTERNET_REACHABLE_RESOURCES_SQL,)
        ),
    ),
    "resources: assets only, all accounts": lambda c: inventory.list_resources(
        c, limit=20, offset=0, filters=inventory.ResourceFilters(assets=True)
    ),
    "resources: first seen in a week, all accounts": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=0,
        filters=inventory.ResourceFilters(
            assets=True,
            include_deleted=True,
            first_seen_from=TODAY - timedelta(days=13),
            first_seen_to=TODAY - timedelta(days=7),
        ),
    ),
    "resources: removed in a week, all accounts": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=0,
        filters=inventory.ResourceFilters(
            assets=True,
            deleted_from=TODAY - timedelta(days=13),
            deleted_to=TODAY - timedelta(days=7),
        ),
    ),
    "resources: a service's types, all accounts": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=0,
        filters=inventory.ResourceFilters(
            assets=True,
            resource_types=(
                "aws_ec2_instance",
                "aws_vpc_security_group",
                *(f"aws_ec2_type_{n}" for n in range(60)),
            ),
        ),
    ),
    "resource: its Vulnerabilities section": lambda c: (
        findings.resource_vulnerabilities(c, VULNERABLE_PAGE[0]),
        findings.resource_coverage(c, VULNERABLE_PAGE[0]),
    ),
    "findings: vulnerabilities only": lambda c: findings.list_findings(
        c, limit=20, offset=0, filters=findings.FindingFilters(tools=("vulnerabilities",))
    ),
    "vulnerabilities: with a public exploit": lambda c: findings.list_findings(
        c,
        limit=20,
        offset=0,
        filters=findings.FindingFilters(tools=("vulnerabilities",), exploitable=True),
    ),
    "vulnerabilities: by CVE, no fix yet": lambda c: findings.finding_groups(
        c,
        limit=20,
        offset=0,
        filters=findings.FindingFilters(tools=("vulnerabilities",), fix="none"),
    ),
    "vulnerabilities: facets": lambda c: findings.finding_facets(c, tools=("vulnerabilities",)),
    "resources: summary, all accounts": lambda c: metrics.resource_summary(
        c, connection_id=0, today=TODAY
    ),
    "resources: summary, one account": lambda c: metrics.resource_summary(
        c, connection_id=7, today=TODAY
    ),
    "vulnerabilities: summary, all accounts": lambda c: metrics.vulnerability_summary(
        c, connection_id=0, today=TODAY
    ),
    "vulnerabilities: summary, one account": lambda c: metrics.vulnerability_summary(
        c, connection_id=1, today=TODAY
    ),
    # Month over month alone (owner, 2026-11-10): also read by the Overview, all types only.
    "vulnerabilities: month over month, all accounts": lambda c: metrics.vulnerability_months(
        c, connection_id=0, today=TODAY
    ),
    "vulnerabilities: month over month, the stale account": lambda c: metrics.vulnerability_months(
        c, connection_id=STALE, today=TODAY
    ),
    # The summary's Top CVEs: the list by CVE with the summary's filters.
    "vulnerabilities: summary, top CVEs": lambda c: findings.finding_groups(
        c, limit=10, offset=0, filters=VULNERABILITY_SUMMARY_FILTERS
    ),
    # An age column's link, and the Fix available tile's.
    "vulnerabilities: first seen 30 to 90 days ago": lambda c: findings.list_findings(
        c,
        limit=20,
        offset=0,
        filters=replace(
            VULNERABILITY_SUMMARY_FILTERS,
            first_seen_from=TODAY - timedelta(days=89),
            first_seen_to=TODAY - timedelta(days=30),
        ),
    ),
    "vulnerabilities: summary, fix available": lambda c: findings.list_findings(
        c, limit=20, offset=0, filters=replace(VULNERABILITY_SUMMARY_FILTERS, fix="available")
    ),
    # Operate -> Reports (ADR-0047): an Admin's list of everyone's, and an Operator's own.
    "reports, an admin's list": lambda c: reports.list_reports(
        c, user_id=0, all_users=True, limit=20, offset=0
    ),
    "reports, an operator's own, a later page": lambda c: reports.list_reports(
        c, user_id=_operator(c), all_users=False, limit=20, offset=100
    ),
}


def _operator(conn: Connection) -> int:
    found: int = conn.execute(
        text("SELECT id FROM app_user WHERE username = 'budget-operator'")
    ).scalar_one()
    return found


@pytest.mark.parametrize("name", list(QUERIES))
def test_every_api_query_is_within_budget(estate: Engine, name: str) -> None:
    p95 = _p95_ms(estate, QUERIES[name])
    print(f"{name}: p95 {p95:.1f} ms")
    assert p95 < BUDGET_MS, f"{name}: p95 {p95:.1f} ms exceeds {BUDGET_MS} ms"


def test_the_overview_reads_only_the_partitions_in_its_range(estate: Engine) -> None:
    with estate.connect() as conn:
        plan = conn.execute(
            text("""
            EXPLAIN (FORMAT JSON) SELECT snapshot_date, metric, dimension, value
            FROM metric_daily WHERE connection_id = 0 AND snapshot_date BETWEEN :s AND :e
        """),
            {"s": TODAY - timedelta(days=183), "e": TODAY},
        ).scalar_one()
    scanned = set(_relations(plan))
    assert scanned, plan
    assert len(scanned) <= 8, scanned  # six months: seven or eight monthly partitions
    assert all(name.startswith("metric_daily_20") for name in scanned), scanned


def test_requirements_read_one_day(estate: Engine) -> None:
    """The requirement list reads one partition: equality on snapshot_date."""
    for table, extra in (
        ("compliance_snapshot", "AND x.connection_id = 7"),
        ("compliance_rollup", ""),
    ):
        with estate.connect() as conn:
            plan = conn.execute(
                text(f"""
                EXPLAIN (FORMAT JSON) SELECT x.* FROM {table} x
                JOIN compliance_requirement cr ON cr.id = x.requirement_id
                WHERE x.snapshot_date = :d {extra} AND cr.framework = :f
            """),  # noqa: S608 - constant SQL only
                {"d": TODAY, "f": FRAMEWORK},
            ).scalar_one()
        scanned = {n for n in _relations(plan) if n.startswith(table)}
        assert scanned == {f"{table}_{TODAY:%Y%m}"}, scanned


def _relations(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        if "Relation Name" in node:
            yield node["Relation Name"]
        for value in node.values():
            yield from _relations(value)
    elif isinstance(node, list):
        for item in node:
            yield from _relations(item)


def test_edges_of_a_day_read_one_partition(estate: Engine) -> None:
    """A map hop reads edge_snapshot by equality on snapshot_date: one monthly partition."""
    with estate.connect() as conn:
        plan = conn.execute(
            text("""
            EXPLAIN (FORMAT JSON) SELECT e.id FROM edge e
            WHERE e.source_uid = 'internet'
              AND EXISTS (SELECT 1 FROM edge_snapshot s
                          WHERE s.edge_id = e.id AND s.snapshot_date = :d)
        """),
            {"d": TODAY},
        ).scalar_one()
    scanned = {n for n in _relations(plan) if n.startswith("edge_snapshot")}
    assert scanned == {f"edge_snapshot_{TODAY:%Y%m}"}, scanned


def test_an_account_scanned_90_days_ago_shows_its_latest_scan(estate: Engine) -> None:
    """No age limit (owner's decision, 2026-11-01): the stale account's resource reads its
    inventory of 90 days ago, found through resource_load, then one partition by equality."""
    with estate.connect() as conn:
        stale = inventory.resource_at(conn, resource_id=35, day=TODAY)
        plan = conn.execute(
            text("""
            EXPLAIN (FORMAT JSON) SELECT config_id FROM resource_snapshot
            WHERE snapshot_date = :d AND resource_id = 35
        """),
            {"d": STALE_DAY},
        ).scalar_one()
    assert stale is not None and stale["connection_id"] == STALE
    assert stale["seen_on"] == STALE_DAY
    scanned = {n for n in _relations(plan) if n.startswith("resource_snapshot")}
    assert scanned == {f"resource_snapshot_{STALE_DAY:%Y%m}"}, scanned


def test_the_misconfigurations_summary_reads_one_day_of_one_scope(estate: Engine) -> None:
    """The summary's breakdowns read one day by equality: one monthly partition."""
    with estate.connect() as conn:
        plan = conn.execute(
            text("""
            EXPLAIN (FORMAT JSON) SELECT metric, dimension, value FROM metric_daily
            WHERE snapshot_date = :d AND connection_id = 0
              AND metric = ANY(CAST(:m AS text[]))
        """),
            {"d": TODAY, "m": ["misconfigurations.open_by_service"]},
        ).scalar_one()
    scanned = {n for n in _relations(plan) if n.startswith("metric_daily")}
    assert scanned == {f"metric_daily_{TODAY:%Y%m}"}, scanned


def _month_end_days() -> list[date]:
    return [end for _, end in calendar_months(TODAY)]


def test_the_month_ends_are_index_probes(estate: Engine) -> None:
    """vulnerability_months finds each month end's latest count with one probe on the marker
    per month (metric_daily_by_connection), never a scan of a partition's rows."""
    with estate.connect() as conn:
        plan = conn.execute(
            text("""
            EXPLAIN (FORMAT JSON)
            SELECT e.day, (SELECT max(m.snapshot_date) FROM metric_daily m
                           WHERE m.connection_id = 0 AND m.metric = :mm
                             AND m.dimension = 'critical' AND m.snapshot_date <= e.day)
            FROM unnest(CAST(:ends AS date[])) AS e(day)
        """),
            {"mm": "vulnerabilities.open_by_severity", "ends": _month_end_days()},
        ).scalar_one()
    scans = {
        n["Node Type"]
        for n in _nodes(plan)
        if str(n.get("Relation Name", "")).startswith("metric_daily")
    }
    assert scans and scans <= {"Index Only Scan", "Index Scan"}, scans


def test_the_month_end_rows_read_only_their_days_partitions(estate: Engine) -> None:
    """The month ends' rows are read by equality on their days: one partition per month."""
    days = _month_end_days()
    with estate.connect() as conn:
        plan = conn.execute(
            text("""
            EXPLAIN (FORMAT JSON) SELECT snapshot_date, metric, dimension, value
            FROM metric_daily
            WHERE connection_id = 0 AND snapshot_date = ANY(CAST(:days AS date[]))
              AND metric = ANY(CAST(:m AS text[]))
        """),
            {
                "days": days,
                "m": ["vulnerabilities.open_by_severity", "vulnerabilities.open_by_resource_type"],
            },
        ).scalar_one()
    scanned = {n for n in _relations(plan) if n.startswith("metric_daily")}
    assert scanned == {f"metric_daily_{d:%Y%m}" for d in days}, scanned


def _nodes(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        if "Node Type" in node:
            yield node
        for value in node.values():
            yield from _nodes(value)
    elif isinstance(node, list):
        for item in node:
            yield from _nodes(item)


# Ingest, not the API: no 300 ms budget, but a bound that catches a full scan of finding or of
# every metric_daily partition (the rollup reads each account's latest day, however old).
WRITER_BOUND_MS = 3000.0


def test_the_summary_counts_of_one_account_stay_cheap_to_write(estate: Engine) -> None:
    with estate.connect() as conn:
        transaction = conn.begin()
        try:
            start = time.perf_counter()
            findings.put_misconfiguration_metrics(conn, connection_id=7, day=TODAY)
            elapsed = (time.perf_counter() - start) * 1000
        finally:
            transaction.rollback()
    print(f"misconfigurations: one account's counts and the rollup: {elapsed:.1f} ms")
    assert elapsed < WRITER_BOUND_MS


def test_the_asset_counts_of_one_account_stay_cheap_to_write(estate: Engine) -> None:
    """After a Steampipe load: one account's assets by type and region, its added and removed,
    and the rollup of all accounts (inventory.put_inventory_metrics)."""
    with estate.connect() as conn:
        transaction = conn.begin()
        try:
            start = time.perf_counter()
            inventory.put_inventory_metrics(conn, connection_id=7, day=TODAY)
            elapsed = (time.perf_counter() - start) * 1000
        finally:
            transaction.rollback()
    print(f"assets: one account's counts and the rollup: {elapsed:.1f} ms")
    assert elapsed < WRITER_BOUND_MS


def test_the_vulnerability_counts_of_one_account_stay_cheap_to_write(estate: Engine) -> None:
    """Connection 1 holds the 50,000 CVE findings."""
    with estate.connect() as conn:
        transaction = conn.begin()
        try:
            start = time.perf_counter()
            findings.put_vulnerability_metrics(conn, connection_id=1, day=TODAY)
            elapsed = (time.perf_counter() - start) * 1000
        finally:
            transaction.rollback()
    print(f"vulnerabilities: one account's counts and the rollup: {elapsed:.1f} ms")
    assert elapsed < WRITER_BOUND_MS


@pytest.mark.parametrize(
    ("label", "connection_ids"), [("one account", [2]), ("every account", list(range(1, 37)))]
)
def test_an_export_is_measured(
    estate: Engine, tmp_path: Path, label: str, connection_ids: list[int]
) -> None:
    """A report of every open misconfiguration (ADR-0047), built as the worker builds it: not a
    300 ms query, so it is measured and recorded rather than held to the budget. The bound only
    catches a regression by an order of magnitude."""
    with estate.begin() as conn:
        conn.execute(text("DELETE FROM report_request WHERE status <> 'failed'"))
        conn.execute(
            text(
                "INSERT INTO report_request (kind, format, filters, connection_ids, requested_by) "
                "VALUES ('misconfigurations', 'csv', '{}', CAST(:c AS bigint[]), 'budget')"
            ),
            {"c": connection_ids},
        )
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    start = time.perf_counter()
    assert reports.build_pending(estate, store=reports.LocalReportStore(tmp_path))
    seconds = time.perf_counter() - start
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    with estate.connect() as conn:
        status, rows, size = conn.execute(
            text(
                "SELECT status, row_count, size_bytes FROM report_request "
                "WHERE status <> 'failed' OR requested_by = 'budget'"
            )
        ).one()
    print(
        f"export, {label}: {rows} rows, {size / 1e6:.1f} MB in {seconds:.1f} s; "
        f"peak RSS {after / 1024:.0f} MiB (before {before / 1024:.0f} MiB)"
    )
    assert status == "ready" and rows > 0
    assert seconds < 600


@pytest.mark.parametrize(
    ("label", "connection_ids"), [("one account", [2]), ("every account", list(range(1, 37)))]
)
def test_a_pdf_context_is_measured(estate: Engine, label: str, connection_ids: list[int]) -> None:
    """The data side of a PDF report (ADR-0047, round 2): read every matching finding, keep the
    capped list, read the check texts, build the context. The render side is bounded by the caps,
    not the estate, and is measured in the reports image (render.py --measure)."""
    filters = findings.FindingFilters(
        connection_ids=tuple(connection_ids), tools=("prowler", "cloudfox")
    )
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    start = time.perf_counter()
    with estate.connect() as conn:
        collected = report_pdf.collect(conn, "misconfigurations", filters)
        context = report_pdf.build_context(
            collected,
            report_id=1,
            kind="misconfigurations",
            requested_by="budget",
            generated_at=datetime(2026, 10, 3, tzinfo=UTC),
            scope_words=label,
            severities_in_scope=list(report_pdf.SEVERITIES),
            data_through={},
        )
    seconds = time.perf_counter() - start
    size = len(json.dumps(context))
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(
        f"pdf context, {label}: {collected.total} findings, {collected.listed} listed, "
        f"{len(context['blocks'])} blocks + {len(context['others'])} named, {size / 1e6:.2f} MB "
        f"in {seconds:.1f} s; peak RSS {after / 1024:.0f} MiB (before {before / 1024:.0f} MiB)"
    )
    assert collected.total > 0 and collected.listed <= report_pdf.PDF_RESOURCE_CAP
    assert seconds < 300
