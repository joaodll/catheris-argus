"""The query budget (design: "Database load and query rules"): every API query stays under
300 ms at p95 on a synthetic estate of 300,000 resources, and snapshot-range queries prune
partitions. The dataset is generated in SQL from a fixed seed, never committed.

Shape (the design's "large" scenario, 36 accounts): 300,000 resources, 300,000 open findings,
180 days of metric_daily for 36 accounts plus the rollup, 36 x 3 x 180 scan runs, 5,000 paths.
Edges (ADR-0033): about 940,000, two days of snapshots, with the hubs the Resource map must
group: `internet` reaching 5,000 resources of one account, a VPC holding 20,000, and an
AWS-managed policy attached to 10,000 principals across accounts.
Compliance as real Prowler on AWS: 40 frameworks of 100 requirements, 180 days of scores and
counts per account, and two days of requirement results per account plus their rollup.
Inspector (ADR-0042): 50,000 CVE findings on connection 1's instances and functions (15 each,
one in five resolved), with their vulnerability facts and coverage (one in seven not scanned).
"""

import math
import time
from collections.abc import Callable, Iterator
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Connection, Engine, text

from argus import (
    attackpaths,
    connections,
    findings,
    ingest,
    inventory,
    metrics,
    relationships,
    scheduling,
)
from argus.attackpaths.engine import find_paths

pytestmark = [pytest.mark.db, pytest.mark.budget]
RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
BUDGET_MS = 300.0
# p95 by nearest rank over 20 runs: the 19th fastest, so one stray run (a checkpoint, a cold
# page) is tolerated and two are not. Never interpolated past the slowest run (2026-10-09).
RUNS = 20
TODAY = date(2026, 10, 3)
ACCOUNTS = 36
FRAMEWORKS = 40
REQUIREMENTS = 100
FRAMEWORK = "fw_7_aws"


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
                              first_seen, last_seen)
        SELECT 'arn:aws:ec2:us-east-1:' || (200000000000 + 1 + g % :n) || ':' || 'instance/i-' || g,
               1 + g % :n, 'us-east-1',
               (ARRAY['aws_ec2_instance','aws_lambda_function','aws_s3_bucket','aws_iam_role',
                      'aws_vpc_security_group'])[1 + g % 5],
               'i-' || g, 'r' || g, :d, :d
        FROM generate_series(1, 300000) g
    """),
        {"n": ACCOUNTS, "d": TODAY},
    )
    conn.execute(
        text("""
        INSERT INTO finding (finding_uid, tool, check_id, connection_id, region, resource_uid,
                             severity, status, muted, title, service, resource_type, categories,
                             state, first_seen, last_seen, resolved_on, reach, reach_reason)
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
               CASE WHEN g % 50 = 1 AND g / 50 % 4 = 1 THEN 'nacl_blocks' END
        FROM generate_series(1, 400000) g
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
                     ('attack_paths.open_by_severity', 'critical'),
                     ('attack_paths.open_by_category', 'IAM privilege escalation'),
                     ('assets.by_type', 'aws_ec2_instance'), ('assets.by_type', 'aws_s3_bucket'),
                     ('assets.by_type', 'aws_iam_role')) AS m(m, dim)
    """),
        {"n": ACCOUNTS, "d": TODAY},
    )
    conn.execute(
        text("""
        INSERT INTO attack_path (path_id, rule_id, rule_version, category, severity,
                                 connection_id, entry_uid, target_uid, node_uids, edge_ids, state,
                                 first_seen, last_seen, confidence)
        SELECT sha256(('p' || g)::bytea), 'r', 1, 'IAM privilege escalation',
               (ARRAY['critical','high','medium'])[1 + g % 3], 1 + g % :n, 'internet',
               't' || g, ARRAY['internet', 't' || g], ARRAY[]::bigint[], 'open', :d, :d,
               (ARRAY['confirmed','supported','candidate','unknown'])[1 + g % 4]
        FROM generate_series(1, 5000) g
    """),
        {"n": ACCOUNTS, "d": TODAY},
    )
    _generate_edges(conn)
    _generate_compliance(conn)
    _generate_vulnerabilities(conn)
    conn.execute(text("ANALYZE"))


def _generate_vulnerabilities(conn: Connection) -> None:
    conn.execute(
        text("""
        INSERT INTO finding (finding_uid, tool, check_id, connection_id, region, resource_uid,
                             resource_id, severity, status, muted, title, service,
                             resource_type, categories, state, first_seen, last_seen,
                             resolved_on)
        SELECT 'insp-' || r.id || '-' || k, 'inspector', 'CVE-2024-' || (1000 + k * 37 % 900),
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
        INSERT INTO finding_vulnerability (finding_id, finding_type, vulnerability_id,
                                           package_name, installed_version, fixed_version,
                                           cvss_score, epss_score, exploit_available,
                                           fix_available)
        SELECT id, 'PACKAGE_VULNERABILITY', check_id, 'pkg', '1.0', '1.1',
               round((random() * 10)::numeric, 1), random(), id % 4 = 0, 'YES'
        FROM finding WHERE tool = 'inspector'
    """)
    )
    conn.execute(
        text("""
        INSERT INTO vulnerability_coverage (resource_id, scan_type, connection_id, status_code,
                                            status_reason, last_scanned_at)
        SELECT DISTINCT resource_id, 'PACKAGE', 1,
               CASE WHEN resource_id % 7 = 0 THEN 'INACTIVE' ELSE 'ACTIVE' END,
               CASE WHEN resource_id % 7 = 0 THEN 'UNMANAGED_EC2_INSTANCE' ELSE 'SUCCESSFUL' END,
               CAST(:d AS timestamptz)
        FROM finding WHERE tool = 'inspector'
    """),
        {"d": TODAY},
    )


HUB_VPC = "arn:aws:ec2:us-east-1:200000000001:vpc/vpc-hub"
HUB_POLICY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
# Resource 30 (an instance of connection 31): one of the VPC hub's 20,000 members.
MAP_FOCUS = "arn:aws:ec2:us-east-1:200000000031:instance/i-30"
# Connection c holds account 2000000000cc: every map read is for one connection (ADR-0033).
MAP_SCOPE = {"scope": relationships.MapScope(31, "200000000031")}
HUB_SCOPE = {"scope": relationships.MapScope(1, "200000000001")}
FLOWS: dict[str, float] = {}
PATHS: dict[str, float] = {}
# Connection 1's instances (resource ids are the generator's g; g % 36 == 0, g % 5 == 0): one
# page of the Resources list, each with 15 CVEs.
VULNERABLE_PAGE = [180 * i for i in range(1, 21)]


def _vulnerability_cells(c: Connection) -> Any:
    return (
        findings.vulnerability_counts(c, VULNERABLE_PAGE),
        findings.scanned_resources(c, VULNERABLE_PAGE),
    )


def _a_flow(c: Connection) -> Any:
    flow_id = c.execute(text("SELECT min(flow_id) FROM flow_snapshot")).scalar_one()
    return relationships.flow_detail(c, flow_id=flow_id, day=TODAY)


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
        -- Every tenth resource on the hub's chains is an administrator (CloudFox): the
        -- attack-path search has a target to rebuild paths to (ADR-0037).
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
                "platform_setting, flow_shape, flow_snapshot RESTART IDENTITY CASCADE"
            )
        )
        _generate(conn)
    # Flow mode: connection 1 holds the internet hub's 5,000 entries, each the head of a
    # ROUTES_TO chain (g -> g+36 -> ...). Written by ingest's own code, which this also times.
    started = time.perf_counter()
    FLOWS["written"] = relationships.write_flows(migrated, connection_id=1, day=TODAY)
    FLOWS["seconds"] = time.perf_counter() - started
    # The attack-path search (ADR-0037) from the same 5,000 entries, read-only: timed, not
    # written, so the seeded paths the list queries read stay as they are.
    kinds = attackpaths.load_path_kinds(RULES_DIR)
    started = time.perf_counter()
    PATHS["found"] = len(find_paths(migrated, kinds=kinds, connection_id=1, day=TODAY))
    PATHS["seconds"] = time.perf_counter() - started
    # A steady-state database: the first reads of freshly inserted rows would otherwise pay
    # for setting their hint bits and flushing the load, and time that instead of the query.
    with migrated.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("VACUUM (ANALYZE)"))
        conn.execute(text("CHECKPOINT"))
    return migrated


def _p95_ms(engine: Engine, query: Callable[[Connection], Any]) -> float:
    timings = []
    with engine.connect() as conn:
        query(conn)  # warm
        for _ in range(RUNS):
            start = time.perf_counter()
            query(conn)
            timings.append((time.perf_counter() - start) * 1000)
    return sorted(timings)[math.ceil(0.95 * len(timings)) - 1]


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
    "findings, Prowler exposure counts for a page of doors": lambda c: (
        findings.open_exposure_counts(c, list(range(1, 2000, 100)))
    ),
    "findings by check, no filter": lambda c: findings.finding_groups(c, limit=20, offset=0),
    "findings by check, past the last page": lambda c: findings.finding_groups(
        c, limit=20, offset=10000
    ),
    "findings by check, one account": lambda c: findings.finding_groups(
        c, limit=20, offset=0, filters=findings.FindingFilters(connection_ids=(7,))
    ),
    "findings, facets": findings.finding_facets,
    "findings, facets, two accounts": lambda c: findings.finding_facets(c, connection_ids=(7, 8)),
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
        filters=inventory.ResourceFilters(connection_id=7, resource_type="aws_s3_bucket"),
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
    "resources, facets": lambda c: inventory.resource_facets(c, connection_id=None),
    "resources, names for a page": lambda c: inventory.resource_names(c, list(range(1000, 1020))),
    "resource as of a day": lambda c: inventory.resource_at(c, resource_id=1234, day=TODAY),
    "edges as of a day": lambda c: relationships.edges_at(
        c, resource_id=1234, connection_id=1234 % ACCOUNTS + 1, day=TODAY
    ),
    "attack paths": lambda c: attackpaths.list_paths(c, limit=50, offset=0),
    "attack paths, newest first": lambda c: attackpaths.list_paths(
        c, limit=20, offset=0, order="last_seen_desc"
    ),
    "attack paths, one confidence": lambda c: attackpaths.list_paths(
        c, limit=50, offset=0, filters=attackpaths.PathFilters(confidences=("candidate",))
    ),
    "attack paths, one kind": lambda c: attackpaths.list_paths(
        c, limit=20, offset=0, filters=attackpaths.PathFilters(kinds=("r",))
    ),
    "attack paths through a resource": lambda c: attackpaths.list_paths(
        c, limit=6, offset=0, filters=attackpaths.PathFilters(through_uid="t4242")
    ),
    "map: a neighbourhood, depth 2": lambda c: relationships.neighbourhood(
        c, focus=MAP_FOCUS, depth=2, day=TODAY, **MAP_SCOPE
    ),
    "map: a neighbourhood, depth 3, every layer": lambda c: relationships.neighbourhood(
        c,
        focus=MAP_FOCUS,
        **MAP_SCOPE,
        depth=3,
        day=TODAY,
        layers=("traffic", "identity", "network", "policy"),
    ),
    "map: the internet hub": lambda c: relationships.neighbourhood(
        c, focus="internet", depth=1, day=TODAY, **HUB_SCOPE
    ),
    "map: a group's first page": lambda c: relationships.group_members(
        c,
        anchor=HUB_VPC,
        **HUB_SCOPE,
        direction="in",
        edge_type="IN_NETWORK",
        resource_type="aws_ec2_instance",
        day=TODAY,
        limit=20,
        offset=0,
    ),
    "map: front doors": lambda c: relationships.front_doors(
        c, connection_id=1, day=TODAY, limit=20, offset=0
    ),
    "map: front doors, a later page": lambda c: relationships.front_doors(
        c, connection_id=1, day=TODAY, limit=20, offset=4000
    ),
    "map: front doors in one region": lambda c: relationships.front_doors(
        c, connection_id=1, day=TODAY, limit=20, offset=0, regions=("us-east-1",)
    ),
    "map: front doors Argus cannot judge": lambda c: relationships.front_doors(
        c, connection_id=1, day=TODAY, limit=20, offset=0, reach=("unknown",)
    ),
    "map: front doors matching a search": lambda c: relationships.front_doors(
        c, connection_id=1, day=TODAY, limit=20, offset=0, q="s3"
    ),
    "map: a flow": _a_flow,
    "resources: the Vulnerabilities cells of a page": _vulnerability_cells,
    "resources: with an exploitable CVE, one account": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=0,
        filters=inventory.ResourceFilters(
            connection_id=1, within=findings.VULNERABLE_RESOURCES_SQL["exploitable"]
        ),
    ),
    "resources: with a critical or high CVE, all accounts": lambda c: inventory.list_resources(
        c,
        limit=20,
        offset=0,
        filters=inventory.ResourceFilters(within=findings.VULNERABLE_RESOURCES_SQL["high"]),
    ),
    "resource: its Inspector section": lambda c: (
        findings.resource_vulnerabilities(c, VULNERABLE_PAGE[0]),
        findings.resource_coverage(c, VULNERABLE_PAGE[0]),
    ),
    "findings: Inspector's only": lambda c: findings.list_findings(
        c, limit=20, offset=0, filters=findings.FindingFilters(tools=("inspector",))
    ),
}


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


def test_flows_are_written_for_every_entry_of_the_hub(estate: Engine) -> None:
    """Ingest's flow walk at the hub's scale: 5,000 entries, each the head of a chain."""
    print(f"flows: {FLOWS['written']:.0f} written in {FLOWS['seconds']:.1f} s")
    assert FLOWS["written"] == 5000
    assert FLOWS["seconds"] < 300
    detail = relationships.flow_detail(estate.connect(), flow_id=1, day=TODAY)
    assert detail and detail["depth"] >= 5  # the chain runs on, step by step


def test_the_path_search_walks_every_entry_of_the_hub(estate: Engine) -> None:
    """Ingest's attack-path search at the hub's scale (ADR-0037): 5,000 entries, each the head
    of a chain, walked to depth 8."""
    print(f"path search: {PATHS['found']:.0f} paths in {PATHS['seconds']:.1f} s")
    assert PATHS["found"] > 1000  # rebuilt paths, not only the walk
    assert PATHS["seconds"] < 300
