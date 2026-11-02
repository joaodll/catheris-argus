# ruff: noqa: S608 - every SQL fragment here is built from this file's constants, never input
"""A realistic AWS-like estate for the graph budget (tests/budget/test_graph_budget.py), from the
graph-engine spike (ADR-0044). 300,000 resources by default; ARGUS_GRAPH_BUDGET_RESOURCES sets
another size (1,000,000 is the owner's 12-24 month target).

Unlike the budget estate's regular chains, the shape is skewed like a real organisation:
- 36 accounts of very different sizes (the largest about 9%, the smallest about 2%)
- workloads sharing few roles (RUNS_AS picks roles with a power law)
- an IAM trust graph with cycles (role -> role CAN_ASSUME, uniform)
- 1.5% of roles assumable from another account (the edge belongs to the trusting account's
  connection, as the rule that reads the trust policy runs there)
- about 2% of resources reachable from the internet
- admin pseudo-nodes admin:<account>
- node facts: failing high Prowler checks, and CVEs with a public exploit

Randomness is a hash of (g, salt), so the data is the same however Postgres orders the work.
Only edge types the attack-path search already knows are used, so today's code runs unchanged.
"""

import os
import time
from datetime import date

from sqlalchemy import Engine, text

TODAY = date(2026, 10, 30)
RESOURCES = int(os.environ.get("ARGUS_GRAPH_BUDGET_RESOURCES", "300000"))
ACCOUNTS = 36

_SETUP = [
    """
    CREATE OR REPLACE FUNCTION spike_u(g bigint, salt text) RETURNS double precision
    IMMUTABLE LANGUAGE sql AS $$
      SELECT (('x' || lpad(substr(md5(g::text || ':' || salt), 1, 8), 16, '0'))::bit(64)::bigint)
             / 4294967296.0
    $$
    """,
    "SELECT argus_ensure_partitions(CAST(:d AS date) - 1, CAST(:d AS date))",
    """
    INSERT INTO connection (id, name, kind, account_id, auth_method, demo_seed, created_by,
                            updated_by) OVERRIDING SYSTEM VALUE
    SELECT a, 'acct-' || a, 'demo', (200000000000 + a)::text, 'none', a, 'spike', 'spike'
    FROM generate_series(1, :accounts) a
    """,
    """
    CREATE UNLOGGED TABLE spike_res AS
    SELECT g, acct, kind, (200000000000 + acct)::text AS account,
           row_number() OVER (PARTITION BY acct, kind ORDER BY g)::int AS rn
    FROM (
      SELECT g, 1 + least(:accounts - 1, floor(:accounts * power(spike_u(g, 'a'), 1.5)))::int
               AS acct,
             CASE WHEN u < 0.28 THEN 'instance' WHEN u < 0.36 THEN 'lambda'
                  WHEN u < 0.46 THEN 'ecs_task' WHEN u < 0.58 THEN 'role'
                  WHEN u < 0.61 THEN 'user' WHEN u < 0.70 THEN 'sg'
                  WHEN u < 0.78 THEN 's3' WHEN u < 0.81 THEN 'rds'
                  WHEN u < 0.83 THEN 'lb' WHEN u < 0.85 THEN 'subnet'
                  WHEN u < 0.853 THEN 'vpc' ELSE 'other' END AS kind
      FROM (SELECT g, spike_u(g, 'k') AS u FROM generate_series(1, :resources) g) x
    ) y
    """,
    """
    ALTER TABLE spike_res ADD COLUMN uid text, ADD COLUMN type text, ADD COLUMN id bigint
    """,
    """
    UPDATE spike_res SET
      uid = CASE kind
        WHEN 'instance' THEN 'arn:aws:ec2:us-east-1:' || account || ':' || 'instance/i-' || g
        WHEN 'lambda' THEN 'arn:aws:lambda:us-east-1:' || account || ':function:f-' || g
        WHEN 'ecs_task' THEN 'arn:aws:ecs:us-east-1:' || account || ':' || 'task/t-' || g
        WHEN 'role' THEN 'arn:aws:iam::' || account || ':' || 'role/r-' || g
        WHEN 'user' THEN 'arn:aws:iam::' || account || ':' || 'user/u-' || g
        WHEN 'sg' THEN 'arn:aws:ec2:us-east-1:' || account || ':' || 'security-group/sg-' || g
        WHEN 's3' THEN 'arn:aws:s3:::b-' || g
        WHEN 'rds' THEN 'arn:aws:rds:us-east-1:' || account || ':db:d-' || g
        WHEN 'lb' THEN 'arn:aws:elasticloadbalancing:us-east-1:' || account
                       || ':' || 'loadbalancer/app/lb-' || g || '/x'
        WHEN 'subnet' THEN 'arn:aws:ec2:us-east-1:' || account || ':' || 'subnet/subnet-' || g
        WHEN 'vpc' THEN 'arn:aws:ec2:us-east-1:' || account || ':' || 'vpc/vpc-' || g
        ELSE 'arn:aws:kms:us-east-1:' || account || ':' || 'key/k-' || g END,
      type = CASE kind
        WHEN 'instance' THEN 'aws_ec2_instance' WHEN 'lambda' THEN 'aws_lambda_function'
        WHEN 'ecs_task' THEN 'aws_ecs_task' WHEN 'role' THEN 'aws_iam_role'
        WHEN 'user' THEN 'aws_iam_user' WHEN 'sg' THEN 'aws_vpc_security_group'
        WHEN 's3' THEN 'aws_s3_bucket' WHEN 'rds' THEN 'aws_rds_db_instance'
        WHEN 'lb' THEN 'aws_ec2_application_load_balancer' WHEN 'subnet' THEN 'aws_vpc_subnet'
        WHEN 'vpc' THEN 'aws_vpc' ELSE 'aws_kms_key' END
    """,
    """
    INSERT INTO resource (resource_uid, connection_id, region, type, native_id, name,
                          first_seen, last_seen)
    SELECT uid, acct, CASE WHEN kind IN ('role', 'user', 's3') THEN 'global' ELSE 'us-east-1' END,
           type, kind || '-' || g, kind || '-' || g, CAST(:d AS date) - 30, :d
    FROM spike_res ORDER BY g
    """,
    # Statistics before anything joins or checks a foreign key against the fresh rows: with none,
    # each foreign-key check planned as a sequential scan of the million resources.
    "ANALYZE resource",
    "UPDATE spike_res s SET id = r.id FROM resource r WHERE r.resource_uid = s.uid",
    "CREATE INDEX ON spike_res (acct, kind, rn)",
    "CREATE INDEX ON spike_res (kind)",
    "ANALYZE spike_res",
    """
    CREATE UNLOGGED TABLE spike_cnt AS
    SELECT acct, kind, count(*)::int AS n FROM spike_res GROUP BY acct, kind
    """,
    """
    INSERT INTO resource_config (config_hash, config, created_on)
    VALUES (sha256('spike'::bytea), '{}', :d)
    """,
    "ANALYZE resource_config",
    """
    INSERT INTO resource_snapshot (snapshot_date, resource_id, config_id)
    SELECT :d, id, (SELECT id FROM resource_config) FROM spike_res
    """,
    # Each account's inventory day (migration 0036): without it the projection finds no
    # inventory and writes every node as a bare stub.
    """
    INSERT INTO resource_load (connection_id, snapshot_date, resources)
    SELECT acct, :d, count(*) FROM spike_res GROUP BY acct
    """,
    """
    CREATE UNLOGGED TABLE spike_edge (src text NOT NULL, dst text NOT NULL, type text NOT NULL,
                                      origin text NOT NULL, conn int NOT NULL)
    """,
]

# One INSERT INTO spike_edge per edge family. `pick(kind, salt, power)` joins the source `s` to
# a resource of `kind` in the same account, chosen with a power law (power 1: uniform).
_PICK = """
  JOIN spike_cnt c{n} ON c{n}.acct = s.acct AND c{n}.kind = '{kind}'
  JOIN spike_res t{n} ON t{n}.acct = s.acct AND t{n}.kind = '{kind}'
   AND t{n}.rn = 1 + least(c{n}.n - 1, floor(c{n}.n * power(spike_u(s.g * 7 + {k}, '{salt}'),
                                                           {power})))::int
"""


def _pick(kind: str, salt: str, power: float = 1.0, *, n: int = 1, k: str = "0") -> str:
    return _PICK.format(kind=kind, salt=salt, power=power, n=n, k=k)


_EDGES = {
    "IN_NETWORK compute -> subnet": f"""
      SELECT s.uid, t1.uid, 'IN_NETWORK', 'rule:resource-in-network@1', s.acct
      FROM spike_res s {_pick("subnet", "net")}
      WHERE s.kind IN ('instance', 'ecs_task', 'rds', 'lb')
         OR (s.kind = 'lambda' AND spike_u(s.g, 'vpc') < 0.4)""",
    "IN_NETWORK subnet -> vpc": f"""
      SELECT s.uid, t1.uid, 'IN_NETWORK', 'rule:resource-in-network@1', s.acct
      FROM spike_res s {_pick("vpc", "vpc", 2.0)} WHERE s.kind = 'subnet'""",
    "MEMBER_OF -> security group": f"""
      SELECT s.uid, t1.uid, 'MEMBER_OF', 'rule:instance-security-group@1', s.acct
      FROM (SELECT s0.*, k FROM spike_res s0,
                   generate_series(1, 1 + floor(3 * spike_u(s0.g, 'sgn'))::int) k
            WHERE s0.kind IN ('instance', 'ecs_task', 'rds', 'lb')
               OR (s0.kind = 'lambda' AND spike_u(s0.g, 'vpc') < 0.4)) s
      {_pick("sg", "sg", 2.0, k="s.k")}""",
    "RUNS_AS workload -> role": f"""
      SELECT s.uid, t1.uid, 'RUNS_AS', 'rule:instance-role@1', s.acct
      FROM spike_res s {_pick("role", "run", 3.0)}
      WHERE (s.kind = 'instance' AND spike_u(s.g, 'prof') < 0.9)
         OR s.kind IN ('lambda', 'ecs_task')""",
    "CAN_ASSUME role -> role (same account)": f"""
      SELECT s.uid, t1.uid, 'CAN_ASSUME', 'rule:role-trust@1', s.acct
      FROM (SELECT s0.*, k FROM spike_res s0, generate_series(1, 2) k
            WHERE s0.kind = 'role'
              AND spike_u(s0.g * 3 + k, 'as') < CASE k WHEN 1 THEN 0.5 ELSE 0.1 END) s
      {_pick("role", "ast", k="s.k")} WHERE t1.uid <> s.uid""",
    "CAN_ASSUME user -> role": f"""
      SELECT s.uid, t1.uid, 'CAN_ASSUME', 'rule:role-trust@1', s.acct
      FROM (SELECT s0.*, k FROM spike_res s0,
                   generate_series(1, 1 + floor(2 * spike_u(s0.g, 'un'))::int) k
            WHERE s0.kind = 'user') s
      {_pick("role", "ut", k="s.k")}""",
    "CAN_ASSUME role -> role (cross-account)": """
      SELECT s.uid, t.uid, 'CAN_ASSUME', 'rule:role-trust@1', t.acct
      FROM spike_res s
      JOIN LATERAL (SELECT 1 + (s.acct + floor(spike_u(s.g, 'xa') * (:accounts - 1))::int)
                           % :accounts AS acct) a ON true
      JOIN spike_cnt c ON c.acct = a.acct AND c.kind = 'role'
      JOIN spike_res t ON t.acct = a.acct AND t.kind = 'role'
       AND t.rn = 1 + least(c.n - 1, floor(c.n * spike_u(s.g, 'xr'))::int)
      WHERE s.kind = 'role' AND spike_u(s.g, 'x') < 0.015""",
    "admin": """
      SELECT s.uid, 'admin:' || s.account,
             CASE WHEN s.kind = 'user' OR u < 0.03 THEN 'IS_ADMIN'
                  WHEN u < 0.05 THEN 'CAN_PRIVESC_TO' ELSE 'CAN_ESCALATE_TO' END,
             CASE WHEN s.kind = 'role' AND u >= 0.05 THEN 'rule:principal-escalation@1'
                  ELSE 'cloudfox' END,
             s.acct
      FROM (SELECT *, spike_u(g, 'adm') AS u FROM spike_res WHERE kind IN ('role', 'user')) s
      WHERE (s.kind = 'role' AND s.u < 0.06) OR (s.kind = 'user' AND s.u < 0.05)""",
    "ACCESSES role -> data store": f"""
      SELECT s.uid, CASE WHEN spike_u(s.g * 5 + s.k, 'dk') < 0.7 THEN t1.uid ELSE t2.uid END,
             'ACCESSES', 'cloudfox', s.acct
      FROM (SELECT s0.*, k FROM spike_res s0,
                   generate_series(1, floor(4 * spike_u(s0.g, 'acn'))::int) k
            WHERE s0.kind = 'role') s
      {_pick("s3", "acs", k="s.k")} {_pick("rds", "acr", n=2, k="s.k")}""",
    "ROUTES_TO load balancer -> workload": f"""
      SELECT s.uid, CASE WHEN spike_u(s.g * 5 + s.k, 'lbk') < 0.5 THEN t1.uid ELSE t2.uid END,
             'ROUTES_TO', 'rule:load-balancer-target@1', s.acct
      FROM (SELECT s0.*, k FROM spike_res s0, generate_series(1, 5) k
            WHERE s0.kind = 'lb') s
      {_pick("instance", "lbi", k="s.k")} {_pick("ecs_task", "lbe", n=2, k="s.k")}""",
    "TRIGGERS bucket -> function": f"""
      SELECT s.uid, t1.uid, 'TRIGGERS', 'rule:bucket-trigger@1', s.acct
      FROM spike_res s {_pick("lambda", "trg")}
      WHERE s.kind = 's3' AND spike_u(s.g, 'tr') < 0.1""",
    "CAN_CONNECT_TO instance -> instance": f"""
      SELECT s.uid, t1.uid, 'CAN_CONNECT_TO', 'rule:network-reach@1', s.acct
      FROM (SELECT s0.*, k FROM spike_res s0, generate_series(1, 3) k
            WHERE s0.kind = 'instance' AND spike_u(s0.g, 'lat') < 0.1) s
      {_pick("instance", "cct", k="s.k")} WHERE t1.uid <> s.uid""",
    "HAS_POLICY -> managed policy (hub)": """
      SELECT uid, 'arn:aws:iam::aws:policy/ReadOnlyAccess', 'HAS_POLICY',
             'rule:principal-policy@1', acct
      FROM spike_res WHERE kind IN ('role', 'user') AND spike_u(g, 'pol') < 0.3""",
    "internet ROUTES_TO (Argus's internet entry)": """
      SELECT 'internet', uid, 'ROUTES_TO', 'rule:internet-entry@1', acct FROM spike_res
      WHERE (kind = 'lb' AND spike_u(g, 'pub') < 0.6)
         OR (kind = 'instance' AND spike_u(g, 'pub') < 0.03)""",
    "internet INTERNET_REACHABLE (CloudFox)": """
      SELECT 'internet', uid, 'INTERNET_REACHABLE', 'cloudfox', acct FROM spike_res
      WHERE (kind = 'lb' AND spike_u(g, 'pub') < 0.6 AND spike_u(g, 'cf') < 0.5)
         OR (kind = 'instance' AND spike_u(g, 'pub') < 0.04)""",
    "internet PUBLIC_RESTRICTED (a closed door)": """
      SELECT 'internet', uid, 'PUBLIC_RESTRICTED', 'rule:internet-entry@1', acct FROM spike_res
      WHERE kind = 'instance' AND spike_u(g, 'pub') >= 0.04 AND spike_u(g, 'pub') < 0.045""",
}

_FINISH = [
    """
    INSERT INTO edge (edge_key, source_uid, target_uid, source_resource_id, target_resource_id,
                      type, origin, first_seen, last_seen, connection_id)
    SELECT DISTINCT ON (k) k, e.src, e.dst, s.id, t.id, e.type, e.origin,
           CAST(:d AS date) - 30, :d, e.conn
    FROM (SELECT sha256((type || '|' || src || '|' || dst || '|' || origin)::bytea) AS k, *
          FROM spike_edge) e
    LEFT JOIN resource s ON s.resource_uid = e.src
    LEFT JOIN resource t ON t.resource_uid = e.dst
    ORDER BY k
    """,
    "ANALYZE edge",
    """
    INSERT INTO edge_snapshot (snapshot_date, edge_id)
    SELECT day, id FROM edge, unnest(ARRAY[CAST(:d AS date), CAST(:d AS date) - 1]) day
    """,
    """
    INSERT INTO edge_load (connection_id, family, snapshot_date, edges)
    SELECT e.connection_id, CASE WHEN e.origin = 'cloudfox' THEN 'cloudfox' ELSE 'rule' END,
           s.snapshot_date, count(*)
    FROM edge_snapshot s JOIN edge e ON e.id = s.edge_id GROUP BY 1, 2, 3
    """,
    "ANALYZE edge_snapshot",
    # Node facts. A failing high Prowler check on 5% of resources.
    """
    INSERT INTO finding (finding_uid, tool, check_id, connection_id, region, resource_uid,
                         resource_id, severity, status, muted, title, service, resource_type,
                         categories, state, first_seen, last_seen)
    SELECT 'p-' || g, 'prowler', 'check_' || (g % 150), acct, 'us-east-1', uid, id, 'high',
           'FAIL', false, 'title ' || g, 'ec2', 'Other', ARRAY['spike'], 'open',
           CAST(:d AS date) - 10, :d
    FROM spike_res WHERE spike_u(g, 'fail') < 0.05
    """,
    # A CVE on 20% of workloads; a quarter of those have a public exploit.
    """
    INSERT INTO finding (finding_uid, tool, check_id, connection_id, region, resource_uid,
                         resource_id, severity, status, muted, title, service, resource_type,
                         categories, state, first_seen, last_seen)
    SELECT 'v-' || g, 'vulnerabilities', 'CVE-2025-' || (1000 + g % 900), acct, 'us-east-1',
           uid, id, 'critical', 'FAIL', false, 'CVE ' || g, 'ec2', 'AwsEc2Instance',
           ARRAY['vulnerability'], 'open', CAST(:d AS date) - 10, :d
    FROM spike_res
    WHERE kind IN ('instance', 'lambda', 'ecs_task') AND spike_u(g, 'cve') < 0.2
    """,
    "ANALYZE finding",
    """
    INSERT INTO finding_vulnerability (finding_id, scanner, kind, vulnerability_id, package_name,
                                       installed_version, fixed_version, cvss_score,
                                       epss_score, exploit_available, fix_available)
    SELECT id, 'aws-inspector', 'package', check_id, 'pkg', '1.0', '1.1', 9.8, 0.5,
           spike_u(id, 'exp') < 0.25, 'YES'
    FROM finding WHERE tool = 'vulnerabilities'
    """,
    "DROP TABLE spike_edge",
    "DROP TABLE spike_cnt",
    # One ingested run per connection: what the graph projection's marker reads.
    """
    INSERT INTO scan_run (run_uid, connection_id, tool, tool_version, source, snapshot_date,
                          status, started_at, finished_at, raw_path, ingested_at)
    SELECT gen_random_uuid(), a, 'steampipe', '1', 'synthetic', :d, 'complete',
           CAST(:d AS timestamptz), CAST(:d AS timestamptz) + interval '5 minutes', 'raw', now()
    FROM generate_series(1, :accounts) a
    """,
]


def generate(engine: Engine) -> dict[str, float]:
    """Writes the estate into an empty, migrated database. Returns timings and counts."""
    params = {"d": TODAY, "accounts": ACCOUNTS, "resources": RESOURCES}
    out: dict[str, float] = {}
    started = time.perf_counter()
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL statement_timeout = 0"))
        for sql in _SETUP:
            conn.execute(text(sql), params)
        for name, sql in _EDGES.items():
            t = time.perf_counter()
            n = conn.execute(
                text(f"INSERT INTO spike_edge (src, dst, type, origin, conn) {sql}"),
                params,
            ).rowcount
            out[f"edges: {name}"] = n
            print(f"  {name}: {n:,} in {time.perf_counter() - t:.1f} s", flush=True)
        for sql in _FINISH:
            conn.execute(text(sql), params)
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("VACUUM (ANALYZE)"))
        conn.execute(text("CHECKPOINT"))
        for table in ("resource", "edge", "finding"):
            out[f"rows: {table}"] = conn.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
        out["cross-account edges"] = conn.execute(
            text("""
            SELECT count(*) FROM edge e JOIN resource s ON s.id = e.source_resource_id
            WHERE s.connection_id <> e.connection_id
            """)
        ).scalar_one()
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE spike_res"))
    out["seconds"] = time.perf_counter() - started
    return out


def prepare(engine: Engine) -> dict[str, float]:
    """Empties the budget database's estate tables and writes the estate again."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE connection, scan_run, resource, resource_config, edge, audit_log "
                "RESTART IDENTITY CASCADE"
            )
        )
    return generate(engine)


def largest_connection(engine: Engine) -> int:
    """The connection with the most resources: the map budget's account."""
    with engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT connection_id FROM resource GROUP BY connection_id "
                    "ORDER BY count(*) DESC, connection_id LIMIT 1"
                )
            ).scalar_one()
        )


# The Resource map's hubs inside one account (the query budget's shapes: a VPC holding 20,000,
# a security group with 10,000 members, a role 5,000 resources belong to). Edge types the
# attack-path search does not walk, so the paths, and the evaluation's cost, stay the same.
_HUBS = (
    # (label, edge type, origin, hub's resource type, neighbours, layer it shows in)
    ("vpc", "IN_NETWORK", "rule:resource-in-network@1", "aws_vpc", 20_000, "network"),
    (
        "sg",
        "MEMBER_OF",
        "rule:instance-security-group@1",
        "aws_vpc_security_group",
        10_000,
        "network",
    ),
    ("role", "BELONGS_TO", "rule:resource-in-network@1", "aws_iam_role", 5_000, "identity"),
)


def add_map_hubs(engine: Engine, connection_id: int) -> dict[str, tuple[str, str]]:
    """Adds the hubs to one connection (once) and returns {label: (hub uid, layer)}. The
    caller re-projects the connection: its marker does not move with these edges."""
    hubs: dict[str, tuple[str, str]] = {}
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL statement_timeout = 0"))
        for i, (label, edge_type, origin, hub_type, wanted, layer) in enumerate(_HUBS):
            hub_id, hub_uid = conn.execute(
                text(
                    "SELECT id, resource_uid FROM resource WHERE connection_id = :c "
                    "AND type = :t ORDER BY id LIMIT 1"
                ),
                {"c": connection_id, "t": hub_type},
            ).one()
            hubs[label] = (hub_uid, layer)
            exists = conn.execute(
                text("SELECT count(*) FROM edge WHERE target_uid = :h AND type = :t"),
                {"h": hub_uid, "t": edge_type},
            ).scalar_one()
            if exists >= wanted // 2:
                continue
            ids = (
                conn.execute(
                    text(
                        """
                    INSERT INTO edge (edge_key, source_uid, target_uid, source_resource_id,
                                      target_resource_id, type, origin, first_seen, last_seen,
                                      connection_id)
                    SELECT sha256(convert_to('maphub|' || :t || '|' || r.resource_uid
                                             || '|' || :h, 'UTF8')),
                           r.resource_uid, :h, r.id, :hid, :t, :o, CAST(:d AS date) - 30, :d,
                           :c
                    FROM resource r
                    WHERE r.connection_id = :c AND r.id <> :hid
                    ORDER BY md5(r.id::text || :salt)
                    LIMIT :n
                    ON CONFLICT (edge_key) DO NOTHING
                    RETURNING id
                    """
                    ),
                    {
                        "t": edge_type,
                        "h": hub_uid,
                        "hid": hub_id,
                        "o": origin,
                        "d": TODAY,
                        "c": connection_id,
                        "salt": str(i),
                        "n": wanted,
                    },
                )
                .scalars()
                .all()
            )
            conn.execute(
                text(
                    "INSERT INTO edge_snapshot (snapshot_date, edge_id) "
                    "SELECT day, id FROM unnest(CAST(:ids AS bigint[])) id, "
                    "unnest(ARRAY[CAST(:d AS date), CAST(:d AS date) - 1]) day"
                ),
                {"ids": list(ids), "d": TODAY},
            )
            conn.execute(
                text(
                    "UPDATE edge_load SET edges = edges + :n WHERE connection_id = :c "
                    "AND family = 'rule' AND snapshot_date IN (CAST(:d AS date), "
                    "CAST(:d AS date) - 1)"
                ),
                {"n": len(ids), "c": connection_id, "d": TODAY},
            )
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("ANALYZE edge"))
        conn.execute(text("ANALYZE edge_snapshot"))
    return hubs
