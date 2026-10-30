"""Finding lifecycle and day snapshots for one run (design: "Ingestion, snapshots and attack
paths", step 2). The same rules apply to every tool's findings:

- A finding seen again stays open (last_seen moves).
- A finding missing from a COMPLETE run that evaluated the same check in the same region is
  resolved. A partial or failed run never resolves anything: a scan timeout must not look
  like a fix.
- A resolved finding that comes back is reopened, which the dashboards count as a regression.
- Re-ingesting a run changes nothing: transitions only fire on a change of state.

A partial Prowler run still records what it evaluated: the day's check results and compliance
(ThreatScore) come from the run itself. On a real account Prowler is often throttled
somewhere, so carrying the previous day forward would hide its results for good. The cost is
that a throttled day can undercount; the run is shown as Partial. Only a failed run, which has
no results, carries the previous day forward (ingest).
"""

import json
from collections.abc import Mapping, Sequence
from datetime import date

from sqlalchemy import Connection, text

from argus import connections, metrics
from argus.core.resolver import record_unresolved, resolve
from argus.findings.model import SEVERITIES, CheckText, FindingResult
from argus.findings.prowler import ProwlerBatch
from argus.inventory import RESOURCES_ON_DAY_SQL, resource_id_sql

SEVERITY_CODE = {s: i + 1 for i, s in enumerate(SEVERITIES)}
STATUS_CODE = {"FAIL": 1, "MANUAL": 2}
CHECK_METRICS = ["checks.status", "checks.failed_by_severity"]
CARRY_FORWARD_DAYS = 31


def _record_unresolved(
    conn: Connection, tool: str, connection_id: int, ref: str, day: date
) -> None:
    record_unresolved(
        conn,
        tool=tool,
        connection_id=connection_id,
        raw_ref=ref,
        reason="not an ARN or known short id",
        day=day,
    )


def _events(conn: Connection, events: list[dict[str, object]], scan_run_id: int) -> None:
    if events:
        conn.execute(
            text(
                "INSERT INTO finding_event (occurred_on, finding_id, event, scan_run_id) "
                "VALUES (:d, :id, :e, :run)"
            ),
            [{**e, "run": scan_run_id} for e in events],
        )


def _upsert_findings(
    conn: Connection,
    *,
    tool: str,
    findings: list[FindingResult],
    connection_id: int,
    day: date,
    account_id: str,
    scan_run_id: int,
) -> dict[str, tuple[int, str]]:
    uids = [f.finding_uid for f in findings]
    before = {
        row.finding_uid: row.state
        for row in conn.execute(
            text("SELECT finding_uid, state FROM finding WHERE finding_uid = ANY(:u)"), {"u": uids}
        )
    }
    rows = []
    for f in findings:
        resource_uid = resolve(f.resource_uid, account_id=account_id, region=f.region)
        if resource_uid is None:
            _record_unresolved(conn, tool, connection_id, f.resource_uid, day)
        rows.append(
            {
                "uid": f.finding_uid,
                "tool": tool,
                "check": f.check_id,
                "c": connection_id,
                "region": f.region,
                "ruid": resource_uid or f.resource_uid,
                "sev": f.severity,
                "status": f.status,
                "muted": f.muted,
                "title": f.title,
                "rtext": f.remediation_text,
                "rurl": f.remediation_url,
                "comp": json.dumps(f.compliance),
                "svc": f.service,
                "rtype": f.resource_type,
                "cats": list(f.categories),
                "detail": f.detail,
                "rname": f.resource_name,
                "d": day,
            }
        )
    if rows:
        conn.execute(
            text(f"""
            INSERT INTO finding (finding_uid, tool, check_id, connection_id, region, resource_uid,
                                 resource_id, severity, status, muted, title, remediation_text,
                                 remediation_url, compliance, service, resource_type,
                                 categories, detail, resource_name, state, first_seen,
                                 last_seen)
            VALUES (:uid, :tool, :check, :c, :region, :ruid,
                    {resource_id_sql("ruid")}, :sev, :status, :muted,
                    :title, :rtext, :rurl, CAST(:comp AS jsonb), :svc, :rtype,
                    CAST(:cats AS text[]), :detail, :rname, 'open', :d, :d)
            ON CONFLICT (finding_uid) DO UPDATE SET
              severity = EXCLUDED.severity, status = EXCLUDED.status, muted = EXCLUDED.muted,
              title = EXCLUDED.title, remediation_text = EXCLUDED.remediation_text,
              remediation_url = EXCLUDED.remediation_url, compliance = EXCLUDED.compliance,
              service = EXCLUDED.service, resource_type = EXCLUDED.resource_type,
              categories = EXCLUDED.categories, detail = EXCLUDED.detail,
              resource_name = EXCLUDED.resource_name,
              -- A name-only reference (a load balancer) resolved since the last scan.
              resource_uid = EXCLUDED.resource_uid,
              resource_id = COALESCE(EXCLUDED.resource_id, finding.resource_id),
              first_seen = LEAST(finding.first_seen, EXCLUDED.first_seen),
              last_seen = GREATEST(finding.last_seen, EXCLUDED.last_seen),
              state = CASE WHEN finding.state = 'resolved' THEN 'reopened' ELSE finding.state END,
              resolved_on = CASE WHEN finding.state = 'resolved' THEN NULL
                                 ELSE finding.resolved_on END
        """),  # noqa: S608 - exported SQL constants only
            rows,
        )
    after = {
        row.finding_uid: (row.id, row.state)
        for row in conn.execute(
            text("SELECT id, finding_uid, state FROM finding WHERE finding_uid = ANY(:u)"),
            {"u": uids},
        )
    }
    events = [
        {"d": day, "id": after[uid][0], "e": "opened" if uid not in before else "reopened"}
        for uid in uids
        if uid not in before or (before[uid] == "resolved" and after[uid][1] == "reopened")
    ]
    _events(conn, events, scan_run_id)
    return after


# A region in an executed (check, region) pair meaning "every region": a tool that scans every
# enabled region and does not list them (CloudFox) covers all of a connection's findings.
ANY_REGION = "*"


def _resolve_missing(
    conn: Connection,
    *,
    tool: str,
    executed: frozenset[tuple[str, str]],
    connection_id: int,
    day: date,
    scan_run_id: int,
) -> int:
    """Resolves the tool's open findings for this connection that the run did not report,
    within the (check, region) pairs the run evaluated (ANY_REGION matches every region)."""
    resolved = (
        conn.execute(
            text("""
        UPDATE finding SET state = 'resolved', resolved_on = :d
        WHERE connection_id = :c AND tool = :tool AND state IN ('open', 'reopened')
          AND last_seen < :d
          AND EXISTS (SELECT 1 FROM unnest(CAST(:checks AS text[]), CAST(:regions AS text[]))
                      AS e(check_id, region)
                      WHERE e.check_id = finding.check_id
                        AND (e.region = finding.region OR e.region = :any))
        RETURNING id
    """),
            {
                "d": day,
                "c": connection_id,
                "tool": tool,
                "checks": [c for c, _ in executed],
                "regions": [r for _, r in executed],
                "any": ANY_REGION,
            },
        )
        .scalars()
        .all()
    )
    _events(conn, [{"d": day, "id": i, "e": "resolved"} for i in resolved], scan_run_id)
    return len(resolved)


def _snapshot(
    conn: Connection,
    *,
    tool: str,
    findings: list[FindingResult],
    complete: bool,
    ids: dict[str, tuple[int, str]],
    connection_id: int,
    day: date,
) -> int:
    params = {"d": day, "c": connection_id, "tool": tool}
    conn.execute(
        text("""
        DELETE FROM finding_snapshot fs USING finding f
        WHERE fs.finding_id = f.id AND fs.snapshot_date = :d AND f.connection_id = :c
          AND f.tool = :tool
    """),
        params,
    )
    rows = [
        {
            "d": day,
            "id": ids[f.finding_uid][0],
            "s": STATUS_CODE[f.status],
            "sev": SEVERITY_CODE.get(f.severity, 5),
            "m": f.muted,
        }
        for f in findings
    ]
    if rows:
        conn.execute(
            text(
                "INSERT INTO finding_snapshot (snapshot_date, finding_id, status, "
                "severity, muted) VALUES (:d, :id, :s, :sev, :m) "
                "ON CONFLICT DO NOTHING"
            ),
            rows,
        )
    carried = 0
    if not complete:
        carried = conn.execute(
            text("""
            INSERT INTO finding_snapshot (snapshot_date, finding_id, status, severity, muted)
            SELECT :d, prev.finding_id, prev.status, prev.severity, prev.muted
            FROM finding_snapshot prev JOIN finding f ON f.id = prev.finding_id
            WHERE f.connection_id = :c AND f.tool = :tool
              AND f.state IN ('open', 'reopened', 'accepted_risk')
              AND prev.snapshot_date = (
                SELECT max(s.snapshot_date) FROM finding_snapshot s
                JOIN finding f2 ON f2.id = s.finding_id
                WHERE f2.connection_id = :c AND f2.tool = :tool
                  AND s.snapshot_date < :d AND s.snapshot_date >= :d - :window)
            ON CONFLICT DO NOTHING
        """),
            {**params, "window": CARRY_FORWARD_DAYS},
        ).rowcount
    return len(rows) + carried


def load_tool_findings(
    conn: Connection,
    *,
    tool: str,
    findings: list[FindingResult],
    executed: frozenset[tuple[str, str]],
    complete: bool,
    connection_id: int,
    day: date,
    account_id: str,
    scan_run_id: int,
) -> dict[str, int]:
    """Lifecycle and day snapshot for one run's findings, any tool."""
    ids = _upsert_findings(
        conn,
        tool=tool,
        findings=findings,
        connection_id=connection_id,
        day=day,
        account_id=account_id,
        scan_run_id=scan_run_id,
    )
    resolved = (
        _resolve_missing(
            conn,
            tool=tool,
            executed=executed,
            connection_id=connection_id,
            day=day,
            scan_run_id=scan_run_id,
        )
        if complete
        else 0
    )
    snapshot = _snapshot(
        conn,
        tool=tool,
        findings=findings,
        complete=complete,
        ids=ids,
        connection_id=connection_id,
        day=day,
    )
    _refresh_facets(conn, connection_id=connection_id)
    return {"findings": len(findings), "resolved": resolved, "snapshot_rows": snapshot}


def _refresh_facets(conn: Connection, *, connection_id: int) -> None:
    """Rebuilds the connection's Findings filter options from its findings (migration 0009):
    the list reads these instead of a DISTINCT over every finding."""
    conn.execute(text("DELETE FROM finding_facet WHERE connection_id = :c"), {"c": connection_id})
    conn.execute(
        text("""
        INSERT INTO finding_facet (connection_id, facet, tool, value)
        SELECT DISTINCT f.connection_id, v.facet, f.tool, v.value
        FROM finding f,
             LATERAL (VALUES ('region', f.region), ('service', f.service),
                             ('resource_type', f.resource_type), ('check', f.check_id)
                      UNION ALL SELECT 'category', unnest(f.categories)) v(facet, value)
        WHERE f.connection_id = :c AND v.value IS NOT NULL
    """),
        {"c": connection_id},
    )


def _frameworks(conn: Connection, batch: ProwlerBatch) -> None:
    """The framework catalog (migration 0013). A name Prowler stops writing is kept."""
    if not batch.frameworks:
        return
    conn.execute(
        text("""
        INSERT INTO compliance_framework (framework, family, name, version, provider)
        VALUES (:f, :family, :name, :v, :p)
        ON CONFLICT (framework) DO UPDATE SET
          family = coalesce(EXCLUDED.family, compliance_framework.family),
          name = coalesce(EXCLUDED.name, compliance_framework.name),
          version = EXCLUDED.version
    """),
        [
            {
                "f": f.framework,
                "family": f.family,
                "name": f.name,
                "v": f.version,
                "p": f.framework.rpartition("_")[2] if "_" in f.framework else "",
            }
            # In key order: two accounts' loads lock the shared rows in the same order.
            for f in sorted(batch.frameworks, key=lambda f: f.framework)
        ],
    )


def _rollup(conn: Connection, day: date) -> None:
    """Rebuilds the day's all-connections requirement status from each enabled connection's
    latest requirement results on or before the day (at most CARRY_FORWARD_DAYS old), as the
    all-connections metrics are (metrics.rollup, decided 2026-10-08).

    Serialised per day like metrics.rollup: two workers finishing different connections would
    otherwise both delete and both insert."""
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtext('argus.compliance.rollup'), :d)"),
        {"d": (day - date(2000, 1, 1)).days},
    )
    conn.execute(text("DELETE FROM compliance_rollup WHERE snapshot_date = :d"), {"d": day})
    conn.execute(
        text(f"""
        WITH latest AS (
          SELECT connection_id, max(snapshot_date) AS day FROM compliance_snapshot
          WHERE snapshot_date <= :d AND snapshot_date >= CAST(:d AS date) - :window
          GROUP BY connection_id
        )
        INSERT INTO compliance_rollup (snapshot_date, requirement_id, fail_connections,
                                       manual_connections, pass_connections, passed_checks,
                                       failed_checks)
        SELECT :d, cs.requirement_id,
               count(*) FILTER (WHERE cs.status = 1), count(*) FILTER (WHERE cs.status = 2),
               count(*) FILTER (WHERE cs.status = 3), sum(cs.passed_checks),
               sum(cs.failed_checks)
        FROM latest l
        JOIN compliance_snapshot cs ON cs.connection_id = l.connection_id
                                   AND cs.snapshot_date = l.day
        JOIN ({connections.DIRECTORY_SQL}) c ON c.id = l.connection_id AND c.enabled
        WHERE cs.snapshot_date <= :d AND cs.snapshot_date >= CAST(:d AS date) - :window
        GROUP BY cs.requirement_id
    """),  # noqa: S608 - an exported SQL constant only
        {"d": day, "window": CARRY_FORWARD_DAYS},
    )


def carry_forward_compliance(conn: Connection, *, day: date, connection_id: int) -> int:
    """For a failed Prowler run: the day keeps what it already has, otherwise the connection's
    most recent earlier requirement results (within CARRY_FORWARD_DAYS), as its metrics are
    (metrics.copy_previous). The all-connections rollup is rebuilt either way."""
    copied = int(
        conn.execute(
            text("""
        INSERT INTO compliance_snapshot (snapshot_date, connection_id, requirement_id,
                                         scan_run_id, status, passed_checks, failed_checks)
        SELECT :d, connection_id, requirement_id, scan_run_id, status, passed_checks,
               failed_checks
        FROM compliance_snapshot
        WHERE connection_id = :c
          AND NOT EXISTS (SELECT 1 FROM compliance_snapshot
                          WHERE snapshot_date = :d AND connection_id = :c)
          AND snapshot_date = (
            SELECT max(snapshot_date) FROM compliance_snapshot
            WHERE connection_id = :c AND snapshot_date < :d
              AND snapshot_date >= :d - :window)
    """),
            {"d": day, "c": connection_id, "window": CARRY_FORWARD_DAYS},
        ).rowcount
    )
    _rollup(conn, day)
    return copied


def _compliance(
    conn: Connection, batch: ProwlerBatch, connection_id: int, day: date, scan_run_id: int
) -> int:
    conn.execute(
        text("DELETE FROM compliance_snapshot WHERE snapshot_date = :d AND connection_id = :c"),
        {"d": day, "c": connection_id},
    )
    _frameworks(conn, batch)
    if not batch.requirements:
        _rollup(conn, day)
        return 0
    conn.execute(
        text("""
        INSERT INTO compliance_requirement (framework, framework_version, requirement_id,
                                            description, title, section, level_of_risk, weight)
        VALUES (:f, :v, :r, :desc, :title, :section, :risk, :weight)
        ON CONFLICT (framework, framework_version, requirement_id) DO UPDATE SET
          description = EXCLUDED.description, title = EXCLUDED.title,
          section = EXCLUDED.section, level_of_risk = EXCLUDED.level_of_risk,
          weight = EXCLUDED.weight
    """),
        [
            {
                "f": r.framework,
                "v": r.version,
                "r": r.requirement_id,
                "desc": r.description,
                "title": r.title,
                "section": r.section,
                "risk": r.level_of_risk,
                "weight": r.weight,
            }
            for r in batch.requirements
        ],
    )
    loaded = int(
        conn.execute(
            text("""
        INSERT INTO compliance_snapshot (snapshot_date, connection_id, requirement_id,
                                         scan_run_id, status, passed_checks, failed_checks)
        SELECT :d, :c, cr.id, :run, :s, :p, :fl
        FROM compliance_requirement cr
        WHERE cr.framework = :f AND cr.framework_version = :v AND cr.requirement_id = :r
    """),
            [
                {
                    "d": day,
                    "c": connection_id,
                    "run": scan_run_id,
                    "s": r.status,
                    "p": r.passed,
                    "fl": r.failed,
                    "f": r.framework,
                    "v": r.version,
                    "r": r.requirement_id,
                }
                for r in batch.requirements
            ],
        ).rowcount
    )
    _rollup(conn, day)
    return loaded


def _check_metrics(conn: Connection, batch: ProwlerBatch, connection_id: int, day: date) -> None:
    values: dict[tuple[str, str], float] = {}
    for (status, severity, muted), n in batch.counts.items():
        key = ("checks.status", "MUTED" if muted else status)
        values[key] = values.get(key, 0) + n
        if status == "FAIL" and not muted:
            sev_key = ("checks.failed_by_severity", severity)
            values[sev_key] = values.get(sev_key, 0) + n
    metrics.put(conn, day=day, connection_id=connection_id, values=values)


def load_checks(conn: Connection, *, tool: str, tool_version: str, checks: list[CheckText]) -> int:
    """Each check's own text, replaced by the latest load of the tool (a newer version's wording
    wins). Returns the checks written."""
    if not checks:
        return 0
    conn.execute(
        text("""
        INSERT INTO finding_check_text (tool, check_id, tool_version, description, risk, links,
                                   code_cli, code_native_iac, code_terraform, code_other, notes)
        VALUES (:tool, :check, :version, :description, :risk, CAST(:links AS text[]), :cli,
                :iac, :terraform, :other, :notes)
        ON CONFLICT (tool, check_id) DO UPDATE SET
          tool_version = EXCLUDED.tool_version, description = EXCLUDED.description,
          risk = EXCLUDED.risk, links = EXCLUDED.links, code_cli = EXCLUDED.code_cli,
          code_native_iac = EXCLUDED.code_native_iac, code_terraform = EXCLUDED.code_terraform,
          code_other = EXCLUDED.code_other, notes = EXCLUDED.notes, updated_at = now()
    """),
        [
            {
                "tool": tool,
                "check": c.check_id,
                "version": tool_version,
                "description": c.description,
                "risk": c.risk,
                "links": list(c.links),
                "cli": c.code_cli,
                "iac": c.code_native_iac,
                "terraform": c.code_terraform,
                "other": c.code_other,
                "notes": c.notes,
            }
            # In check order: two accounts' loads lock the shared rows in the same order.
            for c in sorted(checks, key=lambda c: c.check_id)
        ],
    )
    return len(checks)


def load_prowler(
    conn: Connection,
    *,
    batch: ProwlerBatch,
    connection_id: int,
    day: date,
    account_id: str,
    scan_run_id: int,
) -> dict[str, int]:
    loaded = load_tool_findings(
        conn,
        tool="prowler",
        findings=batch.findings,
        executed=batch.executed,
        complete=batch.complete,
        connection_id=connection_id,
        day=day,
        account_id=account_id,
        scan_run_id=scan_run_id,
    )
    loaded["requirements"] = _compliance(conn, batch, connection_id, day, scan_run_id)
    loaded["checks"] = load_checks(
        conn, tool="prowler", tool_version=batch.tool_version, checks=list(batch.checks.values())
    )
    _check_metrics(conn, batch, connection_id, day)
    return loaded


def set_reach(
    conn: Connection,
    *,
    connection_id: int,
    check_ids: Sequence[str],
    doors: Mapping[str, tuple[str, str | None]],
    rules_judge: bool = False,
    rule_day: date | None = None,
) -> int:
    """Records, on these checks' findings in one account, what Argus's internet rules say about
    their resource (ADR-0035): its door's reach ("confirmed", "restricted", "unknown") and
    reason. With no door: when `rules_judge` (every resource these checks name is a type the
    rules judge: Prowler's exposure checks), "restricted" with no_door if the resource is in the
    inventory the rules judged on `rule_day`, else "not_covered" with not_in_inventory; without
    it (CloudFox names types no rule judges), "not_covered". Returns how many findings changed."""
    changed: int = conn.execute(
        text(f"""
        UPDATE finding f SET reach = v.reach, reach_reason = v.reason
        FROM (
          SELECT f2.id,
                 COALESCE(m.reach, CASE WHEN j.judged THEN 'restricted' ELSE 'not_covered' END)
                   AS reach,
                 CASE WHEN m.uid IS NOT NULL THEN m.reason
                      WHEN NOT :judge THEN NULL
                      WHEN j.judged THEN 'no_door' ELSE 'not_in_inventory' END AS reason
          FROM finding f2
          LEFT JOIN unnest(CAST(:uids AS text[]), CAST(:reaches AS text[]),
                           CAST(:reasons AS text[])) AS m(uid, reach, reason)
            ON m.uid = f2.resource_uid
          CROSS JOIN LATERAL (
            SELECT m.uid IS NULL AND :judge AND EXISTS (
              SELECT 1 FROM ({RESOURCES_ON_DAY_SQL}) r WHERE r.uid = f2.resource_uid)
          ) j(judged)
          WHERE f2.connection_id = :connection_id AND f2.check_id = ANY(CAST(:chk AS text[]))
        ) v
        WHERE f.id = v.id AND (f.reach, f.reach_reason) IS DISTINCT FROM (v.reach, v.reason)
    """),  # noqa: S608 - exported SQL constants only
        {
            "connection_id": connection_id,
            "chk": list(check_ids),
            "uids": list(doors),
            "reaches": [d[0] for d in doors.values()],
            "reasons": [d[1] for d in doors.values()],
            "judge": rules_judge,
            "resource_day": rule_day,
        },
    ).rowcount
    return changed
