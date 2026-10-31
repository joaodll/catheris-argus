"""Vulnerabilities (ADR-0042, amended 2026-10-31): the load of one vulnerabilities run, and the
read side the Resources screen uses.

The tool is provider-neutral: each provider's own scanner sits behind it (AWS Inspector, the
scanner `aws-inspector`, today), parsed by its adapter into one VulnerabilityBatch. A
vulnerability finding is a finding like any other (lifecycle, snapshots, events, facets); this
module adds what only a vulnerability has (finding_vulnerability) and what the scanner scans
(vulnerability_coverage). Open CVEs are counted apart from Prowler's and CloudFox's findings:
the Resources "Open findings" column and attack-path severity leave them out.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from typing import Literal

from sqlalchemy import Connection, text

from argus.core.rawstore import RawRun
from argus.core.resolver import record_unresolved, resolve
from argus.findings.inspector import parse_inspector
from argus.findings.lifecycle import ANY_CHECK, ANY_REGION, load_checks, load_tool_findings
from argus.findings.model import VULNERABILITY_TOOL, VulnerabilityBatch
from argus.inventory import resource_id_sql


@dataclass(frozen=True)
class Scanner:
    """A provider's own vulnerability scanner, behind the vulnerabilities tool."""

    name: str  # the `scanner` of its rows
    parse: Callable[[RawRun], VulnerabilityBatch]
    # The inventory types it scans: a resource of another type has no vulnerability column.
    scanned_types: frozenset[str]


# Per provider. A provider with no scanner yet has no vulnerability column anywhere; GCP and
# OCI add theirs here.
SCANNERS: dict[str, Scanner] = {
    "aws": Scanner(
        name="aws-inspector",
        parse=parse_inspector,
        scanned_types=frozenset({"aws_ec2_instance", "aws_lambda_function", "aws_ecr_repository"}),
    ),
}
VulnerabilityLevel = Literal["any", "high", "exploitable"]
_OPEN_STATE = f"f.tool = '{VULNERABILITY_TOOL}' AND f.state IN ('open', 'reopened')"
_OPEN = f"{_OPEN_STATE} AND NOT f.muted"
_SEVERITY_RANK = (
    "array_position(ARRAY['critical','high','medium','low','informational'], f.severity)"
)

# Exported SQL: the ids of resources with open, unmuted CVEs at a level, for the
# Resources list's Vulnerabilities filter. Parameter-free, so the inventory can embed it.
_IDS = "SELECT f.resource_id FROM finding f"
_WITH_RESOURCE = f"{_OPEN} AND f.resource_id IS NOT NULL"
VULNERABLE_RESOURCES_SQL: dict[VulnerabilityLevel, str] = {
    "any": f"{_IDS} WHERE {_WITH_RESOURCE}",
    "high": f"{_IDS} WHERE {_WITH_RESOURCE} AND f.severity IN ('critical', 'high')",
    "exploitable": (
        f"{_IDS} JOIN finding_vulnerability v ON v.finding_id = f.id "
        f"WHERE {_WITH_RESOURCE} AND v.exploit_available"
    ),
}


def scanner_for(provider: str, resource_type: str) -> str | None:
    """The scanner that scans resources of this provider and type, or None."""
    scanner = SCANNERS.get(provider)
    return scanner.name if scanner and resource_type in scanner.scanned_types else None


def parse_vulnerabilities(run: RawRun) -> VulnerabilityBatch:
    """One run's raw files -> records, by the adapter of the run's provider's scanner."""
    scanner = SCANNERS.get(run.manifest.provider)
    if scanner is None:
        raise ValueError(f"no vulnerability scanner for the provider {run.manifest.provider!r}")
    return scanner.parse(run)


def load_vulnerabilities(
    conn: Connection,
    *,
    batch: VulnerabilityBatch,
    connection_id: int,
    day: date,
    account_id: str,
    scan_run_id: int,
) -> dict[str, int]:
    """Lifecycle and day snapshot for one vulnerabilities run, then each finding's vulnerability
    facts and, when the coverage table is complete, the connection's coverage. A complete run
    resolves every open CVE it no longer reports, in every region: the scanner reports the whole
    account."""
    loaded = load_tool_findings(
        conn,
        tool=VULNERABILITY_TOOL,
        findings=batch.findings,
        executed=frozenset({(ANY_CHECK, ANY_REGION)}),
        complete=batch.complete,
        connection_id=connection_id,
        day=day,
        account_id=account_id,
        scan_run_id=scan_run_id,
    )
    loaded["vulnerabilities"] = _facts(conn, batch)
    loaded["checks"] = load_checks(
        conn,
        tool=VULNERABILITY_TOOL,
        tool_version=batch.tool_version,
        checks=list(batch.checks.values()),
    )
    if batch.coverage_complete:
        loaded["coverage"] = _coverage(
            conn,
            batch,
            connection_id=connection_id,
            day=day,
            account_id=account_id,
            scan_run_id=scan_run_id,
        )
    for reason, n in batch.skipped.items():
        loaded[f"skipped {reason}"] = n
    return loaded


def _facts(conn: Connection, batch: VulnerabilityBatch) -> int:
    rows = [
        {
            "uid": uid,
            "scanner": batch.scanner,
            "kind": v.kind,
            "cve": v.vulnerability_id,
            "pkg": v.package_name,
            "mgr": v.package_manager,
            "installed": v.installed_version,
            "fixed": v.fixed_version,
            "cvss": v.cvss_score,
            "epss": v.epss_score,
            "score": v.scanner_score,
            "exploit": v.exploit_available,
            "fix": v.fix_available,
            "digest": v.image_digest,
            "tags": list(v.image_tags),
            "url": v.reference_url,
        }
        # In uid order: two runs that share rows lock them in the same order.
        for uid, v in sorted(batch.vulnerabilities.items())
    ]
    if rows:
        conn.execute(
            text("""
            INSERT INTO finding_vulnerability (finding_id, scanner, kind, vulnerability_id,
                package_name, package_manager, installed_version, fixed_version, cvss_score,
                epss_score, scanner_score, exploit_available, fix_available, image_digest,
                image_tags, reference_url)
            SELECT f.id, :scanner, :kind, :cve, :pkg, :mgr, :installed, :fixed, :cvss, :epss,
                   :score, :exploit, :fix, :digest, CAST(:tags AS text[]), :url
            FROM finding f WHERE f.finding_uid = :uid
            ON CONFLICT (finding_id) DO UPDATE SET
              scanner = EXCLUDED.scanner, kind = EXCLUDED.kind,
              vulnerability_id = EXCLUDED.vulnerability_id,
              package_name = EXCLUDED.package_name, package_manager = EXCLUDED.package_manager,
              installed_version = EXCLUDED.installed_version,
              fixed_version = EXCLUDED.fixed_version, cvss_score = EXCLUDED.cvss_score,
              epss_score = EXCLUDED.epss_score, scanner_score = EXCLUDED.scanner_score,
              exploit_available = EXCLUDED.exploit_available,
              fix_available = EXCLUDED.fix_available, image_digest = EXCLUDED.image_digest,
              image_tags = EXCLUDED.image_tags, reference_url = EXCLUDED.reference_url
        """),
            rows,
        )
    return len(rows)


def _coverage(
    conn: Connection,
    batch: VulnerabilityBatch,
    *,
    connection_id: int,
    day: date,
    account_id: str,
    scan_run_id: int,
) -> int:
    """Current state: replaces the connection's coverage. A resource not in the inventory is
    recorded as unresolved, never dropped silently."""
    conn.execute(
        text("DELETE FROM vulnerability_coverage WHERE connection_id = :c"), {"c": connection_id}
    )
    rows = []
    for item in sorted(batch.coverage, key=lambda c: (c.resource_uid, c.scan_type)):
        uid = resolve(item.resource_uid, account_id=account_id, region=item.region)
        if uid is None:
            record_unresolved(
                conn,
                tool=VULNERABILITY_TOOL,
                connection_id=connection_id,
                raw_ref=f"coverage:{item.resource_uid}",
                reason="not an ARN or known short id",
                day=day,
            )
            continue
        rows.append(
            {
                "uid": uid,
                "scanner": batch.scanner,
                "scan": item.scan_type,
                "c": connection_id,
                "active": item.active,
                "code": item.status_code,
                "reason": item.status_reason,
                "at": item.last_scanned_at,
                "run": scan_run_id,
            }
        )
    if not rows:
        return 0
    # A resource the scanner scans but the inventory no longer holds (deleted since) has no
    # row: coverage is shown on inventoried resources only.
    conn.execute(
        text(f"""
        INSERT INTO vulnerability_coverage (resource_id, scanner, scan_type, connection_id,
                                            active, status_code, status_reason, last_scanned_at,
                                            scan_run_id)
        SELECT r.id, :scanner, :scan, :c, :active, :code, :reason, :at, :run
        FROM (SELECT {resource_id_sql("uid")} AS id) r WHERE r.id IS NOT NULL
        ON CONFLICT (resource_id, scanner, scan_type) DO NOTHING
    """),  # noqa: S608 - exported SQL constants only
        rows,
    )
    stored: int = conn.execute(
        text("SELECT count(*) FROM vulnerability_coverage WHERE connection_id = :c"),
        {"c": connection_id},
    ).scalar_one()
    return stored


@dataclass(frozen=True)
class VulnerabilityCount:
    open: int  # open and reopened, not muted (suppressed in the scanner)
    worst: str | None
    exploitable: int  # of the open ones, with a public exploit


def vulnerability_counts(
    conn: Connection, resource_ids: list[int]
) -> dict[int, VulnerabilityCount]:
    """Open CVEs per resource, for one page of resources (bounded by the caller)."""
    if not resource_ids:
        return {}
    rows = conn.execute(
        text(f"""
        SELECT f.resource_id, count(*) AS n,
               (ARRAY['critical','high','medium','low','informational'])[min({_SEVERITY_RANK})]
                 AS worst,
               count(*) FILTER (WHERE v.exploit_available) AS exploitable
        FROM finding f LEFT JOIN finding_vulnerability v ON v.finding_id = f.id
        WHERE f.resource_id = ANY(CAST(:ids AS bigint[])) AND {_OPEN}
        GROUP BY f.resource_id
    """),  # noqa: S608 - fixed fragments
        {"ids": resource_ids},
    )
    return {r.resource_id: VulnerabilityCount(int(r.n), r.worst, int(r.exploitable)) for r in rows}


def scanned_resources(conn: Connection, resource_ids: list[int]) -> set[int]:
    """Of these resources, those a scanner scans (any scan type active)."""
    if not resource_ids:
        return set()
    rows = conn.execute(
        text(
            "SELECT DISTINCT resource_id FROM vulnerability_coverage "
            "WHERE resource_id = ANY(CAST(:ids AS bigint[])) AND active"
        ),
        {"ids": resource_ids},
    )
    return {r.resource_id for r in rows}


@dataclass(frozen=True)
class CoverageRow:
    scanner: str
    scan_type: str
    active: bool
    status_code: str
    status_reason: str | None
    last_scanned_at: datetime | None


def resource_coverage(conn: Connection, resource_id: int) -> list[CoverageRow]:
    rows = conn.execute(
        text(
            "SELECT scanner, scan_type, active, status_code, status_reason, last_scanned_at "
            "FROM vulnerability_coverage WHERE resource_id = :r ORDER BY scanner, scan_type"
        ),
        {"r": resource_id},
    )
    return [CoverageRow(**r._mapping) for r in rows]


@dataclass(frozen=True)
class VulnerabilityFacts:
    scanner: str
    kind: str
    vulnerability_id: str | None
    package_name: str | None
    package_manager: str | None
    installed_version: str | None
    fixed_version: str | None
    cvss_score: float | None
    epss_score: float | None
    scanner_score: float | None
    exploit_available: bool
    fix_available: str | None
    image_digest: str | None
    image_tags: list[str]
    reference_url: str | None


def vulnerability_facts(conn: Connection, finding_ids: list[int]) -> dict[int, VulnerabilityFacts]:
    """What each of these findings adds as a vulnerability; only vulnerability findings have any.
    Bounded by the caller (a page of findings)."""
    if not finding_ids:
        return {}
    rows = conn.execute(
        text("""
        SELECT finding_id, scanner, kind, vulnerability_id, package_name, package_manager,
               installed_version, fixed_version, cvss_score::float AS cvss_score, epss_score,
               scanner_score::float AS scanner_score, exploit_available, fix_available,
               image_digest, image_tags, reference_url
        FROM finding_vulnerability WHERE finding_id = ANY(CAST(:ids AS bigint[]))
    """),
        {"ids": finding_ids},
    )
    return {
        r.finding_id: VulnerabilityFacts(
            **{k: v for k, v in r._mapping.items() if k != "finding_id"}
        )
        for r in rows
    }


@dataclass(frozen=True)
class TopVulnerability:
    finding_id: int
    title: str
    severity: str
    muted: bool
    facts: VulnerabilityFacts


@dataclass(frozen=True)
class ResourceVulnerabilities:
    by_severity: dict[str, int]  # open, unmuted
    suppressed: int  # open but suppressed in the scanner
    top: list[TopVulnerability]  # the worst open ones first


def resource_vulnerabilities(
    conn: Connection, resource_id: int, *, limit: int = 5
) -> ResourceVulnerabilities:
    """The resource sheet's Vulnerabilities section: open CVEs by severity, how many the
    scanner suppresses, and the worst `limit` (severity, then a public exploit, then EPSS)."""
    counts = conn.execute(
        text(f"""
        SELECT f.severity, f.muted, count(*) AS n FROM finding f
        WHERE f.resource_id = :r AND {_OPEN_STATE} GROUP BY f.severity, f.muted
    """),  # noqa: S608 - fixed fragment
        {"r": resource_id},
    )
    by_severity: dict[str, int] = {}
    suppressed = 0
    for row in counts:
        if row.muted:
            suppressed += int(row.n)
        else:
            by_severity[row.severity] = by_severity.get(row.severity, 0) + int(row.n)
    top = conn.execute(
        text(f"""
        SELECT f.id, f.title, f.severity, f.muted FROM finding f
        LEFT JOIN finding_vulnerability v ON v.finding_id = f.id
        WHERE f.resource_id = :r AND {_OPEN}
        ORDER BY {_SEVERITY_RANK}, coalesce(v.exploit_available, false) DESC,
                 v.epss_score DESC NULLS LAST, f.id
        LIMIT :l
    """),  # noqa: S608 - fixed fragments
        {"r": resource_id, "l": limit},
    ).all()
    facts = vulnerability_facts(conn, [r.id for r in top])
    return ResourceVulnerabilities(
        by_severity=by_severity,
        suppressed=suppressed,
        top=[
            TopVulnerability(r.id, r.title, r.severity, r.muted, facts[r.id])
            for r in top
            if r.id in facts
        ],
    )
