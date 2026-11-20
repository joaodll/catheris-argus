"""The PDF of a report (ADR-0047, round 2): an audit hand-off, not the whole list (the CSV is).

Three steps, so the database is held only as long as reading takes:
1. `collect` reads inside the report's REPEATABLE READ transaction: it counts every matching
   finding (by severity, account and resource type, uncut), groups them by check or CVE, keeps the
   first resources of each up to the caps, then reads what the tools say about each check.
2. `build_context` turns that into plain JSON: every string is data, and a link survives only as
   http or https. Nothing in it is markup.
3. `render` hands the JSON to the renderer, a separate program in its own venv with none of
   Argus's secrets (core.process.run_isolated), and gets the PDF back.
"""

import heapq
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import Connection

from argus import findings, inventory
from argus.core.process import run_isolated
from argus.findings import FindingFilters
from argus.reports.model import (
    PDF_DETAILED_BLOCKS,
    PDF_NAMED_CAP,
    PDF_PROBLEMS_PER_RESOURCE,
    PDF_RESOURCE_BLOCKS,
    PDF_RESOURCE_CAP,
    PDF_RESOURCES_PER_BLOCK,
    ReportKind,
)

RENDER_PYTHON = "/opt/report-render/bin/python"
RENDER_SCRIPT = "/opt/report-render/render.py"
RENDER_TIMEOUT_SECONDS = 600
RENDER_MAX_BYTES = 200 * 1024 * 1024
SEVERITIES = ("critical", "high", "medium", "low", "informational")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# How many accounts the summary names, and regions on each account's line; the rest are counted.
SUMMARY_ROWS = 15
REGIONS_PER_ACCOUNT = 6
# The summary's "By resource type" (worst first) and "Most common" checks or CVEs.
TYPE_ROWS = 25
TOP_COMMON = 10
# The share bar's units: integer parts of a whole, so the renderer draws numbers, never text.
BAR_UNITS = 1000


@dataclass
class _Group:
    tool: str
    check_id: str
    title: str
    severity: str
    remediation_text: str | None
    remediation_url: str | None
    sample_id: int  # the finding whose CVE facts stand for the group's
    count: int = 0
    accounts: set[int] = field(default_factory=set)
    resources: set[int | str] = field(default_factory=set)  # distinct resources (_key)
    rows: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class TypeCount:
    """One resource type in the report: its findings by severity and its distinct resources.
    The by-resource report also counts them by source (misconfiguration or vulnerability)."""

    type: str
    counts: list[int] = field(default_factory=lambda: [0] * len(SEVERITIES))
    resources: set[int | str] = field(default_factory=set)
    sources: Counter[str] = field(default_factory=Counter)

    def add(self, severity: str, resource: int | str, source: str | None = None) -> None:
        rank = _RANK.get(severity)
        if rank is not None:
            self.counts[rank] += 1
        self.resources.add(resource)
        if source is not None:
            self.sources[source] += 1

    def rank(self) -> tuple[int | str, ...]:
        """Worst first: most critical, then most high, and so on, then most in all."""
        return (*(-n for n in self.counts), -sum(self.counts), self.type)


@dataclass
class _ResourceCount:
    """One resource in a by-resource PDF: where it is and its findings by severity."""

    key: int | str
    connection_id: int
    resource_id: int | None
    uid: str
    region: str | None
    type: str | None
    reported_name: str | None
    counts: list[int] = field(default_factory=lambda: [0] * len(SEVERITIES))

    def rank(self) -> tuple[int | str, ...]:
        """Worst first: most critical, then most high, and so on, then most in all."""
        return (*(-n for n in self.counts), -sum(self.counts), self.uid)


def count_type(
    types: dict[str, TypeCount],
    resource_type: str | None,
    severity: str,
    resource: int | str,
    source: str | None = None,
) -> None:
    """Counts one finding under its resource's type ("unknown" when the tool names none)."""
    key = resource_type or "unknown"
    counted = types.get(key)
    if counted is None:
        counted = types[key] = TypeCount(key)
    counted.add(severity, resource, source)


def type_rows(types: dict[str, TypeCount]) -> list[dict[str, Any]]:
    """The summary's "By resource type": the first TYPE_ROWS types, worst first."""
    return [
        {
            "type": t.type,
            "words": type_words(t.type),
            "resources": len(t.resources),
            "counts": list(t.counts),
            "total": sum(t.counts),
        }
        for t in heapq.nsmallest(TYPE_ROWS, types.values(), key=TypeCount.rank)
    ]


# Service words as AWS writes them; any other word is lower case, the name's first letter up.
_ACRONYMS = {
    w.lower(): w
    for w in (
        "ACM", "AMI", "API", "CloudFormation", "CloudFront", "CloudTrail", "CloudWatch",
        "CodeBuild", "DAX", "DB", "DMS", "DocDB", "DynamoDB", "EBS", "EC2", "ECR", "ECS", "EFS",
        "EKS", "ELB", "ELBv2", "EMR", "EventBridge", "FSx", "GuardDuty", "IAM", "KMS", "MQ", "MSK",
        "NACL", "OpenSearch", "RDS", "S3", "SageMaker", "SES", "SNS", "SQS", "SSM", "SSO",
        "VPC", "WAF", "WAFv2",
    )
}  # fmt: skip
_CAMEL = re.compile(r"[A-Z][a-z0-9]*|[a-z0-9]+")


def type_words(resource_type: str | None) -> str:
    """A resource type as a reader says it: "AwsEc2Instance" (a tool's) and "aws_ec2_instance"
    (the inventory's) both read "EC2 instance". The PDF prints the raw type under it, so an odd
    name never hides the tool's word. A type with no provider prefix ("Other") is kept."""
    if not resource_type:
        return "unknown"
    if resource_type.startswith("aws_"):
        parts = resource_type[4:].split("_")
    elif resource_type.startswith("Aws") and len(resource_type) > 3:
        parts = _CAMEL.findall(resource_type[3:])
    else:
        return resource_type
    parts = [p.lower() for p in parts if p]
    words: list[str] = []
    while parts:  # "Cloud" + "Trail" is one service word, CloudTrail
        if len(parts) > 1 and parts[0] + parts[1] in _ACRONYMS:
            parts[:2] = [parts[0] + parts[1]]
        words.append(_ACRONYMS.get(parts[0], parts[0]))
        parts.pop(0)
    if not words:
        return resource_type
    words[0] = words[0][:1].upper() + words[0][1:]
    return " ".join(words)


def _key(row: dict[str, Any]) -> int | str:
    """A resource: its inventory id, or its uid when the inventory has none."""
    rid: int | None = row["resource_id"]
    return rid if rid is not None else row["resource_uid"]


@dataclass
class Collected:
    total: int
    listed: int
    by_severity: Counter[str]
    by_account: Counter[int]
    by_type: dict[str, TypeCount]
    by_region: dict[int, Counter[str]]  # connection id -> its findings by region
    accounts: dict[int, tuple[str, str]]  # connection id -> (name, account id)
    groups: list[_Group]
    texts: dict[tuple[str, str], dict[str, Any]]
    facts: dict[int, findings.VulnerabilityFacts]
    names: dict[int, str]
    resources: int  # distinct resources with a finding in the report
    # Vulnerabilities only (by resource, owner 2026-11-20): every resource worst first, and the
    # shown ones' CVE rows, worst first and capped.
    ranked: list[_ResourceCount] = field(default_factory=list)
    rows_of: dict[int | str, list[dict[str, Any]]] = field(default_factory=dict)

    @property
    def truncated(self) -> bool:
        """Fewer resources listed than found: the CSV has the rest."""
        return self.listed < self.total


def _slim(row: dict[str, Any]) -> dict[str, Any]:
    """What a listed row keeps of a finding: where it is, its check, and its own sentence."""
    return {
        "id": row["id"],
        "connection_id": row["connection_id"],
        "region": row["region"],
        "resource_type": row["resource_type"],
        "resource_id": row["resource_id"],
        "resource_uid": row["resource_uid"],
        "reported_name": row["reported_resource_name"],
        "first_seen": row["first_seen"],
        "detail": row["detail"],
        "severity": row["severity"],
        "tool": row["tool"],
        "check_id": row["check_id"],
        "title": row["title"],
    }


def _count_resource(resources: dict[int | str, _ResourceCount], row: dict[str, Any]) -> None:
    key = _key(row)
    counted = resources.get(key)
    if counted is None:
        counted = resources[key] = _ResourceCount(
            key=key,
            connection_id=row["connection_id"],
            resource_id=row["resource_id"],
            uid=row["resource_uid"],
            region=row["region"],
            type=row["resource_type"],
            reported_name=row["reported_resource_name"],
        )
    rank = _RANK.get(row["severity"])
    if rank is not None:
        counted.counts[rank] += 1


def _rows_of(
    conn: Connection,
    filters: FindingFilters,
    shown: list[_ResourceCount],
    *,
    per_resource: int,
    cap: int,
) -> dict[int | str, list[dict[str, Any]]]:
    """The shown resources' findings, read again through the report's own filters (same
    REPEATABLE READ transaction, so the same state), each resource's worst first and capped."""
    keys = {r.key for r in shown}
    found: dict[int | str, list[dict[str, Any]]] = {}
    for batch in findings.iter_findings(conn, filters):
        for row in batch:
            key = _key(row)
            if key in keys:
                found.setdefault(key, []).append(_slim(row))
    out: dict[int | str, list[dict[str, Any]]] = {}
    listed = 0
    for r in shown:
        kept = sorted(found.get(r.key, []), key=lambda x: (_RANK.get(x["severity"], 9), x["id"]))
        kept = kept[: max(min(per_resource, cap - listed), 0)]
        out[r.key] = kept
        listed += len(kept)
    return out


def collect(
    conn: Connection,
    kind: ReportKind,
    filters: FindingFilters,
    *,
    per_block: int = PDF_RESOURCES_PER_BLOCK,
    cap: int = PDF_RESOURCE_CAP,
) -> Collected:
    """Reads one report's findings. Call inside the report's transaction, then close it.
    Misconfigurations are grouped by check; vulnerabilities by resource (owner, 2026-11-20)."""
    by_resource = kind == "vulnerabilities"
    by_severity: Counter[str] = Counter()
    by_account: Counter[int] = Counter()
    by_type: dict[str, TypeCount] = {}
    by_region: dict[int, Counter[str]] = {}
    accounts: dict[int, tuple[str, str]] = {}
    groups: dict[tuple[str, str], _Group] = {}
    resources: dict[int | str, _ResourceCount] = {}
    total = listed = 0
    for batch in findings.iter_findings(conn, filters):
        for row in batch:
            total += 1
            by_severity[row["severity"]] += 1
            by_account[row["connection_id"]] += 1
            by_region.setdefault(row["connection_id"], Counter())[row["region"] or ""] += 1
            accounts.setdefault(row["connection_id"], (row["connection"], row["account_id"]))
            where = _key(row)
            _count_resource(resources, row)
            count_type(by_type, row["resource_type"], row["severity"], where)
            key = (row["tool"], row["check_id"])
            group = groups.get(key)
            if group is None:
                group = groups[key] = _Group(
                    tool=row["tool"],
                    check_id=row["check_id"],
                    title=row["title"],
                    severity=row["severity"],
                    remediation_text=row["remediation_text"],
                    remediation_url=row["remediation_url"],
                    sample_id=row["id"],
                )
            elif _RANK.get(row["severity"], 9) < _RANK.get(group.severity, 9):
                group.severity = row["severity"]
            group.count += 1
            group.accounts.add(row["connection_id"])
            group.resources.add(where)
            if not by_resource and len(group.rows) < per_block and listed < cap:
                group.rows.append(_slim(row))
                listed += 1
    ordered = sorted(
        groups.values(), key=lambda g: (_RANK.get(g.severity, 9), -g.count, g.tool, g.check_id)
    )
    ranked: list[_ResourceCount] = []
    rows_of: dict[int | str, list[dict[str, Any]]] = {}
    if by_resource:
        ranked = sorted(resources.values(), key=_ResourceCount.rank)
        rows_of = _rows_of(
            conn,
            filters,
            ranked[:PDF_RESOURCE_BLOCKS],
            per_resource=PDF_PROBLEMS_PER_RESOURCE,
            cap=cap,
        )
        listed_rows = [r for kept in rows_of.values() for r in kept]
        listed = len(listed_rows)
        named = {r.resource_id for r in ranked[: PDF_RESOURCE_BLOCKS + PDF_NAMED_CAP]}
        texts = findings.check_texts(
            conn, sorted({(r["tool"], r["check_id"]) for r in listed_rows})
        )
    else:
        listed_rows = [r for g in ordered for r in g.rows]
        named = {r["resource_id"] for r in listed_rows}
        texts = findings.check_texts(
            conn, [(g.tool, g.check_id) for g in ordered[:PDF_DETAILED_BLOCKS]]
        )
    names = inventory.resource_names(conn, sorted(i for i in named if i is not None))
    facts = (
        findings.vulnerability_facts(conn, [r["id"] for r in listed_rows]) if by_resource else {}
    )
    return Collected(
        total=total,
        listed=listed,
        by_severity=by_severity,
        by_account=by_account,
        by_type=by_type,
        by_region=by_region,
        accounts=accounts,
        groups=ordered,
        texts=texts,
        facts=facts,
        names=names,
        resources=len(resources),
        ranked=ranked,
        rows_of=rows_of,
    )


def _link(url: Any) -> str | None:
    """A link the PDF may show: http or https with a host, else nothing."""
    if not isinstance(url, str):
        return None
    parts = urlsplit(url.strip())
    return url.strip() if parts.scheme in ("http", "https") and parts.netloc else None


_FENCE = re.compile(r"^\s*```[\w-]*\s*$", re.MULTILINE)
_EMPHASIS = re.compile(r"\*\*(.+?)\*\*|__(.+?)__")
_INLINE_CODE = re.compile(r"`([^`\n]+)`")


def _plain(value: Any, *, code: bool = False) -> str | None:
    """Tool text without its Markdown marks (Prowler writes **bold**, `code` and fenced blocks),
    since the PDF prints text, never markup. Empty means none."""
    if not isinstance(value, str):
        return None
    out = _FENCE.sub("", value)
    if not code:
        out = _EMPHASIS.sub(lambda m: m.group(1) or m.group(2), out)
        out = _INLINE_CODE.sub(r"\1", out)
    out = out.strip("\n")
    return out if out.strip() else None


def _day(value: date | datetime | None) -> str | None:
    return value.isoformat()[:10] if value else None


_NO_FACTS = dict.fromkeys(
    ("cve", "cvss", "epss", "exploit", "package", "installed", "fixed", "fix_available", "scanner")
)


def _facts(facts: findings.VulnerabilityFacts | None) -> dict[str, Any]:
    """A CVE's facts; every key present (None when unknown), so the template never meets a gap."""
    if facts is None:
        return dict(_NO_FACTS)
    return {
        "cve": facts.vulnerability_id,
        "cvss": facts.cvss_score,
        "epss": facts.epss_score,
        "exploit": facts.exploit_available,
        "package": facts.package_name,
        "installed": facts.installed_version,
        "fixed": facts.fixed_version,
        "fix_available": facts.fix_available,
        "scanner": facts.scanner,
    }


def _block(c: Collected, group: _Group) -> dict[str, Any]:
    """One check, with the resources it failed on (each with the tool's sentence), its risk and
    its fix."""
    text = c.texts.get((group.tool, group.check_id), {})
    # The command to run, and the code to commit: a hand-off stays readable. The finding's own
    # link has every other form of the fix.
    codes = [
        (label, _plain(text.get(column), code=True))
        for label, column in (("CLI", "code_cli"), ("Terraform", "code_terraform"))
        if text.get(column)
    ]
    rows = []
    for row in group.rows:
        name, account_id = c.accounts.get(row["connection_id"], ("", ""))
        rows.append(
            {
                "account": name,
                "account_id": account_id,
                "region": row["region"],
                "type": row["resource_type"],
                "type_words": type_words(row["resource_type"]),
                "name": c.names.get(row["resource_id"]) or row["reported_name"],
                "uid": row["resource_uid"],
                # The tool's own sentence about this resource (Prowler's status_extended): what
                # is wrong on it, where the check's title is the passing condition.
                "result": _plain(row["detail"]),
                "first_seen": _day(row["first_seen"]),
            }
        )
    return {
        "tool": group.tool,
        "check_id": group.check_id,
        "title": group.title,
        "severity": group.severity,
        "count": group.count,
        "resources": len(group.resources),
        "accounts": len(group.accounts),
        "risk": _plain(text.get("risk")),
        "description": _plain(text.get("description")),
        "fix": _plain(group.remediation_text),
        "fix_link": _link(group.remediation_url),
        "code": [{"label": label, "text": body} for label, body in codes],
        "rows": rows,
        "more": group.count - len(rows),
    }


_LETTERS = {"critical": "C", "high": "H", "medium": "M", "low": "L", "informational": "I"}


def chips(counts: list[int]) -> list[dict[str, Any]]:
    """A resource's counts by severity as chips ("2C 1H"), the severities it has only."""
    return [
        {"severity": s, "letter": _LETTERS[s], "count": n}
        for s, n in zip(SEVERITIES, counts, strict=True)
        if n
    ]


def cve_line(
    row: dict[str, Any],
    facts: findings.VulnerabilityFacts | None,
    description: str | None,
) -> dict[str, Any]:
    """One CVE on one resource, as the CVE table of both by-resource PDFs prints it."""
    return {
        "severity": row["severity"],
        "tool": row["tool"],
        "check_id": row["check_id"],
        "title": row["title"],
        "first_seen": _day(row["first_seen"]),
        "facts": _facts(facts),
        "description": description,
    }


def _resource_block(c: Collected, r: _ResourceCount) -> dict[str, Any]:
    """One resource and its CVEs, worst first (the Vulnerabilities PDF, owner 2026-11-20)."""
    kept = c.rows_of.get(r.key, [])
    return {
        **_resource_where(c, r),
        "lines": [
            cve_line(
                row,
                c.facts.get(row["id"]),
                _plain(c.texts.get((row["tool"], row["check_id"]), {}).get("description")),
            )
            for row in kept
        ],
        "more": sum(r.counts) - len(kept),
    }


def _resource_where(c: Collected, r: _ResourceCount) -> dict[str, Any]:
    name, account_id = c.accounts.get(r.connection_id, ("", ""))
    return {
        "name": (c.names.get(r.resource_id) if r.resource_id is not None else None)
        or r.reported_name,
        "uid": r.uid,
        "account": name,
        "account_id": account_id,
        "region": r.region,
        "type": r.type,
        "type_words": type_words(r.type),
        "chips": chips(r.counts),
        "total": sum(r.counts),
    }


def account_rows(
    accounts: dict[int, tuple[str, str]],
    by_account: Counter[int],
    by_region: dict[int, Counter[str]],
    data_through: dict[int, date],
) -> list[dict[str, Any]]:
    """The summary's "By account": each account's findings and its regions on its own line (owner,
    2026-11-20), the first SUMMARY_ROWS accounts, most findings first."""
    out = []
    for cid, n in by_account.most_common(SUMMARY_ROWS):
        name, account_id = accounts.get(cid, ("", ""))
        regions = by_region.get(cid, Counter())
        out.append(
            {
                "name": name,
                "account_id": account_id,
                "findings": n,
                "data_through": _day(data_through.get(cid)),
                "regions": [
                    {"region": region or None, "findings": count}
                    for region, count in regions.most_common(REGIONS_PER_ACCOUNT)
                ],
                "more_regions": max(len(regions) - REGIONS_PER_ACCOUNT, 0),
            }
        )
    return out


def _shares(by_severity: Counter[str], total: int) -> list[dict[str, Any]]:
    """The share bar: each severity with findings, its start and width in BAR_UNITS (integers
    that add up to BAR_UNITS, by largest remainder) and its percent to one decimal."""
    present = [(s, by_severity.get(s, 0)) for s in SEVERITIES if by_severity.get(s, 0)]
    # The bar's whole is the five severities' findings: a word outside them (none today) would
    # otherwise leave the parts short of the whole, and the renderer refuses that.
    whole = sum(n for _, n in present)
    if not total or not whole:
        return []
    exact = [n * BAR_UNITS / whole for _, n in present]
    units = [int(e) for e in exact]
    for i in sorted(range(len(units)), key=lambda i: units[i] - exact[i])[: BAR_UNITS - sum(units)]:
        units[i] += 1
    out, x = [], 0
    for (severity, n), width in zip(present, units, strict=True):
        out.append(
            {"severity": severity, "x": x, "width": width, "percent": round(n * 100 / total, 1)}
        )
        x += width
    return out


def _common(c: Collected) -> list[dict[str, Any]]:
    """The checks or CVEs that affect the most resources, then the worst, then by id."""
    top = heapq.nsmallest(
        TOP_COMMON,
        c.groups,
        key=lambda g: (-len(g.resources), _RANK.get(g.severity, 9), g.tool, g.check_id),
    )
    return [
        {
            "severity": g.severity,
            "title": g.title,
            "tool": g.tool,
            "check_id": g.check_id,
            "resources": len(g.resources),
            "accounts": len(g.accounts),
        }
        for g in top
    ]


def _body(c: Collected, kind: ReportKind) -> dict[str, Any]:
    """The blocks after the summary: a check each (misconfigurations), or a resource each
    (vulnerabilities), then the rest named, then counted."""
    if kind == "vulnerabilities":
        named = c.ranked[PDF_RESOURCE_BLOCKS : PDF_RESOURCE_BLOCKS + PDF_NAMED_CAP]
        return {
            "caps": {
                "per_block": PDF_PROBLEMS_PER_RESOURCE,
                "total": PDF_RESOURCE_CAP,
                "blocks": PDF_RESOURCE_BLOCKS,
            },
            "blocks": [_resource_block(c, r) for r in c.ranked[:PDF_RESOURCE_BLOCKS]],
            "others": [_resource_where(c, r) for r in named],
            "more_others": max(len(c.ranked) - PDF_RESOURCE_BLOCKS - PDF_NAMED_CAP, 0),
        }
    return {
        "caps": {"per_block": PDF_RESOURCES_PER_BLOCK, "total": PDF_RESOURCE_CAP},
        "blocks": [_block(c, g) for g in c.groups[:PDF_DETAILED_BLOCKS]],
        "others": [
            {
                "severity": g.severity,
                "check_id": g.check_id,
                "title": g.title,
                "count": g.count,
                "tool": g.tool,
            }
            for g in c.groups[PDF_DETAILED_BLOCKS : PDF_DETAILED_BLOCKS + PDF_NAMED_CAP]
        ],
        "more_others": max(len(c.groups) - PDF_DETAILED_BLOCKS - PDF_NAMED_CAP, 0),
    }


def build_context(
    c: Collected,
    *,
    report_id: int,
    kind: ReportKind,
    requested_by: str,
    generated_at: datetime,
    scope_words: str,
    severities_in_scope: list[str],
    data_through: dict[int, date],
) -> dict[str, Any]:
    """Everything the renderer prints, as plain JSON. Pure: no database, no clock."""
    days = sorted({d.isoformat() for d in data_through.values()})
    return {
        "report_id": report_id,
        "kind": kind,
        "requested_by": requested_by,
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M"),
        "scope": scope_words,
        "total": c.total,
        "listed": c.listed,
        "truncated": c.truncated,
        "data_through": days[-1] if days else None,
        "data_through_differs": len(days) > 1,
        "account_names": [a[0] for a in sorted(c.accounts.values())],
        "severities": [
            {"severity": s, "count": c.by_severity.get(s, 0), "in_scope": s in severities_in_scope}
            for s in SEVERITIES
        ],
        "by_account": account_rows(c.accounts, c.by_account, c.by_region, data_through),
        "more_accounts": max(len(c.by_account) - SUMMARY_ROWS, 0),
        "by_type": type_rows(c.by_type),
        "more_types": max(len(c.by_type) - TYPE_ROWS, 0),
        "shares": _shares(c.by_severity, c.total),
        "resources": c.resources,
        "common": _common(c),
        **_body(c, kind),
    }


_STATES = {"reopened": "reopened", "resolved": "resolved", "accepted_risk": "accepted risk"}


def _counted(values: tuple[str, ...], noun: str) -> str | None:
    if not values:
        return None
    return values[0] if len(values) == 1 else f"{len(values)} {noun}"


def describe(filters: FindingFilters, *, accounts: int) -> str:
    """The report's scope in words, as the cover prints it."""
    words: list[str | None] = []
    if filters.severities:
        ordered = sorted(filters.severities, key=lambda s: _RANK.get(s, 9))
        words.append(", ".join(s.capitalize() for s in ordered))
    words.append("1 account" if accounts == 1 else f"{accounts} accounts")
    words.append(_STATES.get(filters.state, "open"))
    words.append(_counted(filters.regions, "regions"))
    words.append(_counted(filters.services, "services"))
    words.append(_counted(filters.resource_types, "resource types"))
    words.append(_counted(filters.check_ids, "checks"))
    words.append(_counted(filters.categories, "categories"))
    words.append({"hide": "not muted", "only": "muted only"}.get(filters.muted))
    words.append("new in the latest scan" if filters.new else None)
    if filters.first_seen_from:
        words.append(f"first seen from {filters.first_seen_from.isoformat()}")
    if filters.first_seen_to:
        words.append(f"first seen to {filters.first_seen_to.isoformat()}")
    words.append("one resource" if filters.resource_id is not None else None)
    words.append(f"matching “{filters.q}”" if filters.q else None)
    words.append("public exploit" if filters.exploitable else None)
    words.append({"available": "fix available", "none": "no fix yet"}.get(filters.fix))
    for key, values in filters.tags:  # as the screen says it: past three values, a count
        shown = (
            " or ".join(values) if len(values) <= 3 else f"{values[0]} or {len(values) - 1} more"
        )
        words.append(f"tag {key} = {shown}")
    return " · ".join(w for w in words if w)


def render(context: dict[str, Any]) -> bytes:
    """The PDF of a context, from the renderer in its own process (no secrets, no fetches)."""
    result = run_isolated(
        [RENDER_PYTHON, "-I", "-B", RENDER_SCRIPT],
        stdin=json.dumps(context).encode(),
        timeout=RENDER_TIMEOUT_SECONDS,
        max_output=RENDER_MAX_BYTES,
    )
    return result.output
