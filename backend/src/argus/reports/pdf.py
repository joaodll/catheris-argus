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
# How many accounts and resource types the summary names; the rest are counted.
SUMMARY_ROWS = 15


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
    rows: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Collected:
    total: int
    listed: int
    by_severity: Counter[str]
    by_account: Counter[int]
    by_type: Counter[str]
    accounts: dict[int, tuple[str, str]]  # connection id -> (name, account id)
    groups: list[_Group]
    texts: dict[tuple[str, str], dict[str, Any]]
    facts: dict[int, findings.VulnerabilityFacts]
    names: dict[int, str]

    @property
    def truncated(self) -> bool:
        """Fewer resources listed than found: the CSV has the rest."""
        return self.listed < self.total


def collect(
    conn: Connection,
    kind: ReportKind,
    filters: FindingFilters,
    *,
    per_block: int = PDF_RESOURCES_PER_BLOCK,
    cap: int = PDF_RESOURCE_CAP,
) -> Collected:
    """Reads one report's findings. Call inside the report's transaction, then close it."""
    by_severity: Counter[str] = Counter()
    by_account: Counter[int] = Counter()
    by_type: Counter[str] = Counter()
    accounts: dict[int, tuple[str, str]] = {}
    groups: dict[tuple[str, str], _Group] = {}
    total = listed = 0
    for batch in findings.iter_findings(conn, filters):
        for row in batch:
            total += 1
            by_severity[row["severity"]] += 1
            by_account[row["connection_id"]] += 1
            by_type[row["resource_type"] or "unknown"] += 1
            accounts.setdefault(row["connection_id"], (row["connection"], row["account_id"]))
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
            if len(group.rows) < per_block and listed < cap:
                group.rows.append(
                    {
                        "id": row["id"],
                        "connection_id": row["connection_id"],
                        "region": row["region"],
                        "resource_type": row["resource_type"],
                        "resource_id": row["resource_id"],
                        "resource_uid": row["resource_uid"],
                        "reported_name": row["reported_resource_name"],
                        "first_seen": row["first_seen"],
                    }
                )
                listed += 1
    ordered = sorted(
        groups.values(), key=lambda g: (_RANK.get(g.severity, 9), -g.count, g.tool, g.check_id)
    )
    listed_rows = [r for g in ordered for r in g.rows]
    names = inventory.resource_names(
        conn, [r["resource_id"] for r in listed_rows if r["resource_id"] is not None]
    )
    facts = (
        findings.vulnerability_facts(
            conn, [g.sample_id for g in ordered] + [r["id"] for r in listed_rows]
        )
        if kind == "vulnerabilities"
        else {}
    )
    texts = findings.check_texts(
        conn, [(g.tool, g.check_id) for g in ordered[:PDF_DETAILED_BLOCKS]]
    )
    return Collected(
        total=total,
        listed=listed,
        by_severity=by_severity,
        by_account=by_account,
        by_type=by_type,
        accounts=accounts,
        groups=ordered,
        texts=texts,
        facts=facts,
        names=names,
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


def _block(c: Collected, group: _Group, kind: ReportKind) -> dict[str, Any]:
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
        facts = c.facts.get(row["id"])
        rows.append(
            {
                "account": name,
                "account_id": account_id,
                "region": row["region"],
                "type": row["resource_type"],
                "name": c.names.get(row["resource_id"]) or row["reported_name"],
                "uid": row["resource_uid"],
                "first_seen": _day(row["first_seen"]),
                "installed": facts.installed_version if facts else None,
            }
        )
    return {
        "tool": group.tool,
        "check_id": group.check_id,
        "title": group.title,
        "severity": group.severity,
        "count": group.count,
        "accounts": len(group.accounts),
        "risk": _plain(text.get("risk")),
        "description": _plain(text.get("description")),
        "fix": _plain(group.remediation_text),
        "fix_link": _link(group.remediation_url),
        "links": [link for link in (_link(u) for u in text.get("links") or []) if link][:5],
        "code": [{"label": label, "text": body} for label, body in codes],
        "facts": _facts(c.facts.get(group.sample_id)) if kind == "vulnerabilities" else None,
        "rows": rows,
        "more": group.count - len(rows),
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
    detailed = c.groups[:PDF_DETAILED_BLOCKS]
    days = sorted({d.isoformat() for d in data_through.values()})
    account_rows = [
        {
            "name": c.accounts.get(cid, ("", ""))[0],
            "account_id": c.accounts.get(cid, ("", ""))[1],
            "findings": n,
            "data_through": _day(data_through.get(cid)),
        }
        for cid, n in c.by_account.most_common(SUMMARY_ROWS)
    ]
    return {
        "report_id": report_id,
        "kind": kind,
        "requested_by": requested_by,
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M"),
        "scope": scope_words,
        "total": c.total,
        "listed": c.listed,
        "truncated": c.truncated,
        "caps": {"per_block": PDF_RESOURCES_PER_BLOCK, "total": PDF_RESOURCE_CAP},
        "data_through": days[-1] if days else None,
        "data_through_differs": len(days) > 1,
        "account_names": [a[0] for a in sorted(c.accounts.values())],
        "severities": [
            {"severity": s, "count": c.by_severity.get(s, 0), "in_scope": s in severities_in_scope}
            for s in SEVERITIES
        ],
        "by_account": account_rows,
        "more_accounts": max(len(c.by_account) - SUMMARY_ROWS, 0),
        "by_type": [{"type": t, "findings": n} for t, n in c.by_type.most_common(SUMMARY_ROWS)],
        "more_types": max(len(c.by_type) - SUMMARY_ROWS, 0),
        "blocks": [_block(c, g, kind) for g in detailed],
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
