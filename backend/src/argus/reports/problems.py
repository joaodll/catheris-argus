"""The by-resource report, "Misconfigurations and vulnerabilities" (ADR-0047 section 3d).

The Resources list's filters choose the resources; each one's open misconfigurations
(findings.OPEN_MISCONFIGURATION) and open CVEs (findings.OPEN_VULNERABILITY) are its problems,
narrowed by the report's severities and tags. A resource with no problem is not in the report.

- The CSV is one row per problem, written while the list is read a page at a time.
- The PDF reads every problem once to count and rank the resources (worst first: most critical,
  then high, and so on), then reads the problems of the resources it shows again, in the same
  REPEATABLE READ transaction, so both reads see one state. The summary is the other PDFs'
  (pdf.py); each block is one resource with its misconfigurations and its CVEs, and each check
  or CVE's risk and fix is printed once, in the Reference.
"""

import heapq
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from sqlalchemy import Connection

from argus import findings, inventory, metrics
from argus.reports.filters import ResourceProblemFilters
from argus.reports.model import (
    PDF_NAMED_CAP,
    PDF_PROBLEMS_PER_RESOURCE,
    PDF_REFERENCE_CAP,
    PDF_RESOURCE_BLOCKS,
    PDF_RESOURCE_CAP,
)
from argus.reports.pdf import (
    _LETTERS,
    _RANK,
    SEVERITIES,
    SUMMARY_ROWS,
    TOP_COMMON,
    TOP_RESOURCES,
    _day,
    _facts,
    _link,
    _plain,
    _shares,
)

BATCH = 1000
MISCONFIGURATION = "misconfiguration"
VULNERABILITY = "vulnerability"
SOURCES = (MISCONFIGURATION, VULNERABILITY)


def _source(row: dict[str, Any]) -> str:
    return VULNERABILITY if row["tool"] == findings.VULNERABILITY_TOOL else MISCONFIGURATION


def _with_resource(
    conn: Connection, rows: list[dict[str, Any]], by_id: dict[int, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Problem rows with their resource as the inventory describes it, the source, and a CVE's
    facts."""
    facts = findings.vulnerability_facts(
        conn, [r["id"] for r in rows if r["tool"] == findings.VULNERABILITY_TOOL]
    )
    for row in rows:
        resource = by_id[row["resource_id"]]
        row["resource_name"] = resource["name"] or resource["native_id"]
        row["resource_type"] = resource["type"]
        row["region"] = resource["region"]
        row["vpc_id"] = resource["vpc_id"]
        row["source"] = _source(row)
        row["vulnerability"] = facts.get(row["id"])
    return rows


def iter_rows(
    conn: Connection, filters: ResourceProblemFilters, *, batch: int = BATCH
) -> Iterator[list[dict[str, Any]]]:
    """Every problem of the chosen resources, a page of the Resources list at a time, by
    resource then id."""
    for resources in _pages(conn, filters, batch):
        by_id = {r["id"]: r for r in resources}
        rows = findings.resource_problems(
            conn, list(by_id), severities=filters.severities, tags=filters.tags
        )
        if rows:
            yield _with_resource(conn, rows, by_id)


def _pages(
    conn: Connection, filters: ResourceProblemFilters, batch: int
) -> Iterator[list[dict[str, Any]]]:
    """The chosen resources a page at a time: the list's, or the one resource asked for, kept
    only when it is in the report's accounts."""
    if filters.resource_id is None:
        yield from inventory.iter_resources(
            conn, filters.resources.inventory_filters(), batch=batch
        )
        return
    scope = filters.resources.connection_ids
    yield [
        r
        for r in inventory.resources_by_ids(conn, [filters.resource_id])
        if not scope or r["connection_id"] in scope
    ]


@dataclass
class _Resource:
    """One resource in the report: where it is and its problems by source and severity."""

    resource_id: int
    resource: dict[str, Any]
    connection_id: int
    counts: dict[str, list[int]] = field(
        default_factory=lambda: {s: [0] * len(SEVERITIES) for s in SOURCES}
    )

    def total(self) -> list[int]:
        return [a + b for a, b in zip(*self.counts.values(), strict=True)]

    def rank(self) -> tuple[int | str, ...]:
        """Worst first: most critical, then most high, and so on, then most in all."""
        both = self.total()
        return (*(-n for n in both), -sum(both), self.resource["resource_uid"])


@dataclass
class _Problem:
    """A check or a CVE across the report: what its reference entry and "Most common" need."""

    tool: str
    check_id: str
    title: str
    severity: str
    remediation_text: str | None
    remediation_url: str | None
    sample_id: int
    resources: set[int] = field(default_factory=set)
    accounts: set[int] = field(default_factory=set)

    @property
    def count(self) -> int:
        return len(self.resources)


@dataclass
class Collected:
    total: int
    by_severity: Counter[str]
    by_source: dict[str, Counter[str]]
    by_account: Counter[int]
    by_type: Counter[str]
    by_region: Counter[str]
    accounts: dict[int, tuple[str, str]]
    resources: list[_Resource]  # every resource with a problem, worst first
    problems: dict[tuple[str, str], _Problem]
    rows: dict[int, list[dict[str, Any]]]  # the shown resources' problems, worst first, capped
    listed: int
    texts: dict[tuple[str, str], dict[str, Any]]
    facts: dict[int, findings.VulnerabilityFacts]
    assets: list[dict[str, Any]] | None

    @property
    def truncated(self) -> bool:
        return self.listed < self.total


def _problem_rank(row: dict[str, Any]) -> tuple[int, int]:
    return (_RANK.get(row["severity"], 9), row["id"])


def collect(
    conn: Connection,
    filters: ResourceProblemFilters,
    *,
    today: date,
    blocks: int = PDF_RESOURCE_BLOCKS,
    per_resource: int = PDF_PROBLEMS_PER_RESOURCE,
    cap: int = PDF_RESOURCE_CAP,
) -> Collected:
    """Reads one by-resource report. Call inside the report's transaction, then close it."""
    by_severity: Counter[str] = Counter()
    by_source: dict[str, Counter[str]] = {s: Counter() for s in SOURCES}
    by_account: Counter[int] = Counter()
    by_type: Counter[str] = Counter()
    by_region: Counter[str] = Counter()
    accounts: dict[int, tuple[str, str]] = {}
    resources: dict[int, _Resource] = {}
    problems: dict[tuple[str, str], _Problem] = {}
    total = 0
    for batch in iter_rows(conn, filters):
        for row in batch:
            total += 1
            source = row["source"]
            by_severity[row["severity"]] += 1
            by_source[source][row["severity"]] += 1
            by_account[row["connection_id"]] += 1
            by_type[row["resource_type"] or "unknown"] += 1
            by_region[row["region"] or ""] += 1
            accounts.setdefault(row["connection_id"], (row["connection"], row["account_id"]))
            rid = row["resource_id"]
            resource = resources.get(rid)
            if resource is None:
                resource = resources[rid] = _Resource(
                    resource_id=rid,
                    resource={
                        k: row[k]
                        for k in ("resource_uid", "resource_name", "resource_type", "region")
                    }
                    | {"vpc_id": row["vpc_id"]},
                    connection_id=row["connection_id"],
                )
            rank = _RANK.get(row["severity"])
            if rank is not None:
                resource.counts[source][rank] += 1
            key = (row["tool"], row["check_id"])
            problem = problems.get(key)
            if problem is None:
                problem = problems[key] = _Problem(
                    tool=row["tool"],
                    check_id=row["check_id"],
                    title=row["title"],
                    severity=row["severity"],
                    remediation_text=row["remediation_text"],
                    remediation_url=row["remediation_url"],
                    sample_id=row["id"],
                )
            elif _RANK.get(row["severity"], 9) < _RANK.get(problem.severity, 9):
                problem.severity = row["severity"]
            problem.resources.add(rid)
            problem.accounts.add(row["connection_id"])
    ordered = sorted(resources.values(), key=_Resource.rank)
    shown = [r.resource_id for r in ordered[:blocks]]
    rows: dict[int, list[dict[str, Any]]] = {}
    listed = 0
    for start in range(0, len(shown), BATCH):
        ids = shown[start : start + BATCH]
        found = findings.resource_problems(
            conn, ids, severities=filters.severities, tags=filters.tags
        )
        by_resource: dict[int, list[dict[str, Any]]] = {}
        for row in found:
            by_resource.setdefault(row["resource_id"], []).append(row)
        for rid in ids:
            kept = sorted(by_resource.get(rid, []), key=_problem_rank)[: max(per_resource, 0)]
            kept = kept[: max(cap - listed, 0)]
            for row in kept:
                row["source"] = _source(row)
            rows[rid] = kept
            listed += len(kept)
    listed_rows = [r for kept in rows.values() for r in kept]
    referenced = sorted(
        {(r["tool"], r["check_id"]) for r in listed_rows},
        key=lambda k: (_RANK.get(problems[k].severity, 9), -problems[k].count, k),
    )[:PDF_REFERENCE_CAP]
    facts = findings.vulnerability_facts(
        conn,
        [r["id"] for r in listed_rows if r["source"] == VULNERABILITY]
        + [problems[k].sample_id for k in referenced if k[0] == findings.VULNERABILITY_TOOL],
    )
    return Collected(
        total=total,
        by_severity=by_severity,
        by_source=by_source,
        by_account=by_account,
        by_type=by_type,
        by_region=by_region,
        accounts=accounts,
        resources=ordered,
        problems=problems,
        rows=rows,
        listed=listed,
        texts=findings.check_texts(conn, referenced),
        facts=facts,
        assets=metrics.asset_types_of(conn, list(filters.resources.connection_ids), today=today),
    )


def _chips(counts: list[int]) -> list[dict[str, Any]]:
    return [
        {"severity": s, "letter": _LETTERS[s], "count": n}
        for s, n in zip(SEVERITIES, counts, strict=True)
        if n
    ]


def _where(c: Collected, r: _Resource) -> dict[str, Any]:
    name, account_id = c.accounts.get(r.connection_id, ("", ""))
    return {
        "name": r.resource["resource_name"],
        "uid": r.resource["resource_uid"],
        "account": name,
        "account_id": account_id,
        "region": r.resource["region"],
        "type": r.resource["resource_type"],
        "vpc_id": r.resource["vpc_id"],
    }


def _resource_row(c: Collected, r: _Resource) -> dict[str, Any]:
    """A resource as the summary and the named list show it: where, chips, totals by source."""
    both = r.total()
    return {
        **_where(c, r),
        "chips": _chips(both),
        "total": sum(both),
        "misconfigurations": sum(r.counts[MISCONFIGURATION]),
        "vulnerabilities": sum(r.counts[VULNERABILITY]),
    }


def _problem_line(c: Collected, row: dict[str, Any]) -> dict[str, Any]:
    facts = c.facts.get(row["id"])
    return {
        "severity": row["severity"],
        "tool": row["tool"],
        "check_id": row["check_id"],
        "title": row["title"],
        "result": _plain(row["detail"]) if row["source"] == MISCONFIGURATION else None,
        "first_seen": _day(row["first_seen"]),
        "facts": _facts(facts) if row["source"] == VULNERABILITY else None,
    }


def _block(c: Collected, r: _Resource) -> dict[str, Any]:
    kept = c.rows.get(r.resource_id, [])
    both = r.total()
    return {
        **_where(c, r),
        "chips": {s: _chips(r.counts[s]) for s in SOURCES},
        "total": sum(both),
        "misconfigurations": [
            _problem_line(c, row) for row in kept if row["source"] == MISCONFIGURATION
        ],
        "vulnerabilities": [
            _problem_line(c, row) for row in kept if row["source"] == VULNERABILITY
        ],
        "more": sum(both) - len(kept),
    }


def _reference(c: Collected, key: tuple[str, str]) -> dict[str, Any]:
    problem = c.problems[key]
    text = c.texts.get(key, {})
    codes = [
        (label, _plain(text.get(column), code=True))
        for label, column in (("CLI", "code_cli"), ("Terraform", "code_terraform"))
        if text.get(column)
    ]
    vulnerability = problem.tool == findings.VULNERABILITY_TOOL
    return {
        "tool": problem.tool,
        "check_id": problem.check_id,
        "title": problem.title,
        "severity": problem.severity,
        "resources": problem.count,
        "risk": None if vulnerability else _plain(text.get("risk")),
        "description": _plain(text.get("description")),
        "fix": _plain(problem.remediation_text),
        "fix_link": _link(problem.remediation_url),
        "code": [{"label": label, "text": body} for label, body in codes],
        "facts": _facts(c.facts.get(problem.sample_id)) if vulnerability else None,
    }


def build_context(
    c: Collected,
    *,
    report_id: int,
    requested_by: str,
    generated_at: datetime,
    scope_words: str,
    severities_in_scope: list[str],
    data_through: dict[int, date],
) -> dict[str, Any]:
    """Everything the renderer prints, as plain JSON, in the shape the summary of every PDF
    shares (pdf.build_context) plus the resource blocks and the reference. Pure."""
    days = sorted({d.isoformat() for d in data_through.values()})
    detailed = c.resources[:PDF_RESOURCE_BLOCKS]
    common = heapq.nsmallest(
        TOP_COMMON,
        c.problems.values(),
        key=lambda p: (-p.count, _RANK.get(p.severity, 9), p.tool, p.check_id),
    )
    referenced = sorted(
        {(row["tool"], row["check_id"]) for kept in c.rows.values() for row in kept},
        key=lambda k: (_RANK.get(c.problems[k].severity, 9), -c.problems[k].count, k),
    )
    return {
        "report_id": report_id,
        "kind": "resource-problems",
        "requested_by": requested_by,
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M"),
        "scope": scope_words,
        "total": c.total,
        "listed": c.listed,
        "truncated": c.truncated,
        "caps": {
            "per_block": PDF_PROBLEMS_PER_RESOURCE,
            "total": PDF_RESOURCE_CAP,
            "blocks": PDF_RESOURCE_BLOCKS,
        },
        "data_through": days[-1] if days else None,
        "data_through_differs": len(days) > 1,
        "account_names": [a[0] for a in sorted(c.accounts.values())],
        "severities": [
            {"severity": s, "count": c.by_severity.get(s, 0), "in_scope": s in severities_in_scope}
            for s in SEVERITIES
        ],
        "by_source": {
            source: [c.by_source[source].get(s, 0) for s in SEVERITIES] for source in SOURCES
        },
        "by_account": [
            {
                "name": c.accounts.get(cid, ("", ""))[0],
                "account_id": c.accounts.get(cid, ("", ""))[1],
                "findings": n,
                "data_through": _day(data_through.get(cid)),
            }
            for cid, n in c.by_account.most_common(SUMMARY_ROWS)
        ],
        "more_accounts": max(len(c.by_account) - SUMMARY_ROWS, 0),
        "by_type": [{"type": t, "findings": n} for t, n in c.by_type.most_common(SUMMARY_ROWS)],
        "more_types": max(len(c.by_type) - SUMMARY_ROWS, 0),
        "by_region": [
            {"region": r or None, "findings": n} for r, n in c.by_region.most_common(SUMMARY_ROWS)
        ],
        "more_regions": max(len(c.by_region) - SUMMARY_ROWS, 0),
        "shares": _shares(c.by_severity, c.total),
        "resources": len(c.resources),
        "worst": [_resource_row(c, r) for r in c.resources[:TOP_RESOURCES]],
        "common": [
            {
                "severity": p.severity,
                "title": p.title,
                "tool": p.tool,
                "check_id": p.check_id,
                "resources": p.count,
                "accounts": len(p.accounts),
            }
            for p in common
        ],
        "assets": metrics.by_category(c.assets) if c.assets is not None else None,
        "blocks": [_block(c, r) for r in detailed],
        "reference": [_reference(c, k) for k in referenced[:PDF_REFERENCE_CAP]],
        "more_reference": max(len(referenced) - PDF_REFERENCE_CAP, 0),
        "others": [
            _resource_row(c, r)
            for r in c.resources[PDF_RESOURCE_BLOCKS : PDF_RESOURCE_BLOCKS + PDF_NAMED_CAP]
        ],
        "more_others": max(len(c.resources) - PDF_RESOURCE_BLOCKS - PDF_NAMED_CAP, 0),
    }


_LEVELS = {
    "any": "with {}",
    "critical_high": "with critical or high {}",
    "high": "with critical or high {}",
    "exploitable": "with a public exploit",
}


def describe(filters: ResourceProblemFilters, *, accounts: int) -> str:
    """The report's scope in words, as the cover prints it."""
    f = filters.resources
    words: list[str | None] = []
    if filters.severities:
        ordered = sorted(filters.severities, key=lambda s: _RANK.get(s, 9))
        words.append(", ".join(s.capitalize() for s in ordered))
    words.append("1 account" if accounts == 1 else f"{accounts} accounts")
    words.append("open")
    words.append("one resource" if filters.resource_id is not None else None)
    if f.regions:
        words.append(f.regions[0] if len(f.regions) == 1 else f"{len(f.regions)} regions")
    if f.resource_types:
        words.append(
            f.resource_types[0]
            if len(f.resource_types) == 1
            else f"{len(f.resource_types)} resource types"
        )
    if f.misconfigurations:
        words.append(_LEVELS[f.misconfigurations].format("misconfigurations"))
    if f.vulnerabilities:
        words.append(_LEVELS[f.vulnerabilities].format("vulnerabilities"))
    words.append("internet reachable" if f.internet else None)
    words.append("assets only" if f.assets else None)
    words.append("removed included" if f.include_deleted else None)
    words.append(f"matching “{f.q}”" if f.q else None)
    for key, values in filters.tags:
        shown = (
            " or ".join(values) if len(values) <= 3 else f"{values[0]} or {len(values) - 1} more"
        )
        words.append(f"tag {key} = {shown}")
    return " · ".join(w for w in words if w)
