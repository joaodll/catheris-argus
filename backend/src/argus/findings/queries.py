"""Read side of findings: the Findings list, its filter options, and open-finding counts per
resource. Filters are plain columns (most take several values, any of which matches); the search
is a contains match on three text columns."""

from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import Connection, text

from argus.connections import DIRECTORY_SQL
from argus.core.db import count_sql, like_contains
from argus.findings.model import VULNERABILITY_TOOL
from argus.findings.prowler import EXPOSURE_CHECKS

# Exported SQL: the view attack-path rules read as `f`. One connection's failing findings now.
# CVEs are left out (ADR-0042): any CVE would raise nearly every path through an instance or a
# function; a path kind built for them joins them on purpose.
FAILING_FINDINGS_SQL = f"""
  SELECT resource_uid, check_id, severity FROM finding
  WHERE connection_id = :connection_id AND state IN ('open', 'reopened') AND NOT muted
    AND status = 'FAIL' AND tool <> '{VULNERABILITY_TOOL}'
"""  # noqa: S608 - a fixed constant

FindingState = Literal["open", "reopened", "resolved", "accepted_risk"]
FindingOrder = Literal["severity", "severity_asc", "last_seen_desc", "last_seen_asc"]
# any: muted findings are listed with the rest; hide: left out; only: nothing else.
MutedFilter = Literal["any", "hide", "only"]
# What Argus's internet rules say about a finding's resource (ADR-0035): set on CloudFox's
# public endpoints and Prowler's exposure checks, null on every other finding.
FindingReach = Literal["confirmed", "restricted", "unknown", "not_covered"]

# "open" in the UI means still to fix: open, and reopened after it was resolved.
_STATES: dict[str, list[str]] = {
    "open": ["open", "reopened"],
    "reopened": ["reopened"],
    "resolved": ["resolved"],
    "accepted_risk": ["accepted_risk"],
}
_SEVERITY_RANK = (
    "array_position(ARRAY['critical','high','medium','low','informational'], f.severity)"
)
_ORDERS: dict[str, str] = {
    "severity": f"{_SEVERITY_RANK}, f.last_seen DESC, f.id",
    # Least severe first: finding_severity_order read backwards, so the same index serves it.
    "severity_asc": f"{_SEVERITY_RANK} DESC, f.last_seen, f.id DESC",
    "last_seen_desc": "f.last_seen DESC, f.id DESC",
    "last_seen_asc": "f.last_seen, f.id",
}
# The searched text, exactly as the trigram index finding_search is defined (migration 0008).
_SEARCH = r"(f.title || E'\n' || f.check_id || E'\n' || f.resource_uid)"
_FILTERS = f"""
  WHERE f.state = ANY(CAST(:states AS text[]))
    AND (CAST(:c AS bigint[]) IS NULL OR f.connection_id = ANY(CAST(:c AS bigint[])))
    AND (CAST(:sev AS text[]) IS NULL OR f.severity = ANY(CAST(:sev AS text[])))
    AND (CAST(:tool AS text[]) IS NULL OR f.tool = ANY(CAST(:tool AS text[])))
    AND (CAST(:prov AS text[]) IS NULL OR f.connection_id IN (
      SELECT d.id FROM ({DIRECTORY_SQL}) d WHERE d.provider = ANY(CAST(:prov AS text[]))))
    AND (CAST(:rg AS text[]) IS NULL OR f.region = ANY(CAST(:rg AS text[])))
    AND (CAST(:svc AS text[]) IS NULL OR f.service = ANY(CAST(:svc AS text[])))
    AND (CAST(:rtype AS text[]) IS NULL OR f.resource_type = ANY(CAST(:rtype AS text[])))
    AND (CAST(:chk AS text[]) IS NULL OR f.check_id = ANY(CAST(:chk AS text[])))
    AND (CAST(:cat AS text[]) IS NULL OR f.categories && CAST(:cat AS text[]))
    AND (CAST(:st AS text[]) IS NULL OR f.status = ANY(CAST(:st AS text[])))
    AND (CAST(:reach AS text[]) IS NULL OR f.reach = ANY(CAST(:reach AS text[])))
    AND (CAST(:muted AS boolean) IS NULL OR f.muted = :muted)
    AND (NOT :new OR f.first_seen = f.last_seen)
    AND (CAST(:res AS bigint) IS NULL OR f.resource_id = :res)
    AND (CAST(:p AS text) IS NULL OR {_SEARCH} ILIKE :p ESCAPE '\\')
"""  # noqa: S608 - exported SQL constants only
_MUTED: dict[str, bool | None] = {"any": None, "hide": False, "only": True}
# What the list and a single finding return. Exported SQL constants only.
_SELECT = f"""
        SELECT f.id, f.finding_uid, f.tool, f.check_id, f.connection_id, c.name AS connection,
               c.provider,
               f.region, f.resource_uid, f.resource_id, f.severity, f.status, f.muted, f.title,
               f.remediation_text, f.remediation_url, f.service, f.resource_type, f.categories,
               f.state, f.first_seen, f.last_seen, f.resolved_on, f.reach, f.reach_reason,
               f.resource_name AS reported_resource_name, f.detail
        FROM finding f JOIN ({DIRECTORY_SQL}) c ON c.id = f.connection_id"""  # noqa: S608


@dataclass(frozen=True)
class FindingFilters:
    """What the Findings list is narrowed to. An empty tuple does not filter; several values
    match any of them. `new`: first seen in the finding's latest scan (Prowler's "delta: new").
    `q` matches the title, check id or resource uid anywhere, in any case."""

    connection_ids: tuple[int, ...] = ()
    severities: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()  # the finding's connection's provider
    state: FindingState = "open"
    regions: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    resource_types: tuple[str, ...] = ()
    check_ids: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    statuses: tuple[str, ...] = ()
    reaches: tuple[str, ...] = ()  # Argus's reach (FindingReach)
    muted: MutedFilter = "any"
    new: bool = False
    resource_id: int | None = None
    q: str | None = None


def _any(values: tuple[Any, ...]) -> list[Any] | None:
    return list(values) if values else None


def _params(filters: FindingFilters) -> dict[str, Any]:
    """The bind parameters of _FILTERS."""
    return {
        "states": _STATES[filters.state],
        "c": _any(filters.connection_ids),
        "sev": _any(filters.severities),
        "tool": _any(filters.tools),
        "prov": _any(filters.providers),
        "rg": _any(filters.regions),
        "svc": _any(filters.services),
        "rtype": _any(filters.resource_types),
        "chk": _any(filters.check_ids),
        "cat": _any(filters.categories),
        "st": _any(filters.statuses),
        "reach": _any(filters.reaches),
        "muted": _MUTED[filters.muted],
        "new": filters.new,
        "res": filters.resource_id,
        "p": like_contains(filters.q) if filters.q else None,
    }


def list_findings(
    conn: Connection,
    *,
    limit: int,
    offset: int,
    filters: FindingFilters | None = None,
    order: FindingOrder = "severity",
) -> tuple[list[dict[str, Any]], int]:
    """One page of findings matching the filters, in `order`, and how many match (with a
    search, at most SEARCH_COUNT_CAP + 1)."""
    filters = filters or FindingFilters()
    params = _params(filters)
    rows = conn.execute(
        text(f"""
        {_SELECT}
        {_FILTERS}
        ORDER BY {_ORDERS[order]}
        LIMIT :l OFFSET :o
    """),
        {**params, "l": limit, "o": offset},
    )
    total = conn.execute(
        text(count_sql(f"FROM finding f {_FILTERS}", search=bool(filters.q))),
        params,
    ).scalar_one()
    return [dict(r._mapping) for r in rows], int(total)


# Findings by check: worst first, then the checks with the most findings. Over `per`, the
# findings grouped by check and connection.
_GROUP_ORDERS: dict[str, str] = {
    "severity": "min(per.rank), sum(per.n) DESC, per.tool, per.check_id",
    "severity_asc": "min(per.rank) DESC, sum(per.n), per.tool, per.check_id",
    "last_seen_desc": "max(per.last_seen) DESC, min(per.rank), per.tool, per.check_id",
    "last_seen_asc": "max(per.last_seen), min(per.rank), per.tool, per.check_id",
}


def finding_groups(
    conn: Connection,
    *,
    limit: int,
    offset: int,
    filters: FindingFilters | None = None,
    order: FindingOrder = "severity",
) -> tuple[list[dict[str, Any]], int]:
    """The Findings list by check: one row per (tool, check id) of the findings matching the
    filters, with its worst severity, how many findings and connections it has, and when it
    was last seen; and how many checks match.

    Findings, not distinct resources: counting distinct resource uids over every open finding
    sorts them all (about 3 s on the budget estate); grouping by connection first keeps every
    aggregate a hash and the connection count exact (owner's decision, 2026-10-31)."""
    filters = filters or FindingFilters()
    params = _params(filters)
    rows = conn.execute(
        text(f"""
        WITH per AS (
          SELECT f.tool, f.check_id, f.connection_id, min(f.title) AS title, count(*) AS n,
                 min({_SEVERITY_RANK}) AS rank, max(f.last_seen) AS last_seen
          FROM finding f
          {_FILTERS}
          GROUP BY f.tool, f.check_id, f.connection_id
        )
        SELECT per.tool, per.check_id, min(per.title) AS title,
               (ARRAY['critical','high','medium','low','informational'])[min(per.rank)]
                 AS severity,
               sum(per.n) AS findings, count(*) AS connections, max(per.last_seen) AS last_seen,
               count(*) OVER () AS total
        FROM per
        GROUP BY per.tool, per.check_id
        ORDER BY {_GROUP_ORDERS[order]}
        LIMIT :l OFFSET :o
    """),  # noqa: S608 - constant SQL only
        {**params, "l": limit, "o": offset},
    ).all()
    if rows:
        total = int(rows[0].total)
    elif offset == 0:
        total = 0
    else:  # past the last page: the count alone
        total = conn.execute(
            text(f"""
            SELECT count(*) FROM (SELECT 1 FROM finding f {_FILTERS} GROUP BY f.tool, f.check_id) g
        """),  # noqa: S608 - constant SQL only
            params,
        ).scalar_one()
    return [{k: v for k, v in r._mapping.items() if k != "total"} for r in rows], int(total)


def get_finding(conn: Connection, finding_id: int) -> dict[str, Any] | None:
    """One finding, whatever its state, with what the tool says about the resource (detail)
    and about the check (description, risk, links, remediation code): the finding's own link,
    and the list's details row."""
    row = conn.execute(
        text(f"""
        SELECT x.*, fc.description, fc.risk, fc.links, fc.code_cli,
               fc.code_native_iac, fc.code_terraform, fc.code_other, fc.notes
        FROM ({_SELECT} WHERE f.id = :i) x
        JOIN finding f ON f.id = x.id
        LEFT JOIN finding_check_text fc ON fc.tool = f.tool AND fc.check_id = f.check_id
    """),  # noqa: S608 - constant SQL only
        {"i": finding_id},
    ).one_or_none()
    return dict(row._mapping) if row else None


@dataclass(frozen=True)
class FindingFacets:
    regions: list[str]
    services: list[str]
    resource_types: list[str]
    categories: list[str]
    checks: list[tuple[str, str]]  # (tool, check_id)


def finding_facets(conn: Connection, *, connection_ids: tuple[int, ...] = ()) -> FindingFacets:
    """The values the data-driven filters offer, over these connections (all when empty), from
    finding_facet, which ingest rebuilds after each load. Empty values (rows not rescanned
    since migration 0009) are not there."""
    rows = conn.execute(
        text("""
        SELECT DISTINCT facet, tool, value FROM finding_facet
        WHERE CAST(:c AS bigint[]) IS NULL OR connection_id = ANY(CAST(:c AS bigint[]))
        ORDER BY facet, value, tool
    """),
        {"c": _any(connection_ids)},
    ).all()
    values: dict[str, list[str]] = {}
    checks: list[tuple[str, str]] = []
    for r in rows:
        if r.facet == "check":
            checks.append((r.tool, r.value))
        elif r.value not in values.setdefault(r.facet, []):
            values[r.facet].append(r.value)  # sorted, so a repeat follows its first
    return FindingFacets(
        regions=values.get("region", []),
        services=values.get("service", []),
        resource_types=values.get("resource_type", []),
        categories=values.get("category", []),
        checks=checks,
    )


def open_finding_counts_by_tool(
    conn: Connection, resource_ids: list[int]
) -> dict[int, dict[str, tuple[int, str]]]:
    """open_finding_counts() per tool: {resource id: {tool: (count, worst severity)}}, for the
    Resource map's badges and panel (ADR-0033). Bounded by the caller (at most 500 ids)."""
    if not resource_ids:
        return {}
    rows = conn.execute(
        text(f"""
        SELECT f.resource_id, f.tool, count(*) AS n,
               (ARRAY['critical','high','medium','low','informational'])[min({_SEVERITY_RANK})]
                 AS worst
        FROM finding f
        WHERE f.resource_id = ANY(CAST(:ids AS bigint[])) AND f.state IN ('open', 'reopened')
        GROUP BY f.resource_id, f.tool
    """),  # noqa: S608 - fixed fragment
        {"ids": resource_ids},
    )
    counts: dict[int, dict[str, tuple[int, str]]] = {}
    for r in rows:
        counts.setdefault(r.resource_id, {})[r.tool] = (int(r.n), r.worst)
    return counts


def open_exposure_counts(conn: Connection, resource_ids: list[int]) -> dict[int, int]:
    """For each of these resources: its open Prowler exposure findings, muted or not, which the
    front doors list counts ("Prowler: N exposure checks failing", ADR-0035, sixth amendment).
    The same findings as the list's tool and Reach filters on the resource. Bounded by the
    caller (one page of doors)."""
    if not resource_ids:
        return {}
    rows = conn.execute(
        text("""
        SELECT f.resource_id, count(*) AS n
        FROM finding f
        WHERE f.resource_id = ANY(CAST(:ids AS bigint[])) AND f.state IN ('open', 'reopened')
          AND f.tool = 'prowler' AND f.check_id = ANY(CAST(:chk AS text[]))
        GROUP BY f.resource_id
    """),
        {"ids": resource_ids, "chk": list(EXPOSURE_CHECKS)},
    )
    return {r.resource_id: int(r.n) for r in rows}


def open_finding_counts(conn: Connection, resource_ids: list[int]) -> dict[int, tuple[int, str]]:
    """For each of these resources with open or reopened Prowler or CloudFox findings: how many,
    and the worst severity among them. CVEs are counted apart (vulnerabilities, ADR-0042).
    Called with one page of resources, so the input is bounded."""
    if not resource_ids:
        return {}
    rows = conn.execute(
        text(f"""
        SELECT f.resource_id, count(*) AS n,
               (ARRAY['critical','high','medium','low','informational'])[min({_SEVERITY_RANK})]
                 AS worst
        FROM finding f
        WHERE f.resource_id = ANY(CAST(:ids AS bigint[])) AND f.state IN ('open', 'reopened')
          AND f.tool <> '{VULNERABILITY_TOOL}'
        GROUP BY f.resource_id
    """),  # noqa: S608 - fixed fragment
        {"ids": resource_ids},
    )
    return {r.resource_id: (int(r.n), r.worst) for r in rows}
