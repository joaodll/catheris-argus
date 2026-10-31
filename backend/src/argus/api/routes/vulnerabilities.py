"""Investigate -> Vulnerabilities: the CVEs each provider's own scanner reports (AWS Inspector on
AWS), from the provider-neutral vulnerabilities tool (ADR-0042, amended 2026-10-31). They are
findings, with the lifecycle every finding has; this list keeps them apart from Prowler's and
CloudFox's (Misconfigurations) and adds what only a vulnerability can be filtered on. A CVE's
own link and details row are /findings/{finding_id}. Read-only."""

from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from argus import findings
from argus.api.deps import Db, Viewer
from argus.api.routes.findings import (
    Facet,
    FindingGroupPage,
    FindingPage,
    Severity,
    finding_page,
    group_page,
)
from argus.api.types import Provider

router = APIRouter(tags=["vulnerabilities"])

TOOLS = (findings.VULNERABILITY_TOOL,)


def _many() -> Any:
    return Field(default_factory=list, max_length=50)


class VulnerabilityQuery(BaseModel):
    """The Vulnerabilities list's query parameters. A list parameter repeats and matches any of
    its values; absent, it does not filter."""

    limit: int = Field(20, ge=1, le=200)
    offset: int = Field(0, ge=0)
    connection_id: list[int] = _many()
    severity: list[Severity] = _many()
    provider: list[Provider] = Field(default_factory=list, max_length=3)
    # open = open and reopened, the vulnerabilities still to fix.
    state: findings.FindingState = "open"
    region: list[Facet] = _many()
    resource_type: list[Facet] = _many()
    # CVE ids (a code vulnerability's is "code:<title>").
    check_id: list[Facet] = _many()
    # Suppressed in the scanner.
    muted: findings.MutedFilter = "any"
    # Only vulnerabilities first seen in their latest scan.
    new: bool = False
    # Only those with a public exploit.
    exploitable: bool = False
    # available: a fixed version exists for its packages (or some of them); none: not yet.
    fix: findings.FixFilter = "any"
    resource_id: int | None = None
    # Matches the title (CVE and package), CVE id or resource uid anywhere, in any case.
    q: str | None = Field(None, max_length=200)
    order: findings.FindingOrder = "severity"


def _filters(query: VulnerabilityQuery) -> findings.FindingFilters:
    return findings.FindingFilters(
        connection_ids=tuple(query.connection_id),
        severities=tuple(query.severity),
        tools=TOOLS,
        providers=tuple(query.provider),
        state=query.state,
        regions=tuple(query.region),
        resource_types=tuple(query.resource_type),
        check_ids=tuple(query.check_id),
        muted=query.muted,
        new=query.new,
        resource_id=query.resource_id,
        q=query.q or None,
        exploitable=query.exploitable,
        fix=query.fix,
    )


@router.get("/vulnerabilities")
def list_vulnerabilities(
    conn: Db, _user: Viewer, query: Annotated[VulnerabilityQuery, Query()]
) -> FindingPage:
    """One page of CVE findings; each item carries its `vulnerability`."""
    return finding_page(
        conn, _filters(query), limit=query.limit, offset=query.offset, order=query.order
    )


@router.get("/vulnerabilities/groups")
def vulnerability_groups(
    conn: Db, _user: Viewer, query: Annotated[VulnerabilityQuery, Query()]
) -> FindingGroupPage:
    """The Vulnerabilities list by CVE, with the list's filters: one row per CVE, worst
    severity first, then the CVEs with the most findings."""
    return group_page(
        conn, _filters(query), limit=query.limit, offset=query.offset, order=query.order
    )


class VulnerabilityFacets(BaseModel):
    regions: list[str]
    resource_types: list[str]


@router.get("/vulnerabilities/facets")
def vulnerability_facets(
    conn: Db,
    _user: Viewer,
    connection_id: Annotated[list[int], Query(max_length=50)] = [],  # noqa: B006 - FastAPI copies
) -> VulnerabilityFacets:
    """The options of the Vulnerabilities filters that come from the data."""
    facets = findings.finding_facets(conn, tools=TOOLS, connection_ids=tuple(connection_id))
    return VulnerabilityFacets(regions=facets.regions, resource_types=facets.resource_types)
