"""Investigate -> Resources: the inventory, and one resource with its configuration and edges
as of a day."""

from datetime import UTC, date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from argus import findings, ingest, inventory, relationships
from argus.api.deps import Db, Viewer
from argus.api.routes.findings import CommandOut, VulnerabilityOut
from argus.core.db import SEARCH_COUNT_CAP

router = APIRouter(tags=["inventory"])


class ResourceOut(BaseModel):
    id: int
    resource_uid: str
    connection_id: int
    provider: str
    region: str
    type: str
    native_id: str
    name: str | None
    vpc_id: str | None
    first_seen: date
    last_seen: date
    deleted_on: date | None


class VulnerabilitySummary(BaseModel):
    """A resource's open Inspector CVEs (ADR-0042), suppressed ones left out."""

    open: int
    worst: str | None  # null when there are none
    exploitable: int  # of the open ones, with a public exploit
    # Inspector scans the resource (an active scan); false: "Not scanned".
    scanned: bool


class ResourceRow(ResourceOut):
    # Open and reopened Prowler and CloudFox findings on the resource, and the worst severity
    # among them (null when there are none). Inspector's CVEs are counted apart.
    open_findings: int
    worst_severity: str | None
    # Null when Inspector does not scan this type, or never ran for the connection.
    vulnerabilities: VulnerabilitySummary | None


class ResourcePage(BaseModel):
    items: list[ResourceRow]
    total: int  # resources matching the filters, for the page count
    # True when a text search matched more than `total` (the count stops at 10,000): the UI
    # says "10,000+ records".
    total_capped: bool
    # The scan time the list reflects (newest day ingested); null when nothing is ingested.
    data_through: date | None


class ResourceFacets(BaseModel):
    types: list[str]
    regions: list[str]


class EdgeOut(BaseModel):
    id: int
    source_uid: str
    target_uid: str
    source_resource_id: int | None
    target_resource_id: int | None
    # The ends' names (or native ids) when they are in the inventory.
    source_name: str | None
    target_name: str | None
    type: str
    origin: str
    attributes: dict[str, Any]
    first_seen: date
    last_seen: date


class ToolScans(BaseModel):
    """The newest day each tool's ingested run covers for the resource's connection; null
    when the tool never scanned it ("Not covered" rather than "no findings")."""

    steampipe: date | None
    prowler: date | None
    cloudfox: date | None
    inspector: date | None


class CoverageOut(BaseModel):
    """Inspector's own words for one scan type: PACKAGE or CODE; ACTIVE or INACTIVE, with a
    reason such as UNMANAGED_EC2_INSTANCE."""

    scan_type: str
    status_code: str
    status_reason: str | None
    last_scanned_at: datetime | None


class TopVulnerabilityOut(BaseModel):
    finding_id: int
    title: str
    severity: str
    vulnerability: VulnerabilityOut


class InspectorSection(BaseModel):
    """The resource's Inspector vulnerabilities, as of the connection's last Inspector run."""

    # Open, unmuted CVEs per severity (a severity with none is absent).
    by_severity: dict[str, int]
    suppressed: int  # open but suppressed in Inspector
    # The worst open ones: severity, then a public exploit, then EPSS.
    top: list[TopVulnerabilityOut]
    # Empty when Inspector reports no coverage for the resource.
    coverage: list[CoverageOut]


class ResourceDetail(ResourceOut):
    tags: dict[str, Any]
    as_of: date
    seen_on: date | None
    config: dict[str, Any] | None
    edges: list[EdgeOut]
    scanned: ToolScans
    # CloudFox's loot commands for this resource (ADR-0038); empty when it has none.
    commands: list[CommandOut]
    # Null when Inspector does not scan this type of resource.
    inspector: InspectorSection | None


class ResourceQuery(BaseModel):
    """The Resources list's query parameters."""

    limit: int = Field(20, ge=1, le=200)
    offset: int = Field(0, ge=0)
    connection_id: int | None = None
    type: str | None = Field(None, max_length=128)
    region: str | None = Field(None, max_length=64)
    q: str | None = Field(None, max_length=200)
    include_deleted: bool = False
    order: inventory.ResourceOrder = "name_asc"
    # Only resources with open Inspector CVEs: any, critical or high, or with a public exploit.
    vulnerabilities: findings.VulnerabilityLevel | None = None


@router.get("/resources")
def list_resources(
    conn: Db, _user: Viewer, query: Annotated[ResourceQuery, Query()]
) -> ResourcePage:
    q = query.q or None
    rows, total = inventory.list_resources(
        conn,
        limit=query.limit,
        offset=query.offset,
        filters=inventory.ResourceFilters(
            connection_id=query.connection_id,
            resource_type=query.type,
            region=query.region,
            q=q,
            include_deleted=query.include_deleted,
            within=(
                findings.VULNERABLE_RESOURCES_SQL[query.vulnerabilities]
                if query.vulnerabilities
                else None
            ),
        ),
        order=query.order,
    )
    # Only a search count is capped (core.db.count_sql); any other count is exact.
    capped = bool(q) and total > SEARCH_COUNT_CAP
    ids = [r["id"] for r in rows]
    counts = findings.open_finding_counts(conn, ids)
    vulns = _vulnerabilities(conn, rows)
    return ResourcePage(
        items=[
            ResourceRow.model_validate(
                {
                    **r,
                    "open_findings": counts.get(r["id"], (0, None))[0],
                    "worst_severity": counts.get(r["id"], (0, None))[1],
                    "vulnerabilities": vulns.get(r["id"]),
                }
            )
            for r in rows
        ],
        total=SEARCH_COUNT_CAP if capped else total,
        total_capped=capped,
        data_through=ingest.data_through(
            conn, connection_id=query.connection_id, tools=["steampipe"]
        ),
    )


def _vulnerabilities(conn: Db, rows: list[dict[str, Any]]) -> dict[int, VulnerabilitySummary]:
    """For one page of resources: the Vulnerabilities cell of those Inspector scans the type of,
    on connections with an Inspector run."""
    scannable = [r for r in rows if r["type"] in findings.SCANNED_TYPES]
    inspected = {
        c
        for c in {r["connection_id"] for r in scannable}
        if ingest.data_through(conn, connection_id=c, tools=["inspector"]) is not None
    }
    ids = [r["id"] for r in scannable if r["connection_id"] in inspected]
    counts = findings.vulnerability_counts(conn, ids)
    scanned = findings.scanned_resources(conn, ids)
    empty = findings.VulnerabilityCount(0, None, 0)
    return {
        i: VulnerabilitySummary(
            open=counts.get(i, empty).open,
            worst=counts.get(i, empty).worst,
            exploitable=counts.get(i, empty).exploitable,
            scanned=i in scanned,
        )
        for i in ids
    }


def _inspector(conn: Db, found: dict[str, Any]) -> InspectorSection | None:
    if found["type"] not in findings.SCANNED_TYPES:
        return None
    section = findings.resource_vulnerabilities(conn, found["id"])
    return InspectorSection(
        by_severity=section.by_severity,
        suppressed=section.suppressed,
        top=[
            TopVulnerabilityOut(
                finding_id=t.finding_id,
                title=t.title,
                severity=t.severity,
                vulnerability=VulnerabilityOut.model_validate(vars(t.facts)),
            )
            for t in section.top
        ],
        coverage=[
            CoverageOut.model_validate(vars(c))
            for c in findings.resource_coverage(conn, found["id"])
        ],
    )


@router.get("/resources/facets")
def resource_facets(conn: Db, _user: Viewer, connection_id: int | None = None) -> ResourceFacets:
    """The options of the Resources filters that come from the data."""
    return ResourceFacets.model_validate(
        inventory.resource_facets(conn, connection_id=connection_id)
    )


@router.get("/resources/{resource_id}")
def resource(
    resource_id: int, conn: Db, _user: Viewer, as_of: date | None = None
) -> ResourceDetail:
    day = as_of or datetime.now(UTC).date()
    found = inventory.resource_at(conn, resource_id=resource_id, day=day)
    if found is None:
        raise LookupError(resource_id)
    edges = relationships.edges_at(
        conn, resource_id=resource_id, connection_id=found["connection_id"], day=day
    )
    ends = {e[k] for e in edges for k in ("source_resource_id", "target_resource_id") if e[k]}
    names = inventory.resource_names(conn, sorted(ends))
    scanned = {
        tool: ingest.data_through(conn, connection_id=found["connection_id"], tools=[tool])
        for tool in ("steampipe", "prowler", "cloudfox", "inspector")
    }
    return ResourceDetail.model_validate(
        {
            **found,
            "scanned": scanned,
            "inspector": _inspector(conn, found),
            "commands": [
                vars(c)
                for c in findings.commands_for_resource(
                    conn, connection_id=found["connection_id"], resource_uid=found["resource_uid"]
                )
            ],
            "edges": [
                EdgeOut.model_validate(
                    {
                        **e,
                        "source_name": names.get(e["source_resource_id"]),
                        "target_name": names.get(e["target_resource_id"]),
                    }
                )
                for e in edges
            ],
        }
    )
