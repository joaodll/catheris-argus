"""Investigate -> Resources: the inventory, and one resource with its configuration and edges
as of a day."""

from datetime import UTC, date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel

from argus import findings, ingest, inventory, relationships
from argus.api.deps import Db, Viewer
from argus.api.routes.findings import CommandOut
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


class ResourceRow(ResourceOut):
    # Open and reopened findings on the resource, and the worst severity among them (null
    # when there are none).
    open_findings: int
    worst_severity: str | None


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


class ResourceDetail(ResourceOut):
    tags: dict[str, Any]
    as_of: date
    seen_on: date | None
    config: dict[str, Any] | None
    edges: list[EdgeOut]
    scanned: ToolScans
    # CloudFox's loot commands for this resource (ADR-0038); empty when it has none.
    commands: list[CommandOut]


@router.get("/resources")
def list_resources(
    conn: Db,
    _user: Viewer,
    *,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    connection_id: int | None = None,
    type: Annotated[str | None, Query(max_length=128)] = None,
    region: Annotated[str | None, Query(max_length=64)] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    include_deleted: bool = False,
    order: inventory.ResourceOrder = "name_asc",
) -> ResourcePage:
    rows, total = inventory.list_resources(
        conn,
        limit=limit,
        offset=offset,
        connection_id=connection_id,
        resource_type=type,
        region=region,
        q=q or None,
        include_deleted=include_deleted,
        order=order,
    )
    # Only a search count is capped (core.db.count_sql); any other count is exact.
    capped = bool(q) and total > SEARCH_COUNT_CAP
    counts = findings.open_finding_counts(conn, [r["id"] for r in rows])
    return ResourcePage(
        items=[
            ResourceRow.model_validate(
                {
                    **r,
                    "open_findings": counts.get(r["id"], (0, None))[0],
                    "worst_severity": counts.get(r["id"], (0, None))[1],
                }
            )
            for r in rows
        ],
        total=SEARCH_COUNT_CAP if capped else total,
        total_capped=capped,
        data_through=ingest.data_through(conn, connection_id=connection_id, tools=["steampipe"]),
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
        for tool in ("steampipe", "prowler", "cloudfox")
    }
    return ResourceDetail.model_validate(
        {
            **found,
            "scanned": scanned,
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
