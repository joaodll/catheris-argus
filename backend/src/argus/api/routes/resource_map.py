"""Investigate -> Resource map (ADR-0033): one neighbourhood at a time, never the estate.
Named reads only: a client chooses a connection, a focus, a depth, layers and origins, never a
query. Every read is for one connection (ADR-0033, amended 2026-10-09)."""

from datetime import UTC, date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from argus import connections, findings, ingest, inventory, relationships
from argus.api.deps import Db, Viewer

router = APIRouter(tags=["map"])

Uid = Annotated[str, Field(min_length=1, max_length=2048)]
TOOLS = ("prowler", "cloudfox")


class ToolFindings(BaseModel):
    open: int
    worst: str


class MapNode(BaseModel):
    uid: str
    # resource; or a pseudo-node: internet, admin (an account's administrator), external (a
    # host no inventoried resource owns), any (every resource of a service: a wildcard grant).
    kind: Literal["resource", "internet", "admin", "external", "any"]
    # Null when the resource is not in the inventory (another account, a type not collected).
    resource_id: int | None
    type: str | None
    name: str | None
    region: str | None
    connection_id: int | None
    deleted_on: date | None
    # Its neighbours were read (the map can still expand the others).
    expanded: bool
    # Owned by another connection, or an ARN of another account: drawn, never expanded.
    boundary: bool
    # Open findings per tool ("prowler", "cloudfox"); a tool with none is absent.
    findings: dict[str, ToolFindings]


class MapEdge(BaseModel):
    id: int
    source_uid: str
    target_uid: str
    type: str
    origin: str
    attributes: dict[str, Any]
    first_seen: date
    last_seen: date


class MapGroup(BaseModel):
    """More neighbours of one kind than the map draws one by one: one node for all of them."""

    id: str
    anchor_uid: str
    direction: Literal["out", "in"]
    edge_type: str
    resource_type: str | None
    count: int


class MapGraph(BaseModel):
    focus: str
    connection_id: int
    as_of: date
    nodes: list[MapNode]
    edges: list[MapEdge]
    groups: list[MapGroup]
    # The 500-node cap stopped the walk: fewer layers or less depth shows the rest.
    truncated: bool
    data_through: date | None


class GroupMember(BaseModel):
    node: MapNode
    edge: MapEdge


class GroupPage(BaseModel):
    items: list[GroupMember]
    total: int
    data_through: date | None


class MapQuery(BaseModel):
    focus: Uid
    # The connection whose edges are walked. Absent: the focus resource's own connection.
    connection_id: int | None = None
    depth: int = Field(1, ge=1, le=relationships.MAX_DEPTH)
    as_of: date | None = None
    layer: list[relationships.Layer] = Field(
        default_factory=lambda: list(relationships.DEFAULT_LAYERS), max_length=5
    )
    origin: list[relationships.Origin] = Field(
        default_factory=lambda: list(relationships.ORIGINS), max_length=3
    )


def _day(as_of: date | None) -> date:
    return as_of or datetime.now(UTC).date()


def _through(conn: Connection, connection_id: int | None = None) -> date | None:
    # Edges come from Steampipe (our rules) and CloudFox.
    return ingest.data_through(conn, connection_id=connection_id, tools=["steampipe", "cloudfox"])


def with_findings(conn: Connection, nodes: list[dict[str, Any]]) -> list[MapNode]:
    """Nodes with their open findings per tool, in one query for all of them."""
    counts = findings.open_finding_counts_by_tool(
        conn, [n["resource_id"] for n in nodes if n["resource_id"] is not None]
    )
    return [
        MapNode.model_validate(
            {
                **n,
                "findings": {
                    tool: {"open": count, "worst": worst}
                    for tool, (count, worst) in counts.get(n["resource_id"], {}).items()
                    if tool in TOOLS
                },
            }
        )
        for n in nodes
    ]


def _connection(conn: Connection, connection_id: int | None, focus: str) -> relationships.MapScope:
    """The connection to walk and its account: the one asked for, else the focus's owner."""
    if connection_id is None:
        owner = inventory.resource_nodes(conn, [focus]).get(focus, {}).get("connection_id")
        if owner is None:
            raise ValueError("connection_id is required when the focus is not in the inventory")
        connection_id = int(owner)
    found = connections.get(conn, connection_id)
    if found is None:
        raise LookupError(connection_id)
    return relationships.MapScope(found.id, found.account_id)


@router.get("/map/graph")
def graph(conn: Db, _user: Viewer, query: Annotated[MapQuery, Query()]) -> MapGraph:
    day = _day(query.as_of)
    scope = _connection(conn, query.connection_id, query.focus)
    found = relationships.neighbourhood(
        conn,
        focus=query.focus,
        scope=scope,
        depth=query.depth,
        day=day,
        layers=tuple(query.layer),
        origins=tuple(query.origin),
    )
    focus = found["nodes"][0]
    if focus["kind"] == "resource" and focus["resource_id"] is None and not found["edges"]:
        raise LookupError(query.focus)  # neither in the inventory nor on any edge that day
    return MapGraph(
        focus=query.focus,
        connection_id=scope.connection_id,
        as_of=day,
        nodes=with_findings(conn, found["nodes"]),
        edges=[MapEdge.model_validate(e) for e in found["edges"]],
        groups=[MapGroup.model_validate(g) for g in found["groups"]],
        truncated=found["truncated"],
        data_through=_through(conn, scope.connection_id),
    )


class GroupQuery(BaseModel):
    """A group: its anchor node, the edges' direction and type, the members' resource type
    (absent for members not in the inventory)."""

    anchor: Uid
    connection_id: int
    direction: Literal["out", "in"]
    edge_type: Annotated[str, Field(pattern=r"^[A-Z][A-Z_]{0,63}$")]
    resource_type: Annotated[str | None, Field(max_length=128)] = None
    as_of: date | None = None
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0)


@router.get("/map/group")
def group(conn: Db, _user: Viewer, query: Annotated[GroupQuery, Query()]) -> GroupPage:
    """A group's members, by name, each with the edge that links it to the anchor."""
    scope = _connection(conn, query.connection_id, query.anchor)
    rows, total = relationships.group_members(
        conn,
        anchor=query.anchor,
        scope=scope,
        direction=query.direction,
        edge_type=query.edge_type,
        resource_type=query.resource_type or None,
        day=_day(query.as_of),
        limit=query.limit,
        offset=query.offset,
    )
    nodes = with_findings(conn, [r["node"] for r in rows])
    return GroupPage(
        items=[
            GroupMember(node=node, edge=MapEdge.model_validate(r["edge"]))
            for node, r in zip(nodes, rows, strict=True)
        ],
        total=total,
        data_through=_through(conn, scope.connection_id),
    )
