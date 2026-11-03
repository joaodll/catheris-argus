"""Investigate -> Resource map (ADR-0033): one neighbourhood at a time, never the estate.
Named reads only: a client chooses a connection, a focus, a depth, layers and origins, never a
query. Every read is for one connection (ADR-0033, amended 2026-10-09), in its latest state in
the graph read model (ADR-0044, M3b): the map has no past days."""

from datetime import date
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from argus import connections, findings, graph, inventory, relationships
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


class MapGraphState(BaseModel):
    """How current the map is for its connection (ADR-0044, M-3)."""

    # The days its state in the graph was projected from; null when that family has none, or
    # while its sync has failed.
    resource_day: date | None
    rule_day: date | None
    cloudfox_day: date | None
    # A newer scan is ingested and not yet in the graph.
    behind: bool
    # Its sync failed, or it has been behind for 10 minutes: it waits for the next update.
    failed: bool


class MapGraph(BaseModel):
    focus: str
    connection_id: int
    graph: MapGraphState
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
    layer: list[relationships.Layer] = Field(
        default_factory=lambda: list(relationships.DEFAULT_LAYERS), max_length=5
    )
    origin: list[relationships.Origin] = Field(
        default_factory=lambda: list(relationships.ORIGINS), max_length=3
    )


def _through(state: dict[str, Any]) -> date | None:
    """The newest day the connection's state in the graph was projected from."""
    days = [state[k] for k in ("resource_day", "rule_day", "cloudfox_day") if state[k] is not None]
    return max(days) if days else None


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
def map_graph(conn: Db, _user: Viewer, query: Annotated[MapQuery, Query()]) -> MapGraph:
    scope = _connection(conn, query.connection_id, query.focus)
    found = graph.neighbourhood(
        conn,
        focus=query.focus,
        scope=scope,
        depth=query.depth,
        layers=tuple(query.layer),
        origins=tuple(query.origin),
    )
    focus = found["nodes"][0]
    if focus["kind"] == "resource" and focus["resource_id"] is None and not found["edges"]:
        raise LookupError(query.focus)  # neither in the inventory nor on any edge of the graph
    state = graph.map_state(conn, connection_id=scope.connection_id)
    return MapGraph(
        focus=query.focus,
        connection_id=scope.connection_id,
        graph=MapGraphState.model_validate(state),
        nodes=with_findings(conn, found["nodes"]),
        edges=[MapEdge.model_validate(e) for e in found["edges"]],
        groups=[MapGroup.model_validate(g) for g in found["groups"]],
        truncated=found["truncated"],
        data_through=_through(state),
    )


class GroupQuery(BaseModel):
    """A group: its anchor node, the edges' direction and type, the members' resource type
    (absent for members not in the inventory)."""

    anchor: Uid
    connection_id: int
    direction: Literal["out", "in"]
    edge_type: Annotated[str, Field(pattern=r"^[A-Z][A-Z_]{0,63}$")]
    resource_type: Annotated[str | None, Field(max_length=128)] = None
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0)


@router.get("/map/group")
def group(conn: Db, _user: Viewer, query: Annotated[GroupQuery, Query()]) -> GroupPage:
    """A group's members, by name, each with the edge that links it to the anchor."""
    scope = _connection(conn, query.connection_id, query.anchor)
    rows, total = graph.group_members(
        conn,
        anchor=query.anchor,
        scope=scope,
        direction=query.direction,
        edge_type=query.edge_type,
        resource_type=query.resource_type or None,
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
        data_through=_through(graph.map_state(conn, connection_id=scope.connection_id)),
    )
