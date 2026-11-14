"""Investigate -> Resource Map and Security Map (ADR-0051): a neighbourhood, never the estate.
Named reads only: a client chooses a map, a connection, a focus, a depth (at most three hops),
layers and origins, never a query, and the screen grows its map by asking for a neighbour's own
neighbourhood (Expand). Every read is for one connection, in its latest scan, however old: the
maps have no past days. A node says what a resource is and where.

The Resource Map reads no security fact from any route (owner, 2026-11-13): its graph and
groups leave out relationships.SECURITY_EDGE_TYPES, and its start, search and panel read the
plain routes below (/map/types, /map/resources, /map/resource/{id}), whose models carry no
misconfiguration, vulnerability, reach, risk or loot field (tests/api/test_resource_map.py
checks the contract)."""

from datetime import UTC, date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from argus import connections, ingest, inventory, metrics, relationships
from argus.api.deps import Db, Viewer
from argus.api.routes.resources import EdgeOut, ResourceOut
from argus.core.db import SEARCH_COUNT_CAP

router = APIRouter(tags=["map"])

Uid = Annotated[str, Field(min_length=1, max_length=2048)]


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
    # Its neighbours were read: true for the focus (the map can still expand the others).
    expanded: bool
    # Owned by another connection, or an ARN of another account: drawn, never expanded.
    boundary: bool


class MapEdge(BaseModel):
    id: int
    source_uid: str
    target_uid: str
    type: str
    origin: str
    # Protocol and ports only (relationships.EDGE_ATTRIBUTES), never the rules' evidence.
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


class MapDays(BaseModel):
    """The scans the connection's lines come from. Null: that family has no load yet."""

    # Argus's relationship rules, derived from the Steampipe inventory.
    rule_day: date | None
    cloudfox_day: date | None


class MapGraph(BaseModel):
    focus: str
    connection_id: int
    nodes: list[MapNode]
    edges: list[MapEdge]
    groups: list[MapGroup]
    # The 500-node cap cut the hop short: fewer layers show the rest.
    truncated: bool
    days: MapDays
    # The newer of the two days.
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
    # Which map: the Resource Map draws no security line (relationships.SECURITY_EDGE_TYPES).
    map: relationships.Map = "resource"
    depth: int = Field(1, ge=1, le=relationships.MAX_DEPTH)
    # The connection whose edges are walked. Absent: the focus resource's own connection.
    connection_id: int | None = Field(None, ge=1)
    layer: list[relationships.Layer] = Field(
        default_factory=lambda: list(relationships.DEFAULT_LAYERS), max_length=5
    )
    origin: list[relationships.Origin] = Field(
        default_factory=lambda: list(relationships.ORIGINS), max_length=3
    )


def _today() -> date:
    return datetime.now(UTC).date()


def _days(conn: Connection, connection_id: int, day: date) -> MapDays:
    """Each edge family's load that stands for the day, from edge_load."""
    return MapDays.model_validate(
        relationships.effective_days(conn, connection_id=connection_id, day=day)
    )


def _through(days: MapDays) -> date | None:
    found = [d for d in (days.rule_day, days.cloudfox_day) if d is not None]
    return max(found) if found else None


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
    day = _today()
    scope = _connection(conn, query.connection_id, query.focus)
    found = relationships.neighbourhood(
        conn,
        focus=query.focus,
        scope=scope,
        day=day,
        depth=query.depth,
        layers=tuple(query.layer),
        origins=tuple(query.origin),
        kind=query.map,
    )
    focus = found["nodes"][0]
    if focus["kind"] == "resource" and focus["resource_id"] is None and not found["edges"]:
        raise LookupError(query.focus)  # neither in the inventory nor on any edge
    days = _days(conn, scope.connection_id, day)
    return MapGraph(
        focus=query.focus,
        connection_id=scope.connection_id,
        nodes=[MapNode.model_validate(n) for n in found["nodes"]],
        edges=[MapEdge.model_validate(e) for e in found["edges"]],
        groups=[MapGroup.model_validate(g) for g in found["groups"]],
        truncated=found["truncated"],
        days=days,
        data_through=_through(days),
    )


class GroupQuery(BaseModel):
    """A group: its anchor node, the edges' direction and type, the members' resource type
    (absent for members not in the inventory)."""

    anchor: Uid
    connection_id: int = Field(ge=1)
    map: relationships.Map = "resource"
    direction: Literal["out", "in"]
    edge_type: Annotated[str, Field(pattern=r"^[A-Z][A-Z_]{0,63}$")]
    resource_type: Annotated[str | None, Field(max_length=128)] = None
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0, le=100_000)


@router.get("/map/group")
def map_group(conn: Db, _user: Viewer, query: Annotated[GroupQuery, Query()]) -> GroupPage:
    """A group's members, by name, each with the edge that links it to the anchor."""
    day = _today()
    scope = _connection(conn, query.connection_id, query.anchor)
    through = _through(_days(conn, scope.connection_id, day))
    if not relationships.on_map(query.edge_type, query.map):  # a line this map never draws
        return GroupPage(items=[], total=0, data_through=through)
    rows, total = relationships.group_members(
        conn,
        anchor=query.anchor,
        scope=scope,
        direction=query.direction,
        edge_type=query.edge_type,
        resource_type=query.resource_type or None,
        day=day,
        limit=query.limit,
        offset=query.offset,
    )
    return GroupPage(
        items=[
            GroupMember(
                node=MapNode.model_validate(r["node"]), edge=MapEdge.model_validate(r["edge"])
            )
            for r in rows
        ],
        total=total,
        data_through=through,
    )


# ---- the Resource Map's plain reads: what a resource is, never what is wrong with it ---------


class MapTypeCount(BaseModel):
    type: str
    count: int


class MapTypesOut(BaseModel):
    """The start's "What's here": the inventory's assets by type, largest first, as the
    Resources summary counts them; null before any Steampipe load."""

    by_type: list[MapTypeCount] | None
    data_through: date | None


@router.get("/map/types")
def map_types(
    conn: Db, _user: Viewer, connection_id: Annotated[int, Query(ge=0)] = 0
) -> MapTypesOut:
    """All connections (0) or one: stored counts written by ingest."""
    by_type = metrics.asset_types(conn, connection_id=connection_id, today=_today())
    return MapTypesOut.model_validate(
        {
            "by_type": by_type,
            "data_through": ingest.data_through(
                conn, connection_id=connection_id or None, tools=["steampipe"]
            )
            if by_type is not None
            else None,
        }
    )


class MapResourceQuery(BaseModel):
    """A type's resources (the start's list) or a search (the start's and the map's box)."""

    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0, le=100_000)
    connection_id: list[int] = Field(default_factory=list, max_length=50)
    type: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(
        default_factory=list, max_length=50
    )
    q: Annotated[str, Field(max_length=200)] | None = None


class MapResourcePage(BaseModel):
    items: list[ResourceOut]
    total: int
    total_capped: bool  # a search matched more than `total` (the count stops at 10,000)
    data_through: date | None


@router.get("/map/resources")
def map_resources(
    conn: Db, _user: Viewer, query: Annotated[MapResourceQuery, Query()]
) -> MapResourcePage:
    q = query.q or None
    rows, total = inventory.list_resources(
        conn,
        limit=query.limit,
        offset=query.offset,
        filters=inventory.ResourceFilters(
            connection_ids=tuple(query.connection_id), resource_types=tuple(query.type), q=q
        ),
    )
    capped = bool(q) and total > SEARCH_COUNT_CAP
    return MapResourcePage(
        items=[ResourceOut.model_validate(r) for r in rows],
        total=SEARCH_COUNT_CAP if capped else total,
        total_capped=capped,
        data_through=ingest.data_through(
            conn, connection_ids=query.connection_id, tools=["steampipe"]
        ),
    )


class MapResource(ResourceOut):
    """The Resource Map's panel: what Steampipe describes, the lines the map draws, tags and
    configuration (redacted at ingest)."""

    tags: dict[str, Any]
    as_of: date
    seen_on: date | None
    config: dict[str, Any] | None
    # The resource's own lines on the Resource Map, plain attributes only.
    edges: list[EdgeOut]
    # The newest Steampipe run ingested for its connection; null: never scanned.
    data_through: date | None


@router.get("/map/resource/{resource_id}")
def map_resource(resource_id: int, conn: Db, _user: Viewer) -> MapResource:
    day = _today()
    found = inventory.resource_at(conn, resource_id=resource_id, day=day)
    if found is None:
        raise LookupError(resource_id)
    edges = relationships.map_edges_at(
        conn,
        resource_id=resource_id,
        connection_id=found["connection_id"],
        day=day,
        kind="resource",
    )
    ends = {e[k] for e in edges for k in ("source_resource_id", "target_resource_id") if e[k]}
    names = inventory.resource_names(conn, sorted(ends))
    return MapResource.model_validate(
        {
            **found,
            "edges": [
                {
                    **e,
                    "source_name": names.get(e["source_resource_id"]),
                    "target_name": names.get(e["target_resource_id"]),
                }
                for e in edges
            ],
            "data_through": ingest.data_through(
                conn, connection_id=found["connection_id"], tools=["steampipe"]
            ),
        }
    )
