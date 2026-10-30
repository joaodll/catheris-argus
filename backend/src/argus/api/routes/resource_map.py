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
Region = Annotated[str, Field(min_length=1, max_length=64)]
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


class DoorOpen(BaseModel):
    ipv4: list[str]
    ipv6: list[str]


class DoorSubnet(BaseModel):
    subnet: str
    family: str
    # igw, the default route's target (nat-…, tgw-…, vpce-…), none, or unknown (no route table).
    route: str
    # allows, blocks, unknown (no ACL collected); null when nothing is open to test.
    acl: str | None


class DoorInterface(BaseModel):
    # The network interface; null for a load balancer, a database or an instance listing none.
    interface: str | None
    # The address families it has a public address of.
    public: list[str]
    # What its security groups open to the whole internet, per family, ICMP included.
    open: DoorOpen
    subnets: list[DoorSubnet]


class FrontDoor(BaseModel):
    node: MapNode
    # What found it: "rule" (Argus's internet rules), "cloudfox".
    via: list[str]
    # open: traffic can arrive; unknown: data the verdict needs is missing; restricted: public
    # settings, but security groups, routing, a network ACL, auth or an address list keep the
    # internet out; cloudfox_only: only CloudFox calls it public (ADR-0035).
    reach: relationships.Reach
    # Restricted only: why (sg_no_public_source, no_internet_route, nacl_blocks, cidr_allowlist,
    # iam_auth, no_public_address) and the sources its rules admit (address lists, security
    # groups, prefix lists).
    reason: str | None
    sources: list[str]
    # Restricted, in a VPC: what its groups open to the whole internet on any port, the ports it
    # serves (null: any port counts) and, with no route, where each subnet's default route goes
    # ("nat-0a1b", "none"). ADR-0035, fourth amendment.
    open_ports: list[str] = []
    listens: list[str] | None = None
    default_routes: list[str] = []
    # Unknown only: what is missing, as "<kind>:<id>" (security_group:sg-1, route_table:subnet-1,
    # network_acl:subnet-1) or "subnet".
    missing: list[str]
    # Open only: the ports open to the internet ("tcp/443", "all") and, for a resource in a VPC,
    # the address families that get in (ipv4, ipv6). Empty when the rule names none.
    open: list[str]
    families: list[str]
    # A door in a VPC, whatever its reach: the evidence it is judged from, per interface
    # (ADR-0035, fifth amendment), and an instance's state (running, stopped, ...).
    network: list[DoorInterface] = []
    state: str | None = None
    # A resource public by its own policy (ADR-0037, second amendment): the actions its
    # statements for anyone allow ("s3:getobject"). Empty for every other door.
    policy_actions: list[str] = []
    # Prowler's open exposure findings on this resource (ADR-0035, sixth amendment): the
    # Findings list with tool prowler and every reach, on this resource.
    prowler_exposure: int = 0
    # The flow drawn from this door that day (ADR-0036): its id, resources drawn and whether a
    # cap cut it. Null for a door no flow starts from (CloudFox's alone).
    flow_id: int | None
    resources: int | None
    truncated: bool


class FrontDoorPage(BaseModel):
    items: list[FrontDoor]
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


class FrontDoorQuery(BaseModel):
    connection_id: int
    as_of: date | None = None
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0)
    # Absent: every reach. Absent region: every region.
    reach: list[relationships.Reach] = Field(default_factory=list, max_length=4)
    region: list[Region] = Field(default_factory=list, max_length=50)
    # Matches the door's name, uid or type anywhere, in any case ("S3").
    q: str | None = Field(None, max_length=200)


@router.get("/map/front-doors")
def front_doors(
    conn: Db, _user: Viewer, query: Annotated[FrontDoorQuery, Query()]
) -> FrontDoorPage:
    """What faces the internet in one account: where the map starts. Open doors first, then
    unknown, restricted and CloudFox's alone, each by name (ADR-0035); `reach`, `region` and
    `q` narrow it.
    Each door names the flow that starts from it (ADR-0036)."""
    connection_id = query.connection_id
    rows, total = relationships.front_doors(
        conn,
        connection_id=connection_id,
        day=_day(query.as_of),
        limit=query.limit,
        offset=query.offset,
        reach=tuple(query.reach or relationships.REACHES),
        regions=tuple(query.region),
        q=query.q.strip() if query.q else None,
    )
    nodes = with_findings(conn, [r["node"] for r in rows])
    exposure = findings.open_exposure_counts(
        conn, [n.resource_id for n in nodes if n.resource_id is not None]
    )
    return FrontDoorPage(
        items=[
            FrontDoor(
                node=node,
                prowler_exposure=exposure.get(node.resource_id, 0) if node.resource_id else 0,
                **{k: v for k, v in r.items() if k != "node"},
            )
            for node, r in zip(nodes, rows, strict=True)
        ],
        total=total,
        data_through=_through(conn, connection_id),
    )


# ---- Flow mode (ADR-0036): the whole chain from one internet entry, computed in ingest.
FlowReach = Literal["open", "restricted", "unknown"]


class FlowStep(BaseModel):
    # The column the target is drawn in, left to right from the internet (0).
    col: int
    # edge: one edge; dns: a Route53 record naming the entry (no edge of its own); uses: a
    # compute resource reaching data through its role (via_uid); group: more targets of one
    # type than the flow draws one by one (group_type, group_count; no target).
    kind: Literal["edge", "dns", "uses", "group"]
    source_uid: str
    target_uid: str | None
    via_uid: str | None
    edge_ids: list[int]
    group_type: str | None
    group_count: int | None


class FlowChip(BaseModel):
    """What a node carries without being a step of the flow."""

    node_uid: str
    kind: Literal["security_group", "role", "waf"]
    chip_uid: str
    name: str | None
    edge_id: int


class FlowDetail(BaseModel):
    id: int
    connection_id: int
    entry_uid: str
    reach: FlowReach
    truncated: bool
    as_of: date
    nodes: list[MapNode]
    steps: list[FlowStep]
    chips: list[FlowChip]
    edges: list[MapEdge]
    data_through: date | None


@router.get("/map/flows/{flow_id}")
def flow(flow_id: int, conn: Db, _user: Viewer, as_of: date | None = None) -> FlowDetail:
    """One flow as it stood on a day: its steps left to right, each node's chips and findings."""
    day = _day(as_of)
    found = relationships.flow_detail(conn, flow_id=flow_id, day=day)
    if found is None:
        raise LookupError(flow_id)
    uids: list[str] = ["internet"]
    for step in found["steps"]:
        for uid in (step["source_uid"], step["target_uid"]):
            if uid and uid not in uids:
                uids.append(uid)
    names = {
        n["uid"]: n["name"]
        for n in relationships.node_views(conn, sorted({c["chip_uid"] for c in found["chips"]}))
    }
    edges = relationships.edges_by_ids(
        conn, sorted({i for step in found["steps"] for i in step["edge_ids"]})
    )
    return FlowDetail(
        id=found["id"],
        connection_id=found["connection_id"],
        entry_uid=found["entry_uid"],
        reach=found["reach"],
        truncated=found["truncated"],
        as_of=day,
        nodes=with_findings(conn, relationships.node_views(conn, uids)),
        steps=[FlowStep.model_validate(s) for s in found["steps"]],
        chips=[
            FlowChip.model_validate({**c, "name": names.get(c["chip_uid"])}) for c in found["chips"]
        ],
        edges=[MapEdge.model_validate(e) for e in edges.values()],
        data_through=_through(conn, found["connection_id"]),
    )
