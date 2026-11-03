"""What the Resource map's reads share (ADR-0033): its limits, its layers, and an edge as the API
returns it. The reads themselves are over the graph read model (argus.graph, ADR-0044 M3b).

    layer_of()        which layer an edge is drawn in: the one declaration, projected onto every
                      edge in the graph
    kind_of()         what kind of node a uid is: a resource, or the pseudo-nodes `internet`,
                      `admin:<account>`, `external:<host>` and `any:<service>` (a wildcard grant,
                      role-accesses)
    group_id()        the id of a group of neighbours
    edges_by_ids()    edges by id (an attack path's steps, or a map's)
    plain_attributes()  what a map edge shows of its attributes

The map shows dependencies and connections, not reach (the owner's decision, 2026-11-01, round
M3a): a door the internet rules judge closed or undecided has no layer, and a map edge carries only
its plain attributes (EDGE_ATTRIBUTES), never the rules' evidence. Attack paths, Findings and the
Resources sheet explain reach.
"""

import re
from typing import Any, Literal, NamedTuple

from sqlalchemy import Connection, text

from argus.relationships.queries import MAX_EDGES

Layer = Literal["traffic", "identity", "network", "policy", "data"]
Origin = Literal["rule", "cloudfox", "manual"]
Direction = Literal["out", "in"]

MAX_DEPTH = 3
MAX_NODES = MAX_EDGES  # design: the neighbourhood stops at 500 nodes
GROUP_OVER = 25  # more neighbours of one kind than this: one group node (a constant, ADR-0033)
DEFAULT_LAYERS: tuple[Layer, ...] = ("traffic", "identity")
ORIGINS: tuple[Origin, ...] = ("rule", "cloudfox", "manual")
# What a map edge shows of its attributes, and all the graph read model keeps of them
# (graph/projection.py): the protocol and ports. The internet rules' evidence (network, routes,
# reasons) stays on the edge row for Attack paths and the Resources sheet.
EDGE_ATTRIBUTES: tuple[str, ...] = ("protocol", "from_port", "to_port", "port")

# Which layer each edge type is in: the one declaration, projected onto every edge in the graph
# read model (ADR-0044, M3b). Connections only (round M3a): the internet rules' closed and undecided
# doors (PUBLIC_RESTRICTED, PUBLIC_UNVERIFIED) are verdicts, not connections, and have no layer.
LAYER_TYPES: dict[str, tuple[str, ...]] = {
    "traffic": ("ROUTES_TO", "TRIGGERS", "INTERNET_REACHABLE"),
    "identity": (
        "RUNS_AS",
        "CAN_ASSUME",
        "IS_ADMIN",
        "CAN_PRIVESC_TO",
        "BELONGS_TO",
        "OUTSIDER",
        "HAS_CREDENTIAL",
        "CAN_ESCALATE_TO",
        "CAN_RUN_ON",
    ),
    "network": ("IN_NETWORK", "ALLOWS_INGRESS", "PROTECTED_BY", "CAN_CONNECT_TO"),
    "policy": ("HAS_POLICY",),
    # What a role's policies let it use (ADR-0036).
    "data": ("ACCESSES",),
}
_LAYER_OF = {edge_type: layer for layer, types in LAYER_TYPES.items() for edge_type in types}
# An IAM group's ARN: MEMBER_OF to a group is identity, to a security group is network.
_IAM_GROUP_ARN = re.compile(r":iam::[0-9]{12}:group/")


def layer_of(edge_type: str, target_uid: str) -> str | None:
    """The map layer an edge is drawn in; None: the map never draws it."""
    if edge_type == "MEMBER_OF":
        return "identity" if _IAM_GROUP_ARN.search(target_uid) else "network"
    return _LAYER_OF.get(edge_type)


_EDGE_COLUMNS = (
    "e.id, e.source_uid, e.target_uid, e.type, e.origin, e.attributes, e.first_seen, e.last_seen"
)


def kind_of(uid: str) -> str:
    if uid == "internet":
        return "internet"
    if uid.startswith("admin:"):
        return "admin"
    if uid.startswith("external:"):
        return "external"
    if uid.startswith("any:"):
        return "any"  # a wildcard grant: every resource of a service (role-accesses)
    return "resource"


def group_id(anchor: str, direction: str, edge_type: str, resource_type: str | None) -> str:
    return "|".join((anchor, direction, edge_type, resource_type or ""))


class MapScope(NamedTuple):
    """The connection a map read walks, and its account (for boundary nodes)."""

    connection_id: int
    account_id: str


def plain_attributes(attributes: dict[str, Any] | None) -> dict[str, Any]:
    """An edge's plain attributes (EDGE_ATTRIBUTES), scalars only."""
    return {
        k: v
        for k, v in (attributes or {}).items()
        if k in EDGE_ATTRIBUTES and isinstance(v, str | int | float | bool)
    }


def _edge(r: Any, *, plain: bool = True) -> dict[str, Any]:
    """An edge as the API returns it: on the map with its plain attributes only; an attack
    path's steps (edges_by_ids) keep every attribute, the evidence their words explain."""
    return {
        "id": r.id,
        "source_uid": r.source_uid,
        "target_uid": r.target_uid,
        "type": r.type,
        "origin": r.origin,
        "attributes": plain_attributes(r.attributes) if plain else (r.attributes or {}),
        "first_seen": r.first_seen,
        "last_seen": r.last_seen,
    }


def edges_by_ids(
    conn: Connection, edge_ids: list[int], *, plain: bool = False
) -> dict[int, dict[str, Any]]:
    """Edges by id, whatever day they stood: an attack path's steps with every attribute, the
    evidence their words explain; `plain`, a map edge's attributes only (EDGE_ATTRIBUTES)."""
    if not edge_ids:
        return {}
    rows = conn.execute(
        text(f"SELECT {_EDGE_COLUMNS} FROM edge e WHERE e.id = ANY(CAST(:ids AS bigint[]))"),  # noqa: S608
        {"ids": edge_ids},
    )
    return {r.id: _edge(r, plain=plain) for r in rows}
