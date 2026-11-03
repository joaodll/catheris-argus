"""The Resource map's reads over the graph read model (ADR-0033; ADR-0044, M3b): one neighbourhood
at a time, never the estate.

    neighbourhood()   a focus and its neighbours, hop by hop (at most 3), at most 500 nodes; more
                      than 25 neighbours of one (direction, edge type, resource type) come back
                      as one group instead
    group_members()   a group's members, a page at a time
    map_state()       how current the graph is for a connection (M-3)

Memgraph holds each connection's latest state, so the map has no past days (D1). It supplies the
topology, one named read per hop, each within MAP_TIMEOUT_S. Postgres supplies what a person reads
about it, in a batch: names and places, and each edge's details.

Every read is for one connection (ADR-0033, amended 2026-10-09): the edges that connection's runs
derived. A resource owned by another connection, or an ARN of another account, is a boundary node:
drawn, never expanded. Layers and origins are names a client chooses, never a query.

The map shows dependencies and connections, not reach (round M3a): an edge with no layer is not
drawn, and a map edge carries only its plain attributes.

While Memgraph is out of reach the map is out of reach (M-1, the owner's decision):
GraphUnavailable, which the API answers with 503 and Retry-After. There is no second implementation
to fall back on.
"""

import logging
from collections.abc import Iterator
from typing import Any

from neo4j.exceptions import (
    AuthError,
    ClientError,
    ServiceUnavailable,
    SessionExpired,
    TransientError,
)
from sqlalchemy import Connection, text

from argus import connections, ingest, inventory, relationships
from argus.graph import client
from argus.graph.paths import STALLED_AFTER
from argus.graph.projection import graph_uid, postgres_uid
from argus.relationships import (
    DEFAULT_LAYERS,
    GROUP_OVER,
    MAX_DEPTH,
    MAX_NODES,
    ORIGINS,
    Direction,
    MapScope,
    group_id,
    kind_of,
)

log = logging.getLogger(__name__)
MAP_TIMEOUT_S = 5.0
_STATE_SQL = f"""
  SELECT g.status, g.source_run_id, g.resource_day, g.rule_day, g.cloudfox_day, r.run_id,
         r.ingested_at < now() - CAST(:stalled AS interval) AS stalled
  FROM ({connections.DIRECTORY_SQL}) c
  LEFT JOIN ({ingest.LATEST_INGESTED_RUNS_SQL}) r ON r.connection_id = c.id
  LEFT JOIN graph_projection g ON g.connection_id = c.id
  WHERE c.id = :c
"""  # noqa: S608 - exported SQL only


class GraphUnavailable(RuntimeError):
    """Memgraph can't answer now: down, its pool full, or a read over its timeout."""


def _read(name: str, **params: Any) -> list[dict[str, Any]]:
    try:
        return client.read(name, within=MAP_TIMEOUT_S, **params)
    except (
        client.GraphNotConfigured,
        ServiceUnavailable,
        SessionExpired,
        TransientError,
        AuthError,
    ) as e:
        log.warning("graph unavailable", extra={"read": name, "error": type(e).__name__})
        raise GraphUnavailable from e
    except ClientError as e:
        if "failed to obtain a connection" not in str(e):
            raise  # a query of ours is wrong: a bug, not an outage
        log.warning("graph unavailable", extra={"read": name, "error": "pool exhausted"})
        raise GraphUnavailable from e


def _account_of(uid: str) -> str | None:
    """The account an ARN or an `admin:<account>` node names, if any (S3 and Route53 ARNs
    name none)."""
    if uid.startswith("admin:"):
        return uid.removeprefix("admin:")
    parts = uid.split(":", 5)
    if len(parts) == 6 and parts[0] == "arn" and len(parts[4]) == 12 and parts[4].isdigit():
        return parts[4]
    return None


class _Scope:
    """One connection's view: which nodes are its own and which are boundary nodes."""

    def __init__(self, conn: Connection, scope: MapScope) -> None:
        self.conn, self.connection_id, self.account_id = conn, *scope
        self.inventory: dict[str, dict[str, Any]] = {}

    def look_up(self, uids: list[str]) -> None:
        wanted = [u for u in uids if kind_of(u) == "resource" and u not in self.inventory]
        found = inventory.resource_nodes(self.conn, wanted)
        self.inventory.update({u: found.get(u, {}) for u in wanted})

    def boundary(self, uid: str) -> bool:
        owner = self.inventory.get(uid, {}).get("connection_id")
        if owner is not None:
            return bool(owner != self.connection_id)
        account = _account_of(uid)
        return account is not None and account != self.account_id

    def nodes(self, uids: list[str], expanded: set[str]) -> list[dict[str, Any]]:
        self.look_up(uids)
        return [
            _node(uid, self.inventory.get(uid, {}), uid in expanded, self.boundary(uid))
            for uid in uids
        ]


def _node(uid: str, info: dict[str, Any], expanded: bool, boundary: bool) -> dict[str, Any]:
    return {
        "uid": uid,
        "kind": kind_of(uid),
        "resource_id": info.get("id"),
        "type": info.get("type"),
        "name": info.get("name"),
        "region": info.get("region"),
        "connection_id": info.get("connection_id"),
        "deleted_on": info.get("deleted_on"),
        "expanded": expanded,
        "boundary": boundary,
    }


def _ordered(rows: list[list[Any]]) -> Iterator[tuple[Any, ...]]:
    """A hop's rows in a fixed order, which decides what a neighbourhood cut at MAX_NODES keeps: a
    large group as one row, else one row per edge (two when a rule and CloudFox both find it), by
    name, uid and edge id, in code-point order."""
    flat: list[tuple[Any, ...]] = []
    for anchor_uid, direction, edge_type, other_type, siblings, hits in rows:
        anchor = postgres_uid(anchor_uid)
        if siblings > GROUP_OVER:
            flat.append((anchor, direction, edge_type, other_type, None, None, siblings, None))
            continue
        for edge_id, other, name in hits:
            flat.append(
                (
                    anchor,
                    direction,
                    edge_type,
                    other_type,
                    name,
                    postgres_uid(other),
                    siblings,
                    edge_id,
                )
            )
    flat.sort(
        key=lambda x: (
            x[0],
            x[1],
            x[2],
            x[3] is not None,
            x[3] or "",
            x[4] is None,
            x[4] or "",
            x[5] or "",
            x[7] or 0,
        )
    )
    return iter(flat)


def neighbourhood(
    conn: Connection,
    *,
    focus: str,
    scope: MapScope,
    depth: int,
    layers: tuple[str, ...] = DEFAULT_LAYERS,
    origins: tuple[str, ...] = ORIGINS,
) -> dict[str, Any]:
    """The focus and its neighbours up to `depth` hops, in one connection, as its latest state
    stands in the graph.

    Returns nodes (uid, kind, and the inventory's id, type, name, region, connection when it has
    the resource; `expanded` when its neighbours were read; `boundary` for another connection's
    or account's resource, which is never expanded), edges, groups and `truncated` (the 500-node
    cap stopped the walk)."""
    depth = max(1, min(depth, MAX_DEPTH))
    params = {
        "c": scope.connection_id,
        "layers": sorted(set(layers)),
        "rule": "rule" in origins,
        "cloudfox": "cloudfox" in origins,
        "g": GROUP_OVER,
    }
    walk = _Scope(conn, scope)
    order: dict[str, None] = {focus: None}  # insertion-ordered set of node uids
    edge_ids: dict[int, None] = {}
    groups: dict[str, dict[str, Any]] = {}
    expanded: set[str] = set()
    truncated = False
    frontier = [focus]
    for _ in range(depth):
        if not frontier or truncated:
            break
        hop = _read(
            "map_hop", frontier=[graph_uid(u, scope.account_id) for u in frontier], **params
        )[0]["hop"]
        expanded.update(frontier)
        found: list[str] = []
        for anchor, direction, edge_type, other_type, _name, other, siblings, edge_id in _ordered(
            hop
        ):
            if len(order) + len(groups) >= MAX_NODES:
                truncated = True
                break
            if siblings > GROUP_OVER:
                key = group_id(anchor, direction, edge_type, other_type)
                groups.setdefault(
                    key,
                    {
                        "id": key,
                        "anchor_uid": anchor,
                        "direction": direction,
                        "edge_type": edge_type,
                        "resource_type": other_type,
                        "count": int(siblings),
                    },
                )
                continue
            if other not in order:
                order[other] = None
                found.append(other)
            edge_ids[edge_id] = None
        walk.look_up(found)
        frontier = [uid for uid in found if not walk.boundary(uid)]
    edges = relationships.edges_by_ids(conn, list(edge_ids), plain=True)
    return {
        "nodes": walk.nodes(list(order), expanded),
        "edges": [edges[i] for i in edge_ids if i in edges],
        "groups": list(groups.values()),
        "truncated": truncated,
    }


def group_members(
    conn: Connection,
    *,
    anchor: str,
    scope: MapScope,
    direction: Direction,
    edge_type: str,
    resource_type: str | None,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], int]:
    """One page of a group's members (by name) in one connection, each with the edge that links
    it, and the group's size."""
    found = _read(
        f"map_group_page_{direction}",
        anchor=graph_uid(anchor, scope.account_id),
        type=edge_type,
        c=scope.connection_id,
        rt=resource_type or "",
        first=offset,
        last=offset + limit,
    )[0]
    page = [(postgres_uid(uid), int(edge_id)) for uid, edge_id in found["page"]]
    nodes = {n["uid"]: n for n in _Scope(conn, scope).nodes([uid for uid, _ in page], set())}
    edges = relationships.edges_by_ids(conn, [edge_id for _, edge_id in page], plain=True)
    return (
        [{"node": nodes[uid], "edge": edges[edge_id]} for uid, edge_id in page if edge_id in edges],
        int(found["total"]),
    )


def map_state(conn: Connection, *, connection_id: int) -> dict[str, Any]:
    """How current the graph is for a connection (M-3): the days its state was projected from;
    `behind` when it has a newer ingested run than the graph; `failed` when its sync failed or it
    has been behind for STALLED_AFTER. Postgres only."""
    row = conn.execute(text(_STATE_SQL), {"c": connection_id, "stalled": STALLED_AFTER}).first()
    if row is None or row.run_id is None:  # nothing ingested yet: nothing to be behind
        return {
            "resource_day": None,
            "rule_day": None,
            "cloudfox_day": None,
            "behind": False,
            "failed": False,
        }
    behind = row.source_run_id != row.run_id
    return {
        "resource_day": row.resource_day,
        "rule_day": row.rule_day,
        "cloudfox_day": row.cloudfox_day,
        "behind": behind,
        "failed": row.status == "failed" or bool(behind and row.stalled),
    }
