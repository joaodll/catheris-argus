"""The Resource map's reads (ADR-0033): one neighbourhood at a time, never the estate.

    neighbourhood()   a focus and its neighbours, hop by hop (at most 3), at most 500 nodes;
                      more than 25 neighbours of one (direction, edge type, resource type)
                      come back as one group instead
    group_members()   a group's members, a page at a time
    front_doors()     what faces the internet in one account: the targets of edges from
                      `internet` (internet-entry, internet-restricted, CloudFox's
                      INTERNET_REACHABLE), with their reach (ADR-0035) and their flow
                      (ADR-0036): the Resource map's one start list
    edges_by_ids()    edges by id (an attack path's steps)

Every read is for one connection and one day (ADR-0033, amended 2026-10-09): the edges that
connection's runs derived, in each edge family's snapshot that stands for the day (edge_load),
plus manual edges that touch one of its resources. A resource owned by another connection, or
an ARN of another account, is a boundary node: drawn, never expanded. Layers and origins pick
edges from fixed SQL fragments; a client only names them. Nodes are uids: resources (placed
with inventory's exported node view) and the pseudo-nodes `internet`, `admin:<account>`,
`external:<host>` and `any:<service>` (a wildcard grant, role-accesses).
"""

from datetime import date
from typing import Any, Literal, NamedTuple

from sqlalchemy import Connection, text

from argus.core.db import like_contains
from argus.inventory import RESOURCE_NODES_SQL, resource_nodes
from argus.relationships.queries import MAX_EDGES, all_effective_days

Layer = Literal["traffic", "identity", "network", "policy", "data"]
Origin = Literal["rule", "cloudfox", "manual"]
Direction = Literal["out", "in"]

MAX_DEPTH = 3
MAX_NODES = MAX_EDGES  # design: the neighbourhood stops at 500 nodes
GROUP_OVER = 25  # more neighbours of one kind than this: one group node (a constant, ADR-0033)
DEFAULT_LAYERS: tuple[Layer, ...] = ("traffic", "identity")
ORIGINS: tuple[Origin, ...] = ("rule", "cloudfox", "manual")

# An IAM group's ARN: MEMBER_OF to a group is identity, to a security group is network.
_IAM_GROUP = "e.target_uid ~ '[:]iam[:][:][0-9]{12}[:]group/'"
LAYER_SQL: dict[str, str] = {
    # A door's link from the internet, whatever its reach (ADR-0033, amended 2026-10-21): a
    # Restricted or Unknown door shows it too, drawn dashed.
    "traffic": (
        "e.type IN ('ROUTES_TO', 'TRIGGERS', 'INTERNET_REACHABLE', 'PUBLIC_RESTRICTED', "
        "'PUBLIC_UNVERIFIED')"
    ),
    "identity": (
        "e.type IN ('RUNS_AS', 'CAN_ASSUME', 'IS_ADMIN', 'CAN_PRIVESC_TO', 'BELONGS_TO', "
        "'OUTSIDER', 'HAS_CREDENTIAL', 'CAN_ESCALATE_TO', 'CAN_RUN_ON') "
        f"OR (e.type = 'MEMBER_OF' AND {_IAM_GROUP})"
    ),
    "network": (
        "e.type IN ('IN_NETWORK', 'ALLOWS_INGRESS', 'PROTECTED_BY', 'CAN_CONNECT_TO') "
        f"OR (e.type = 'MEMBER_OF' AND NOT {_IAM_GROUP})"
    ),
    "policy": "e.type = 'HAS_POLICY'",
    # What a role's policies let it use (ADR-0036).
    "data": "e.type = 'ACCESSES'",
}
ORIGIN_SQL: dict[str, str] = {
    "rule": "starts_with(e.origin, 'rule:')",
    "cloudfox": "e.origin = 'cloudfox'",
    "manual": "e.origin = 'manual'",
}
_DAYS = (
    "days AS (SELECT * FROM unnest(CAST(:dc AS bigint[]), CAST(:drd AS date[]), "
    "CAST(:dcd AS date[])) AS d(cid, rd, cd))"
)
# Derived by the chosen connection's runs, or a manual edge with an end in its inventory.
_IN_CONNECTION = f"""(e.connection_id = :c OR (e.origin = 'manual' AND EXISTS (
    SELECT 1 FROM ({RESOURCE_NODES_SQL}) o
    WHERE o.id IN (e.source_resource_id, e.target_resource_id) AND o.connection_id = :c)))"""  # noqa: S608 - fixed fragments
# Standing on the day: in its family's snapshot for its connection, or manual.
_ALIVE = """(e.origin = 'manual' OR EXISTS (
    SELECT 1 FROM edge_snapshot s WHERE s.edge_id = e.id
      AND s.snapshot_date = CASE WHEN e.origin = 'cloudfox' THEN d.cd ELSE d.rd END))"""
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


def _filters(layers: tuple[str, ...], origins: tuple[str, ...]) -> str:
    """The WHERE fragment for these layers and origins: fixed SQL only (unknown names raise)."""
    if not layers or not origins:
        return "false"
    by_layer = " OR ".join(f"({LAYER_SQL[name]})" for name in sorted(set(layers)))
    by_origin = " OR ".join(ORIGIN_SQL[name] for name in sorted(set(origins)))
    return f"({by_layer}) AND ({by_origin})"


def _day_params(
    conn: Connection, day: date, connection_ids: list[int] | None = None
) -> dict[str, Any]:
    days = all_effective_days(conn, day=day, connection_ids=connection_ids)
    ids = sorted(days)
    return {
        "dc": ids,
        "drd": [days[c]["rule_day"] for c in ids],
        "dcd": [days[c]["cloudfox_day"] for c in ids],
    }


# A neighbour's inventory row: by the id ingest resolved on the edge, else by uid (a resource
# ingested after the edge was last loaded, or a pseudo-node, which finds none). LATERAL, so a
# hub's thousands of neighbours are index probes, never a scan of the inventory.
_OTHER = f"""LATERAL (
      (SELECT r.type, r.name FROM ({RESOURCE_NODES_SQL}) r WHERE r.id = h.other_id)
      UNION ALL
      (SELECT r.type, r.name FROM ({RESOURCE_NODES_SQL}) r
       WHERE h.other_id IS NULL AND r.uid = h.other COLLATE "default")
      LIMIT 1
    ) n ON true"""  # noqa: S608 - fixed fragments


def _hop_sql(filters: str) -> str:
    # Two stages, so a hub costs one narrow pass: count the distinct neighbours per (anchor,
    # direction, edge type, neighbour type) over ids and uids only, then read whole edges and
    # names only for the kinds that are drawn one by one (at most GROUP_OVER each). An edge
    # found by a rule and by CloudFox is one neighbour.
    return f"""
    WITH {_DAYS},
    hop AS (
      SELECT e.id, e.source_uid AS anchor, e.target_uid AS other, 'out' AS direction, e.type,
             e.target_resource_id AS other_id
      FROM edge e LEFT JOIN days d ON d.cid = e.connection_id
      WHERE e.source_uid = ANY(CAST(:uids AS text[])) AND {filters} AND {_IN_CONNECTION}
        AND {_ALIVE}
      UNION ALL
      SELECT e.id, e.target_uid, e.source_uid, 'in', e.type, e.source_resource_id
      FROM edge e LEFT JOIN days d ON d.cid = e.connection_id
      WHERE e.target_uid = ANY(CAST(:uids AS text[])) AND {filters} AND {_IN_CONNECTION}
        AND {_ALIVE}
    ),
    typed AS MATERIALIZED (
      SELECT h.id, h.anchor, h.other, h.direction, h.type,
             n.type AS other_type, n.name AS other_name
      FROM hop h LEFT JOIN {_OTHER}
    ),
    sizes AS (
      SELECT anchor, direction, type, other_type, count(*) AS siblings
      FROM (SELECT anchor, direction, type, other_type, other COLLATE "C" FROM typed
            GROUP BY 1, 2, 3, 4, 5) x
      GROUP BY anchor, direction, type, other_type
    )
    SELECT t.anchor, t.direction, t.type, t.other_type, t.other_name, t.other, s.siblings,
           e.id, e.source_uid, e.target_uid, e.origin, e.attributes, e.first_seen, e.last_seen
    FROM sizes s
    JOIN typed t USING (anchor, direction, type)
    JOIN edge e ON e.id = t.id
    WHERE s.siblings <= :g AND t.other_type IS NOT DISTINCT FROM s.other_type
    UNION ALL
    SELECT anchor, direction, type, other_type, NULL, NULL, siblings,
           NULL, NULL, NULL, NULL, NULL, NULL, NULL
    FROM sizes WHERE siblings > :g
    ORDER BY anchor, direction, type, other_type NULLS FIRST, other_name NULLS LAST, other, id
    """  # noqa: S608 - fixed fragments; values are bound


def group_id(anchor: str, direction: str, edge_type: str, resource_type: str | None) -> str:
    return "|".join((anchor, direction, edge_type, resource_type or ""))


def _account_of(uid: str) -> str | None:
    """The account an ARN or an `admin:<account>` node names, if any (S3 and Route53 ARNs
    name none)."""
    if uid.startswith("admin:"):
        return uid.removeprefix("admin:")
    parts = uid.split(":", 5)
    if len(parts) == 6 and parts[0] == "arn" and len(parts[4]) == 12 and parts[4].isdigit():
        return parts[4]
    return None


class MapScope(NamedTuple):
    """The connection a map read walks, and its account (for boundary nodes)."""

    connection_id: int
    account_id: str


class _Scope:
    """One connection's view: which nodes are its own and which are boundary nodes."""

    def __init__(self, conn: Connection, scope: MapScope) -> None:
        self.conn, self.connection_id, self.account_id = conn, *scope
        self.inventory: dict[str, dict[str, Any]] = {}

    def look_up(self, uids: list[str]) -> None:
        wanted = [u for u in uids if kind_of(u) == "resource" and u not in self.inventory]
        found = resource_nodes(self.conn, wanted)
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


def neighbourhood(
    conn: Connection,
    *,
    focus: str,
    scope: MapScope,
    depth: int,
    day: date,
    layers: tuple[str, ...] = DEFAULT_LAYERS,
    origins: tuple[str, ...] = ORIGINS,
) -> dict[str, Any]:
    """The focus and its neighbours up to `depth` hops, in one connection, as they stood on
    `day`.

    Returns nodes (uid, kind, and the inventory's id, type, name, region, connection when it
    has the resource; `expanded` when its neighbours were read; `boundary` for another
    connection's or account's resource, which is never expanded), edges, groups and
    `truncated` (the 500-node cap stopped the walk)."""
    depth = max(1, min(depth, MAX_DEPTH))
    sql = text(_hop_sql(_filters(layers, origins)))
    params = {**_day_params(conn, day, [scope.connection_id]), "c": scope.connection_id}
    walk = _Scope(conn, scope)
    order: dict[str, None] = {focus: None}  # insertion-ordered set of node uids
    edges: dict[int, dict[str, Any]] = {}
    groups: dict[str, dict[str, Any]] = {}
    expanded: set[str] = set()
    truncated = False
    frontier = [focus]
    for _ in range(depth):
        if not frontier or truncated:
            break
        rows = conn.execute(sql, {**params, "uids": frontier, "g": GROUP_OVER})
        expanded.update(frontier)
        found: list[str] = []
        for r in rows:
            if len(order) + len(groups) >= MAX_NODES:
                truncated = True
                break
            if r.siblings > GROUP_OVER:
                key = group_id(r.anchor, r.direction, r.type, r.other_type)
                groups.setdefault(
                    key,
                    {
                        "id": key,
                        "anchor_uid": r.anchor,
                        "direction": r.direction,
                        "edge_type": r.type,
                        "resource_type": r.other_type,
                        "count": int(r.siblings),
                    },
                )
                continue
            if r.other not in order:
                order[r.other] = None
                found.append(r.other)
            edges[r.id] = _edge(r)
        walk.look_up(found)
        frontier = [uid for uid in found if not walk.boundary(uid)]
    nodes = walk.nodes(list(order), expanded)
    return {
        "nodes": nodes,
        "edges": list(edges.values()),
        "groups": list(groups.values()),
        "truncated": truncated,
    }


def _edge(r: Any) -> dict[str, Any]:
    return {
        "id": r.id,
        "source_uid": r.source_uid,
        "target_uid": r.target_uid,
        "type": r.type,
        "origin": r.origin,
        "attributes": r.attributes or {},
        "first_seen": r.first_seen,
        "last_seen": r.last_seen,
    }


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


def node_views(conn: Connection, uids: list[str]) -> list[dict[str, Any]]:
    """Map nodes for these uids, in their order: one connection's own front doors and flows,
    never boundary nodes."""
    found = resource_nodes(conn, [u for u in uids if kind_of(u) == "resource"])
    return [_node(uid, found.get(uid, {}), False, False) for uid in uids]


_MEMBERS = {
    "out": ("e.source_uid", "e.target_uid", "e.target_resource_id"),
    "in": ("e.target_uid", "e.source_uid", "e.source_resource_id"),
}


def group_members(
    conn: Connection,
    *,
    anchor: str,
    scope: MapScope,
    direction: Direction,
    edge_type: str,
    resource_type: str | None,
    day: date,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], int]:
    """One page of a group's members (by name) in one connection, each with the edge that
    links it, and the group's size."""
    side, other, other_id = _MEMBERS[direction]
    # Narrow first: the members' ids and names, sorted and cut to the page; whole edges only
    # for that page.
    rows = conn.execute(
        text(f"""
        WITH {_DAYS},
        h AS (
          SELECT {other} COLLATE "C" AS other, min(e.id) AS id, min({other_id}) AS other_id
          FROM edge e LEFT JOIN days d ON d.cid = e.connection_id
          WHERE {side} = :a AND e.type = :t AND {_IN_CONNECTION} AND {_ALIVE}
          GROUP BY 1
        ),
        m AS (
          SELECT h.id, h.other,
                 coalesce(n.name, h.other COLLATE "default") AS label
          FROM h LEFT JOIN {_OTHER}
          WHERE n.type IS NOT DISTINCT FROM CAST(:rt AS text)
        ),
        page AS (
          SELECT m.*, count(*) OVER () AS total FROM m
          ORDER BY lower(m.label), m.other
          LIMIT :l OFFSET :o
        )
        SELECT page.other, page.total, {_EDGE_COLUMNS}
        FROM page JOIN edge e ON e.id = page.id
        ORDER BY lower(page.label), page.other
    """),  # noqa: S608 - fixed fragments; values are bound
        {
            **_day_params(conn, day, [scope.connection_id]),
            "c": scope.connection_id,
            "a": anchor,
            "t": edge_type,
            "rt": resource_type,
            "l": limit,
            "o": offset,
        },
    ).all()
    total = int(rows[0].total) if rows else 0
    nodes = {n["uid"]: n for n in _Scope(conn, scope).nodes([r.other for r in rows], set())}
    return [{"node": nodes[r.other], "edge": _edge(r)} for r in rows], total


Reach = Literal["open", "unknown", "restricted", "cloudfox_only"]
# In the list's order: an unknown door could be open, so it comes before the restricted ones.
REACHES: tuple[Reach, ...] = ("open", "unknown", "restricted", "cloudfox_only")


def _cloudfox_ports(attributes: list[dict[str, Any]]) -> list[str]:
    """What CloudFox calls open on a door only it finds, as Argus labels ports ("tcp/80",
    "tcp/8000-8100"): endpoints give one port, network-ports a list ("80,443,8000-8100")."""
    labels = set()
    for a in attributes:
        protocol = (a.get("protocol") or "tcp").lower()
        ports = a.get("ports") or a.get("port") or ""
        labels |= {f"{protocol}/{p.strip()}" for p in str(ports).split(",") if p.strip()}

    def order(label: str) -> tuple[int, str]:
        first = label.split("/", 1)[1].split("-", 1)[0]
        return (int(first) if first.isdigit() else -1, label)

    return sorted(labels, key=order)


def front_doors(
    conn: Connection,
    *,
    connection_id: int,
    day: date,
    limit: int,
    offset: int,
    reach: tuple[str, ...] = REACHES,
    regions: tuple[str, ...] = (),
    q: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """One page of what faces the internet in one account, and how many there are: open doors
    first, then unknown, restricted and CloudFox's alone, each by name. Each has the origins
    that found it ("rule", "cloudfox") and its reach (ADR-0035): "open" when Argus's rules say
    traffic can arrive (with the ports and address families that get in), "unknown" when data
    the verdict needs is missing (`missing` names it), "restricted" when its settings are public
    but security groups, routing, a network ACL, auth or address lists keep the internet out
    (with the rule's `reason` and `sources`), "cloudfox_only" when only CloudFox calls it public
    (its endpoints or network-ports module; `open` then holds the ports CloudFox names). A door
    with a flow that day (ADR-0036) carries its id, size and cut; `regions`, when given, keeps the
    doors in those regions; `q` keeps those whose name, uid or type holds it, in any case, the
    type's underscores also read as spaces ("S3", "s3 bucket": aws_s3_bucket; 2026-10-15)."""
    rows = conn.execute(
        text(f"""
        WITH {_DAYS},
        fd AS (
          SELECT e.target_uid AS uid,
                 array_agg(DISTINCT CASE WHEN e.origin = 'cloudfox' THEN 'cloudfox'
                                         ELSE 'rule' END) AS via,
                 CASE WHEN bool_or(e.type = 'ROUTES_TO') THEN 'open'
                      WHEN bool_or(e.type = 'PUBLIC_RESTRICTED') THEN 'restricted'
                      WHEN bool_or(e.type = 'PUBLIC_UNVERIFIED') THEN 'unknown'
                      ELSE 'cloudfox_only' END AS reach,
                 -- The rule edge's attributes: why, what is open, what is missing.
                 (array_agg(e.attributes ORDER BY array_position(
                    ARRAY['ROUTES_TO', 'PUBLIC_RESTRICTED', 'PUBLIC_UNVERIFIED'], e.type), e.id)
                    FILTER (WHERE e.origin <> 'cloudfox'))[1] AS attrs,
                 -- CloudFox's own: its port and protocol per endpoint or address.
                 array_agg(e.attributes ORDER BY e.id) FILTER (WHERE e.origin = 'cloudfox')
                   AS cloudfox
          FROM edge e JOIN days d ON d.cid = e.connection_id
          WHERE e.source_uid = 'internet' AND e.connection_id = :c
            AND e.type IN ('ROUTES_TO', 'PUBLIC_RESTRICTED', 'PUBLIC_UNVERIFIED',
                           'INTERNET_REACHABLE') AND {_ALIVE}
          GROUP BY e.target_uid
        ),
        page AS (
          SELECT fd.*, count(*) OVER () AS total,
                 row_number() OVER (ORDER BY array_position(CAST(:order AS text[]), fd.reach),
                                             lower(coalesce(n.name, fd.uid)), fd.uid) AS ord
          FROM fd LEFT JOIN ({RESOURCE_NODES_SQL}) n ON n.uid = fd.uid
          WHERE fd.reach = ANY(CAST(:reach AS text[]))
            AND (cardinality(CAST(:regions AS text[])) = 0
                 OR n.region = ANY(CAST(:regions AS text[])))
            AND (CAST(:p AS text) IS NULL
                 OR concat_ws(E'\\n', n.name, fd.uid, n.type, replace(n.type, '_', ' '))
                    ILIKE :p ESCAPE '\\')
          ORDER BY ord
          LIMIT :l OFFSET :o
        )
        SELECT p.uid, p.via, p.reach, p.attrs, p.cloudfox, p.total,
               f.id AS flow_id, sh.node_count, sh.truncated
        FROM page p
        CROSS JOIN days d
        LEFT JOIN flow f
          ON f.flow_key = sha256(convert_to('flow|' || :c || '|' || p.uid, 'UTF8'))
        LEFT JOIN flow_snapshot s ON s.flow_id = f.id AND s.snapshot_date = d.rd
        LEFT JOIN flow_shape sh ON sh.id = s.shape_id
        WHERE d.cid = :c
        ORDER BY p.ord
    """),  # noqa: S608 - fixed fragments; values are bound
        {
            **_day_params(conn, day, [connection_id]),
            "c": connection_id,
            "order": list(REACHES),
            "reach": list(reach),
            "regions": list(regions),
            "p": like_contains(q) if q else None,
            "l": limit,
            "o": offset,
        },
    ).all()
    total = int(rows[0].total) if rows else 0
    nodes = {n["uid"]: n for n in node_views(conn, [r.uid for r in rows])}
    doors = []
    for r in rows:
        attrs = r.attrs or {}
        restricted = r.reach == "restricted"
        doors.append(
            {
                "node": nodes[r.uid],
                "via": sorted(r.via),
                "reach": r.reach,
                "reason": attrs.get("reason") if restricted else None,
                "sources": attrs.get("sources", []) if restricted else [],
                # The facts behind a restricted verdict (ADR-0035, fourth amendment).
                "open_ports": attrs.get("open_ports", []) if restricted else [],
                "listens": attrs.get("listens") if restricted else None,
                "default_routes": attrs.get("default_routes", []) if restricted else [],
                "missing": attrs.get("missing", []) if r.reach == "unknown" else [],
                "open": (
                    attrs.get("open", [])
                    if r.reach == "open"
                    else _cloudfox_ports(r.cloudfox or [])
                    if r.reach == "cloudfox_only"
                    else []
                ),
                "families": attrs.get("families", []) if r.reach == "open" else [],
                # The evidence of a door in a VPC, whatever its reach (ADR-0035, fifth
                # amendment): per interface, what is public and open, each subnet's route and
                # ACL; and an instance's state.
                "network": attrs.get("network", []),
                "state": attrs.get("state"),
                # A resource public by its own policy, whatever its reach: what the statements
                # for anyone allow (ADR-0037, second amendment, wave 2).
                "policy_actions": (
                    attrs.get("actions", []) if attrs.get("via") == "resource_policy" else []
                ),
                # The flow drawn from this door that day; none for CloudFox's alone.
                "flow_id": r.flow_id if r.node_count is not None else None,
                "resources": r.node_count,
                "truncated": bool(r.truncated),
            }
        )
    return doors, total


def edges_by_ids(conn: Connection, edge_ids: list[int]) -> dict[int, dict[str, Any]]:
    """Edges by id, whatever day they stood (an attack path keeps its steps' ids)."""
    if not edge_ids:
        return {}
    rows = conn.execute(
        text(f"SELECT {_EDGE_COLUMNS} FROM edge e WHERE e.id = ANY(CAST(:ids AS bigint[]))"),  # noqa: S608
        {"ids": edge_ids},
    )
    return {r.id: _edge(r) for r in rows}
