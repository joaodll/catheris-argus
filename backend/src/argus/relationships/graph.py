"""The Resource Map's and the Security Map's reads (ADR-0051): a neighbourhood, never the
estate.

    neighbourhood()   a focus and its neighbours, hop by hop (at most MAX_DEPTH), at most 500
                      nodes; more than 25 neighbours of one (direction, edge type, resource type)
                      come back as one group instead
    group_members()   a group's members, a page at a time

A walk goes on only from resources of the connection: a pseudo-node (`internet`, an account's
administrator, an external host, a wildcard grant), a boundary node or a group is drawn and
never walked past, so a hub met on the way costs one count, not its thousands of neighbours.
The screen expands those by hand (ADR-0051, amended 2026-11-14: three hops with every layer from
a resource beside the hubs were 390 ms at p95 when the walk went through them).

Two maps (owner, 2026-11-13): the Resource Map draws how resources connect, and no security
fact; the Security Map also draws SECURITY_EDGE_TYPES, the lines that are security judgements.
The split is by edge type, not by origin: rules emit some of them as well as CloudFox.

Every read is for one connection and one day: the edges that connection's runs derived, in each
edge family's snapshot that stands for the day (edge_load), plus manual edges that touch one of
its resources. The API asks for today, so a map shows each account's latest scan, however old;
the day stays a parameter here as the seam for a past-day view (ADR-0051). A resource owned by
another connection, or an ARN of another account, is a boundary node: drawn, never expanded.
Layers and origins pick edges from fixed SQL fragments; a client only names them. Nodes are
uids: resources (placed with inventory's exported node view) and the pseudo-nodes `internet`,
`admin:<account>`, `external:<host>` and `any:<service>` (a wildcard grant, role-accesses).

A door the internet rules judge closed or undecided (VERDICT_EDGE_TYPES) is on neither map, and
a map edge carries only its plain attributes (EDGE_ATTRIBUTES), never the rules' evidence.
Misconfigurations and the Resources sheet explain reach.
"""

from datetime import date
from typing import Any, Literal, NamedTuple

from sqlalchemy import Connection, text

from argus.inventory import RESOURCE_NODES_SQL, resource_nodes
from argus.relationships.queries import MAX_EDGES, all_effective_days, edges_at

Layer = Literal["traffic", "identity", "network", "policy", "data"]
Origin = Literal["rule", "cloudfox", "manual"]
Direction = Literal["out", "in"]
Map = Literal["resource", "security"]

MAX_DEPTH = 3  # hops one read walks (owner, 2026-11-13: "bring 3 hops back")
MAX_NODES = MAX_EDGES  # a hop stops at 500 nodes, and the screen's map holds as many
GROUP_OVER = 25  # more neighbours of one kind than this: one group node (ADR-0051)
DEFAULT_LAYERS: tuple[Layer, ...] = ("traffic", "identity")
ORIGINS: tuple[Origin, ...] = ("rule", "cloudfox", "manual")
# What a map edge shows of its attributes: the protocol and ports. The internet rules' evidence
# (network, routes, reasons) stays on the edge row for the Resources sheet.
EDGE_ATTRIBUTES: tuple[str, ...] = ("protocol", "from_port", "to_port", "port")

# Lines that are security judgements, drawn on the Security Map only: who is an administrator,
# who can escalate to whom, an outside account trusted, a credential held, CloudFox's claim that
# the internet reaches a resource. Every other line says how resources connect.
SECURITY_EDGE_TYPES: tuple[str, ...] = (
    "IS_ADMIN",
    "CAN_PRIVESC_TO",
    "CAN_ESCALATE_TO",
    "OUTSIDER",
    "HAS_CREDENTIAL",
    "INTERNET_REACHABLE",
)
# The internet rules' closed and undecided doors: verdicts, not connections, on neither map.
VERDICT_EDGE_TYPES: tuple[str, ...] = ("PUBLIC_RESTRICTED", "PUBLIC_UNVERIFIED")
MAP_SQL: dict[str, str] = {
    "resource": "e.type NOT IN ({})".format(", ".join(f"'{t}'" for t in SECURITY_EDGE_TYPES)),
    "security": "true",
}

# An IAM group's ARN: MEMBER_OF to a group is identity, to a security group is network.
_IAM_GROUP = "e.target_uid ~ '[:]iam[:][:][0-9]{12}[:]group/'"
LAYER_SQL: dict[str, str] = {
    # Connections only: VERDICT_EDGE_TYPES are not in any layer.
    "traffic": "e.type IN ('ROUTES_TO', 'TRIGGERS', 'INTERNET_REACHABLE')",
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


def _filters(layers: tuple[str, ...], origins: tuple[str, ...], kind: Map) -> str:
    """The WHERE fragment for this map, layers and origins: fixed SQL only (unknown names
    raise)."""
    if not layers or not origins:
        return "false"
    by_layer = " OR ".join(f"({LAYER_SQL[name]})" for name in sorted(set(layers)))
    by_origin = " OR ".join(ORIGIN_SQL[name] for name in sorted(set(origins)))
    return f"({by_layer}) AND ({by_origin}) AND {MAP_SQL[kind]}"


def on_map(edge_type: str, kind: Map) -> bool:
    """Whether a line of this type is drawn on this map."""
    if edge_type in VERDICT_EDGE_TYPES:
        return False
    return kind == "security" or edge_type not in SECURITY_EDGE_TYPES


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
    day: date,
    depth: int = 1,
    layers: tuple[str, ...] = DEFAULT_LAYERS,
    origins: tuple[str, ...] = ORIGINS,
    kind: Map = "resource",
) -> dict[str, Any]:
    """The focus and its neighbours up to `depth` hops (1 to MAX_DEPTH), in one connection, as
    they stood on `day`, with the lines of one map.

    Returns nodes (uid, kind, and the inventory's id, type, name, region, connection when it
    has the resource; `expanded` when its neighbours were read; `boundary` for another
    connection's or account's resource, which is never expanded), edges, groups and
    `truncated` (the 500-node cap stopped the walk). A hop goes on only from the connection's
    own resources: a pseudo-node or a boundary node is drawn and left for the screen to
    expand."""
    depth = max(1, min(depth, MAX_DEPTH))
    sql = text(_hop_sql(_filters(layers, origins, kind)))
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
        frontier = [u for u in found if kind_of(u) == "resource" and not walk.boundary(u)]
    return {
        "nodes": walk.nodes(list(order), expanded),
        "edges": list(edges.values()),
        "groups": list(groups.values()),
        "truncated": truncated,
    }


def plain_attributes(attributes: dict[str, Any] | None) -> dict[str, Any]:
    """An edge's plain attributes (EDGE_ATTRIBUTES), scalars only."""
    return {
        k: v
        for k, v in (attributes or {}).items()
        if k in EDGE_ATTRIBUTES and isinstance(v, str | int | float | bool)
    }


def map_edges_at(
    conn: Connection, *, resource_id: int, connection_id: int, day: date, kind: Map
) -> list[dict[str, Any]]:
    """A resource's own edges as a map's panel lists them: only the lines that map draws, with
    their plain attributes (the Resources sheet reads edges_at, evidence included)."""
    return [
        {**e, "attributes": plain_attributes(e["attributes"])}
        for e in edges_at(conn, resource_id=resource_id, connection_id=connection_id, day=day)
        if on_map(e["type"], kind)
    ]


def _edge(r: Any) -> dict[str, Any]:
    """An edge as the map returns it: with its plain attributes only."""
    return {
        "id": r.id,
        "source_uid": r.source_uid,
        "target_uid": r.target_uid,
        "type": r.type,
        "origin": r.origin,
        "attributes": plain_attributes(r.attributes),
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
    links it, and the group's size. The caller asks only for a type its map draws (on_map)."""
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
