"""Flow mode on the Resource map (ADR-0036): from each internet entry, the whole chain traffic
and events reach, computed in ingest and read by id.

    write_flows()   after the day's edges: one flow per entry of the connection, its shape
                    stored once per content (flow_shape), the day's pointer in flow_snapshot
    flow_detail()   one flow as it stood on a day: steps, chips, nodes, edges
    delete_orphan_flow_shapes()   retention's cleanup, after old partitions are dropped

A flow starts at a resource the internet reaches (internet-entry: open), is kept out of
(internet-restricted: restricted, ADR-0035) or may reach (internet-unverified: unknown, data is
missing; ADR-0035, second amendment). It walks forward along ROUTES_TO and TRIGGERS
edges, and from compute to data through the compute's role (RUNS_AS then ACCESSES, drawn as one
"uses" step via the role). The DNS records that name the entry are drawn before it, record by
record back to the outermost one (a CNAME to a record to the entry; argus_v12). The walk is
recursive SQL with a depth limit (walk.py); this module shapes its result: columns, groups for
fan-out, chips (security groups, role, WAF), and the caps. The flows' list is the Resource
map's front doors (graph.front_doors): each door carries its flow.
"""

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from sqlalchemy import Connection, Engine, text

from argus.inventory import resource_nodes
from argus.relationships.queries import effective_days
from argus.relationships.walk import walk

MAX_DEPTH = 10  # steps from the entry
MAX_REACHED = 2000  # nodes the walk may reach from one entry before the flow is cut
MAX_DRAWN = 150  # nodes a flow draws
GROUP_OVER = 25  # more targets of one type from one node: one group step (as the map)

# The day's rule edges a flow reads: the moves, the entries and the chips.
_EDGES_SQL = """
  SELECT e.id, e.source_uid, e.target_uid, e.type
  FROM edge e JOIN edge_snapshot s ON s.edge_id = e.id AND s.snapshot_date = :rd
  WHERE e.connection_id = :c AND starts_with(e.origin, 'rule:')
    AND e.type IN ('ROUTES_TO', 'TRIGGERS', 'RUNS_AS', 'ACCESSES', 'MEMBER_OF', 'PROTECTED_BY',
                   'PUBLIC_RESTRICTED', 'PUBLIC_UNVERIFIED')
"""
# The moves of the walk, as (source_uid, target_uid): ROUTES_TO and TRIGGERS not from the
# internet, and compute -> data through the compute's role.
_MOVES_SQL = f"""
  SELECT m.source_uid, m.target_uid FROM ({_EDGES_SQL}) m
  WHERE m.type IN ('ROUTES_TO', 'TRIGGERS') AND m.source_uid <> 'internet'
  UNION
  SELECT ra.source_uid, ac.target_uid
  FROM ({_EDGES_SQL}) ra JOIN ({_EDGES_SQL}) ac
    ON ac.source_uid = ra.target_uid AND ac.type = 'ACCESSES'
  WHERE ra.type = 'RUNS_AS'
"""  # noqa: S608 - fixed fragments


# An internet edge's type -> the reach of the flow it starts.
ENTRY_REACH = {
    "ROUTES_TO": "open",
    "PUBLIC_RESTRICTED": "restricted",
    "PUBLIC_UNVERIFIED": "unknown",
}


def _is_security_group(uid: str) -> bool:
    return ":security-group/" in uid


@dataclass
class _Edges:
    """The day's rule edges of one connection, indexed for shaping."""

    out: dict[str, list[tuple[int, str, str]]] = field(default_factory=lambda: defaultdict(list))
    into: dict[str, list[tuple[int, str, str]]] = field(default_factory=lambda: defaultdict(list))

    def add(self, edge_id: int, source: str, target: str, type_: str) -> None:
        self.out[source].append((edge_id, target, type_))
        self.into[target].append((edge_id, source, type_))


@dataclass
class _Step:
    col: int
    kind: str
    source: str
    target: str | None
    via: str | None
    edge_ids: list[int]
    group_type: str | None = None
    group_count: int | None = None

    def row(self) -> list[Any]:
        return [
            self.col,
            self.kind,
            self.source,
            self.target,
            self.via,
            sorted(self.edge_ids),
            self.group_type,
            self.group_count,
        ]


def _moves(edges: _Edges, node: str) -> list[tuple[str, str | None, list[int]]]:
    """(target, via role, edge ids) for each move out of a node."""
    found: dict[tuple[str, str | None], list[int]] = {}
    for edge_id, target, type_ in edges.out.get(node, []):
        if type_ in ("ROUTES_TO", "TRIGGERS"):
            found.setdefault((target, None), []).append(edge_id)
        elif type_ == "RUNS_AS":
            for access_id, data, access_type in edges.out.get(target, []):
                if access_type == "ACCESSES":
                    found.setdefault((data, target), []).extend([edge_id, access_id])
    return [(target, via, ids) for (target, via), ids in found.items()]


@dataclass
class _Flow:
    entry: str
    reach: str
    steps: list[_Step]
    chips: list[list[Any]]
    node_count: int
    depth: int
    truncated: bool


# The resource types that are DNS records, per provider: what the internet asks for before it
# reaches a door (a GCP or OCI record type joins here with its provider).
DNS_RECORD_TYPES = frozenset({"aws_route53_record"})


def is_dns_record(type_: str | None) -> bool:
    return type_ in DNS_RECORD_TYPES


def _names_back(entry: str, edges: _Edges, types: dict[str, str | None]) -> dict[str, int]:
    """Every DNS record that names the entry, directly or through other records, with its
    distance in hops (1: names the entry). Breadth first, MAX_DEPTH deep; a record seen once
    keeps its shortest distance, so a cycle ends."""
    dist: dict[str, int] = {}
    frontier, depth = [entry], 0
    while frontier and depth < MAX_DEPTH:
        depth += 1
        nxt = []
        for node in sorted(frontier):
            for _, source, type_ in edges.into.get(node, []):
                if (
                    type_ == "ROUTES_TO"
                    and is_dns_record(types.get(source))
                    and source != entry
                    and source not in dist
                ):
                    dist[source] = depth
                    nxt.append(source)
        frontier = nxt
    return dist


def _entry_steps(entry: str, edges: _Edges, types: dict[str, str | None]) -> list[_Step]:
    """Internet -> the outermost records -> ... -> the records that name the entry -> the entry,
    one column per hop; else internet -> entry."""
    dist = _names_back(entry, edges, types)
    if not dist:
        entry_edges = [
            edge_id
            for edge_id, source, type_ in edges.into.get(entry, [])
            if source == "internet" and type_ in ENTRY_REACH
        ]
        return [_Step(1, "edge", "internet", entry, None, entry_edges)]
    far = max(dist.values())
    col = {record: far - d + 1 for record, d in dist.items()} | {entry: far + 1}
    links: list[_Step] = []
    named: set[str] = set()
    for node in sorted(col, key=lambda n: (col[n], n)):
        for edge_id, source, type_ in sorted(edges.into.get(node, [])):
            # Only towards the entry: a record naming one nearer the internet is not drawn.
            if type_ == "ROUTES_TO" and source in dist and col[source] < col[node]:
                links.append(_Step(col[node], "edge", source, node, None, [edge_id]))
                named.add(node)
    roots = sorted(r for r in dist if r not in named)
    return [_Step(col[r], "dns", "internet", r, None, []) for r in roots] + links


def _forward_steps(
    entry: str,
    depths: dict[str, int],
    edges: _Edges,
    types: dict[str, str | None],
    offset: int,
) -> tuple[list[_Step], set[str], bool]:
    """The moves from the entry, breadth first: only forward ones (the target deeper than the
    source), so a cycle or a lateral edge is not drawn twice; more than GROUP_OVER targets of
    one type from one node become one group. Returns the steps, the nodes drawn and whether
    MAX_DRAWN cut the flow."""
    steps: list[_Step] = []
    drawn: set[str] = {entry}
    truncated = False
    frontier = [entry]
    while frontier:
        nxt: list[str] = []
        for node in sorted(frontier, key=lambda n: (depths[n], n)):
            by_type: dict[str | None, list[tuple[str, str | None, list[int]]]] = defaultdict(list)
            for move in _moves(edges, node):
                if move[0] in depths and depths[move[0]] > depths[node]:
                    by_type[types.get(move[0])].append(move)
            for type_, group in sorted(by_type.items(), key=lambda kv: kv[0] or ""):
                if len(group) > GROUP_OVER:
                    ids = [i for m in group for i in m[2]]
                    col = offset + depths[node] + 1
                    steps.append(_Step(col, "group", node, None, None, ids, type_, len(group)))
                    continue
                for target, via, ids in sorted(group, key=lambda m: (m[0], m[1] or "")):
                    if target not in drawn and len(drawn) >= MAX_DRAWN:
                        truncated = True
                        continue
                    kind = "uses" if via else "edge"
                    steps.append(_Step(offset + depths[target], kind, node, target, via, ids))
                    if target not in drawn:
                        drawn.add(target)
                        nxt.append(target)
        frontier = nxt
    return steps, drawn, truncated


_CHIPS = {"RUNS_AS": "role", "PROTECTED_BY": "waf"}


def _chips(drawn: set[str], edges: _Edges) -> list[list[Any]]:
    """What each drawn node carries: its security groups, its role, a WAF."""
    chips = []
    for node in drawn:
        for edge_id, target, type_ in edges.out.get(node, []):
            if type_ == "MEMBER_OF" and _is_security_group(target):
                chips.append([node, "security_group", target, edge_id])
            elif type_ in _CHIPS:
                chips.append([node, _CHIPS[type_], target, edge_id])
    return sorted(chips)


def _shape(
    entry: str,
    reach: str,
    depths: dict[str, int],
    edges: _Edges,
    types: dict[str, str | None],
) -> _Flow:
    """One entry's flow: its steps and chips, node count and depth, and whether a cap cut it."""
    truncated = len(depths) > MAX_REACHED
    if truncated:
        keep = sorted(depths, key=lambda n: (depths[n], n))[:MAX_REACHED]
        depths = {n: depths[n] for n in keep}
    head = _entry_steps(entry, edges, types)
    offset = max(s.col for s in head)
    steps, drawn, cut = _forward_steps(entry, depths, edges, types, offset)
    records = len(
        {s.target for s in head if s.kind == "dns"}
        | {s.source for s in head if s.kind == "edge" and s.source != "internet"}
    )
    return _Flow(
        entry,
        reach,
        head + steps,
        _chips(drawn, edges),
        len(drawn) + records,
        max(s.col for s in head + steps),
        truncated or cut,
    )


def _hash(reach: str, steps: list[_Step], chips: list[list[Any]], truncated: bool) -> bytes:
    canonical = json.dumps(
        [reach, [s.row() for s in steps], chips, truncated], separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).digest()


def flow_key(connection_id: int, entry_uid: str) -> bytes:
    return hashlib.sha256(f"flow|{connection_id}|{entry_uid}".encode()).digest()


def write_flows(engine: Engine, *, connection_id: int, day: date) -> int:
    """Replaces the day's flows of one connection. Returns how many there are."""
    with engine.begin() as conn:
        rule_day = effective_days(conn, connection_id=connection_id, day=day)["rule_day"]
        conn.execute(
            text("""
                DELETE FROM flow_snapshot s USING flow f
                WHERE s.flow_id = f.id AND s.snapshot_date = :d AND f.connection_id = :c
            """),
            {"d": day, "c": connection_id},
        )
        if rule_day is None:
            return 0
        params = {"c": connection_id, "rd": rule_day}
        edges = _Edges()
        entries: dict[str, str] = {}
        for r in conn.execute(text(_EDGES_SQL), params):
            edges.add(r.id, r.source_uid, r.target_uid, r.type)
            if r.source_uid == "internet":
                reach = ENTRY_REACH.get(r.type)
                if reach is not None and entries.get(r.target_uid) != "open":
                    entries[r.target_uid] = reach
        if not entries:
            return 0
        reached = walk(
            conn, moves_sql=_MOVES_SQL, params=params, seeds=sorted(entries), max_depth=MAX_DEPTH
        )
        uids = {u for nodes in reached.values() for u in nodes} | _named_by(entries, edges)
        types = {uid: info.get("type") for uid, info in resource_nodes(conn, sorted(uids)).items()}
        for entry, reach in sorted(entries.items()):
            flow = _shape(entry, reach, reached.get(entry, {entry: 0}), edges, types)
            _store(conn, connection_id, day, flow)
        return len(entries)


def _named_by(entries: dict[str, str], edges: _Edges) -> set[str]:
    """What routes to the entries, hop by hop back, MAX_DEPTH deep: the candidates for their
    DNS chains, whose types are then read once."""
    seen: set[str] = set()
    frontier = sorted(entries)
    for _ in range(MAX_DEPTH):
        nxt = []
        for node in frontier:
            for _, source, type_ in edges.into.get(node, []):
                if type_ == "ROUTES_TO" and source != "internet" and source not in seen:
                    seen.add(source)
                    nxt.append(source)
        if not nxt:
            break
        frontier = nxt
    return seen


def _store(conn: Connection, connection_id: int, day: date, flow: _Flow) -> None:
    entry, reach, steps, chips = flow.entry, flow.reach, flow.steps, flow.chips
    flow_id = conn.execute(
        text("""
            INSERT INTO flow (flow_key, connection_id, entry_uid, first_seen, last_seen)
            VALUES (:k, :c, :e, :d, :d)
            ON CONFLICT (flow_key) DO UPDATE SET
              first_seen = LEAST(flow.first_seen, EXCLUDED.first_seen),
              last_seen = GREATEST(flow.last_seen, EXCLUDED.last_seen)
            RETURNING id
        """),
        {"k": flow_key(connection_id, entry), "c": connection_id, "e": entry, "d": day},
    ).scalar_one()
    shape_hash = _hash(reach, steps, chips, flow.truncated)
    shape_id = conn.execute(
        text("""
            INSERT INTO flow_shape (shape_hash, reach, node_count, depth, truncated, created_on)
            VALUES (:h, :r, :n, :depth, :t, :d)
            ON CONFLICT (shape_hash) DO NOTHING RETURNING id
        """),
        {
            "h": shape_hash,
            "r": reach,
            "n": flow.node_count,
            "depth": flow.depth,
            "t": flow.truncated,
            "d": day,
        },
    ).scalar_one_or_none()
    if shape_id is None:
        shape_id = conn.execute(
            text("SELECT id FROM flow_shape WHERE shape_hash = :h"), {"h": shape_hash}
        ).scalar_one()
    else:
        conn.execute(
            text("""
                INSERT INTO flow_step (shape_id, ord, col, kind, source_uid, target_uid, via_uid,
                                       edge_ids, group_type, group_count)
                VALUES (:s, :o, :col, :kind, :src, :tgt, :via, CAST(:ids AS bigint[]), :gt, :gc)
            """),
            [
                {
                    "s": shape_id,
                    "o": i,
                    "col": st.col,
                    "kind": st.kind,
                    "src": st.source,
                    "tgt": st.target,
                    "via": st.via,
                    "ids": sorted(st.edge_ids),
                    "gt": st.group_type,
                    "gc": st.group_count,
                }
                for i, st in enumerate(steps)
            ],
        )
        if chips:
            conn.execute(
                text("""
                    INSERT INTO flow_chip (shape_id, node_uid, kind, chip_uid, edge_id)
                    VALUES (:s, :n, :k, :u, :e) ON CONFLICT DO NOTHING
                """),
                [{"s": shape_id, "n": n, "k": k, "u": u, "e": e} for n, k, u, e in chips],
            )
    conn.execute(
        text(
            "INSERT INTO flow_snapshot (snapshot_date, flow_id, shape_id) VALUES (:d, :f, :s) "
            "ON CONFLICT (snapshot_date, flow_id) DO UPDATE SET shape_id = EXCLUDED.shape_id"
        ),
        {"d": day, "f": flow_id, "s": shape_id},
    )


def _rule_day(conn: Connection, connection_id: int, day: date) -> date | None:
    return effective_days(conn, connection_id=connection_id, day=day)["rule_day"]


def flow_detail(conn: Connection, *, flow_id: int, day: date) -> dict[str, Any] | None:
    """One flow as it stood on a day: its steps, chips and the uids they name; None when the
    flow does not exist or had no shape that day."""
    flow = conn.execute(
        text("SELECT id, connection_id, entry_uid FROM flow WHERE id = :i"), {"i": flow_id}
    ).one_or_none()
    if flow is None:
        return None
    rule_day = _rule_day(conn, flow.connection_id, day)
    shape = conn.execute(
        text("""
            SELECT sh.id, sh.reach, sh.node_count, sh.depth, sh.truncated
            FROM flow_snapshot s JOIN flow_shape sh ON sh.id = s.shape_id
            WHERE s.snapshot_date = :rd AND s.flow_id = :f
        """),
        {"rd": rule_day, "f": flow_id},
    ).one_or_none()
    if shape is None:
        return None
    steps = [
        dict(r._mapping)
        for r in conn.execute(
            text("""
                SELECT col, kind, source_uid, target_uid, via_uid, edge_ids, group_type,
                       group_count
                FROM flow_step WHERE shape_id = :s ORDER BY ord
            """),
            {"s": shape.id},
        )
    ]
    chips = [
        dict(r._mapping)
        for r in conn.execute(
            text(
                "SELECT node_uid, kind, chip_uid, edge_id FROM flow_chip WHERE shape_id = :s "
                "ORDER BY node_uid, kind, chip_uid"
            ),
            {"s": shape.id},
        )
    ]
    return {
        "id": flow.id,
        "connection_id": flow.connection_id,
        "entry_uid": flow.entry_uid,
        "reach": shape.reach,
        "node_count": shape.node_count,
        "depth": shape.depth,
        "truncated": shape.truncated,
        "rule_day": rule_day,
        "steps": steps,
        "chips": chips,
    }


def delete_orphan_flow_shapes(conn: Connection) -> int:
    """Retention: shapes no remaining snapshot points to (their steps and chips go with them)."""
    deleted: int = conn.execute(
        text("""
            DELETE FROM flow_shape sh
            WHERE NOT EXISTS (SELECT 1 FROM flow_snapshot s WHERE s.shape_id = sh.id)
        """)
    ).rowcount
    return deleted
