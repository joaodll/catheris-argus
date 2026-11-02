"""The Resource map in Cypher, measured before it is built: Phase 0 of round M3 (ADR-0044, M3
amendment, D2's gate). M3b may move the map's reads to Memgraph only when this passes:
- parity: the Cypher prototype answers what relationships.neighbourhood() answers today (the
  same nodes, edges, groups, boundary nodes and `truncated`), at depths 1-3, with the default
  layers and with all of them; a group's members match group_members()
- speed: p95 <= 300 ms and p99 <= 1 s at 8 concurrent clients, idle, while the largest
  connection is re-projected, and while the attack paths are evaluated

The prototype is test code. Round 4b MOVES it into argus.graph (the hop as a named read, the
loop beside it) and deletes the SQL; it is never copied. It reads what M3b will read:
topology from Memgraph (one read per hop, in a read transaction with a 5 s timeout), then
names and edge details from Postgres in batches. Layers are edge-type lists here; Phase 3
projects a `layer` per edge instead.

Clients are threads of one process, as requests are in one API process. The re-projection and
the evaluation run in a process of their own, as graph-sync does, so they do not share this
process's interpreter lock. SQL runs as argus_api with its 5 s statement timeout.

Runs after test_graph_budget.py in the same session (the `budget` profile runs both) and reuses
its estate; alone, it generates one. It adds three hubs to the largest connection (20,000,
10,000 and 5,000 neighbours: graph_estate.add_map_hubs) and re-projects it.
"""

import math
import os
import random
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from multiprocessing import get_context
from typing import Any

import pytest
from neo4j import ManagedTransaction, unit_of_work
from neo4j.exceptions import TransientError
from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.exc import OperationalError
from tests.budget import graph_estate
from tests.conftest import RULES_DIR

from argus import graph, inventory, relationships
from argus.core.config import get_settings
from argus.core.db import CONNECT_ARGS, get_engine
from argus.graph import client
from argus.graph.projection import graph_uid, postgres_uid
from argus.relationships.graph import (
    DEFAULT_LAYERS,
    GROUP_OVER,
    MAX_DEPTH,
    MAX_NODES,
    ORIGINS,
    MapScope,
    _account_of,
    group_id,
    kind_of,
)

pytestmark = [
    pytest.mark.db,
    pytest.mark.graph,
    pytest.mark.skipif(
        not os.environ.get("ARGUS_GRAPH_BUDGET"), reason="opt-in: ARGUS_GRAPH_BUDGET=1"
    ),
]
P95_MS = 300.0
P99_MS = 1000.0
TIMEOUT_S = 5.0
ALL_LAYERS = ("traffic", "identity", "network", "policy", "data")
CLIENTS = (8, 16)
IDLE_REQUESTS = 40  # per client
WARM_UP = 2  # unrecorded requests per client before each measurement
SINGLE_RUNS = 10
PAGE_SIZE = 20  # the API's default page (api/routes/resource_map.py)

# ---- the prototype -----------------------------------------------------------------------

# The layers as edge types (LAYER_SQL in relationships/graph.py, which Phase 3 replaces with one
# Python declaration projected onto each edge). MEMBER_OF is identity when its target is an IAM
# group, network otherwise.
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
    "data": ("ACCESSES",),
}
IAM_GROUP = ".*:iam::[0-9]{12}:group/.*"

# One hop: every edge of the connection at the frontier, grouped per (anchor, direction, edge
# type, neighbour type); a group's members only when it is drawn one by one. The WITH makes
# Memgraph find the anchor by its uid first and expand from it: in one MATCH, its planner
# starts from the global edge index on `conn` and scans every edge of the connection for each
# anchor (3,989,601 edges for 200 anchors at 20,000 resources: 1.8 s against 0.16 s). One
# record per hop: the client's cost is per Bolt record (about 40 ms of CPU per map request with
# a record per group, under the interpreter lock that a busy API process shares).
HOP = """
UNWIND $frontier AS anchor
MATCH (a:R {uid: anchor})
WITH a, anchor
MATCH (a)-[r]-(b:R)
WHERE r.conn = $c
  AND (type(r) IN $types
       OR (type(r) = 'MEMBER_OF'
           AND (($groups AND endNode(r).uid =~ $iam_group)
                OR ($others AND NOT endNode(r).uid =~ $iam_group))))
  AND (($rule AND r.origin STARTS WITH 'rule:') OR ($cloudfox AND r.origin = 'cloudfox'))
WITH anchor, r, b,
     CASE WHEN startNode(r).uid = anchor THEN 'out' ELSE 'in' END AS direction
WITH anchor, direction, type(r) AS type, b.type AS other_type,
     count(DISTINCT b.uid) AS siblings,
     collect([r.id, b.uid, b.name, b.conn]) AS hits
RETURN collect([anchor, direction, type, other_type, siblings,
                CASE WHEN siblings <= $g THEN hits ELSE [] END]) AS hop
"""
# One page of a group's members, by name, each with the lowest edge id that links it.
_GROUP_PAGE = """
MATCH (a:R {{uid: $anchor}})
WITH a
MATCH (a){pattern}(b:R)
WHERE type(r) = $type AND r.conn = $c AND coalesce(b.type, '') = $rt
WITH b, min(r.id) AS id
WITH b.uid AS other, id, toLower(coalesce(b.name, b.uid)) AS label
ORDER BY label, other
WITH collect([other, id]) AS members
RETURN size(members) AS total, members[$first..$last] AS page
"""
GROUP_PAGE = {
    "out": _GROUP_PAGE.format(pattern="-[r]->"),
    "in": _GROUP_PAGE.format(pattern="<-[r]-"),
}


def _read(cypher: str, *, timeout: float = TIMEOUT_S, **params: Any) -> list[dict[str, Any]]:
    @unit_of_work(timeout=timeout)
    def work(tx: ManagedTransaction) -> list[dict[str, Any]]:
        # Plain values: Record.data() walks every nested value to convert graph types, and the
        # reads here return none.
        result = tx.run(cypher, params)
        keys = result.keys()
        return [dict(zip(keys, record.values(), strict=True)) for record in result]

    with client.driver().session() as session:
        rows: list[dict[str, Any]] = session.execute_read(work)
        return rows


def _hop_params(c: int, layers: tuple[str, ...], origins: tuple[str, ...]) -> dict[str, Any]:
    return {
        "c": c,
        "types": sorted({t for layer in layers for t in LAYER_TYPES[layer]}),
        "groups": "identity" in layers,
        "others": "network" in layers,
        "iam_group": IAM_GROUP,
        "rule": "rule" in origins,
        "cloudfox": "cloudfox" in origins,
        "g": GROUP_OVER,
    }


def _boundary(uid: str, owner: int | None, scope: MapScope) -> bool:
    if owner is not None:
        return owner != scope.connection_id
    account = _account_of(uid)
    return account is not None and account != scope.account_id


def _ordered(rows: list[list[Any]]) -> Iterator[tuple[Any, ...]]:
    """The hop's groups in relationships.neighbourhood()'s order: a large group as one row,
    else one row per edge (two when a rule and CloudFox both find it), by name, uid, edge id.
    Code-point order: SQL sorts in the database's collation, so which nodes a cut neighbourhood
    keeps can differ (round 4b fixes one order)."""
    flat: list[tuple[Any, ...]] = []
    for anchor_uid, direction, etype, other_type, siblings, hits in rows:
        anchor = postgres_uid(anchor_uid)
        if siblings > GROUP_OVER:
            flat.append((anchor, direction, etype, other_type, None, None, siblings, None, None))
            continue
        for edge_id, other, name, owner in hits:
            flat.append(
                (
                    anchor,
                    direction,
                    etype,
                    other_type,
                    name,
                    postgres_uid(other),
                    siblings,
                    edge_id,
                    owner,
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


def cypher_neighbourhood(
    conn: Connection,
    *,
    focus: str,
    scope: MapScope,
    depth: int,
    layers: tuple[str, ...] = DEFAULT_LAYERS,
    origins: tuple[str, ...] = ORIGINS,
) -> dict[str, Any]:
    """relationships.neighbourhood() over Memgraph: the same walk, limits and answer."""
    depth = max(1, min(depth, MAX_DEPTH))
    params = _hop_params(scope.connection_id, layers, origins)
    order: dict[str, None] = {focus: None}
    owners: dict[str, int | None] = {}
    edge_ids: dict[int, None] = {}
    groups: dict[str, dict[str, Any]] = {}
    expanded: set[str] = set()
    truncated = False
    frontier = [focus]
    for _ in range(depth):
        if not frontier or truncated:
            break
        rows = _read(HOP, frontier=[graph_uid(u, scope.account_id) for u in frontier], **params)[0][
            "hop"
        ]
        expanded.update(frontier)
        found: list[str] = []
        for (
            anchor,
            direction,
            etype,
            other_type,
            _name,
            other,
            siblings,
            edge_id,
            owner,
        ) in _ordered(rows):
            if len(order) + len(groups) >= MAX_NODES:
                truncated = True
                break
            if siblings > GROUP_OVER:
                key = group_id(anchor, direction, etype, other_type)
                groups.setdefault(
                    key,
                    {
                        "id": key,
                        "anchor_uid": anchor,
                        "direction": direction,
                        "edge_type": etype,
                        "resource_type": other_type,
                        "count": int(siblings),
                    },
                )
                continue
            if other not in order:
                order[other] = None
                found.append(other)
            owners[other] = owner
            edge_ids[edge_id] = None
        frontier = [u for u in found if not _boundary(u, owners.get(u), scope)]
    # Postgres: names and places, and the edges' details, in one batch each.
    uids = list(order)
    info = inventory.resource_nodes(conn, [u for u in uids if kind_of(u) == "resource"])
    edges = relationships.edges_by_ids(conn, list(edge_ids))
    nodes = [
        {
            "uid": u,
            "kind": kind_of(u),
            "resource_id": info.get(u, {}).get("id"),
            "type": info.get(u, {}).get("type"),
            "name": info.get(u, {}).get("name"),
            "expanded": u in expanded,
            "boundary": _boundary(u, owners.get(u), scope),
        }
        for u in uids
    ]
    return {
        "nodes": nodes,
        "edges": [edges[i] for i in edge_ids if i in edges],
        "groups": list(groups.values()),
        "truncated": truncated,
    }


def cypher_group_page(
    *,
    anchor: str,
    scope: MapScope,
    direction: str,
    edge_type: str,
    resource_type: str | None,
    limit: int,
    offset: int,
) -> tuple[list[tuple[str, int]], int]:
    rows = _read(
        GROUP_PAGE[direction],
        anchor=graph_uid(anchor, scope.account_id),
        type=edge_type,
        c=scope.connection_id,
        rt=resource_type or "",
        first=offset,
        last=offset + limit,
    )
    page = [(postgres_uid(uid), int(edge_id)) for uid, edge_id in rows[0]["page"]]
    return page, int(rows[0]["total"])


# ---- the harness -------------------------------------------------------------------------


def _percentile(samples: list[float], p: float) -> float:
    """Nearest rank, never interpolated past the slowest sample."""
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(p * len(ordered)) - 1)]


def _api_engine(size: int) -> Engine:
    """Connections as the API's role, with its statement timeout (a role setting, which SET
    ROLE does not apply)."""
    engine = create_engine(
        get_settings().database_url(),
        connect_args=CONNECT_ARGS,
        pool_size=size,
        max_overflow=0,
    )

    @event.listens_for(engine, "connect")
    def _as_api(dbapi_conn, _record):  # type: ignore[no-untyped-def]
        with dbapi_conn.cursor() as cur:
            cur.execute("SET ROLE argus_api")
            cur.execute("SET statement_timeout = '5s'")

    return engine


@dataclass
class Sample:
    latencies_ms: list[float] = field(default_factory=list)
    timeouts: int = 0
    errors: list[str] = field(default_factory=list)
    cores: float = 0.0  # this process's CPU time over the wall time: 1.0 is one busy core

    def line(self) -> str:
        if not self.latencies_ms:
            return f"no requests, {self.timeouts} timeouts, {len(self.errors)} errors"
        return (
            f"{len(self.latencies_ms):5d} requests  p50 {_percentile(self.latencies_ms, 0.5):7.1f}"
            f"  p95 {_percentile(self.latencies_ms, 0.95):7.1f}"
            f"  p99 {_percentile(self.latencies_ms, 0.99):7.1f} ms"
            f"  {self.timeouts} timeouts, {len(self.errors)} errors, {self.cores:.2f} cores"
        )


Request = Callable[[Connection, str, int], Any]


def _requests(scope: MapScope) -> dict[str, Request]:
    def sql(conn: Connection, focus: str, depth: int) -> Any:
        return relationships.neighbourhood(
            conn,
            focus=focus,
            scope=scope,
            depth=depth,
            day=graph_estate.TODAY,
            layers=ALL_LAYERS,
        )

    def cypher(conn: Connection, focus: str, depth: int) -> Any:
        return cypher_neighbourhood(conn, focus=focus, scope=scope, depth=depth, layers=ALL_LAYERS)

    return {"SQL": sql, "Cypher": cypher}


def _client(
    engine: Engine,
    request: Request,
    work: list[tuple[str, int]],
    seed: int,
    sample: Sample,
    lock: threading.Lock,
    *,
    count: int | None,
    until: threading.Event | None,
) -> None:
    rng = random.Random(seed)  # noqa: S311 - a fixed request order, not a secret
    done = 0
    while (count is not None and done < count) or (until is not None and not until.is_set()):
        focus, depth = work[rng.randrange(len(work))]
        started = time.perf_counter()
        try:
            with engine.connect() as conn:
                request(conn, focus, depth)
            ms = (time.perf_counter() - started) * 1000
            with lock:
                sample.latencies_ms.append(ms)
        except (OperationalError, TransientError) as e:
            with lock:
                if "timeout" in str(e).lower() or "canceling statement" in str(e).lower():
                    sample.timeouts += 1
                else:
                    sample.errors.append(f"{type(e).__name__}: {str(e)[:200]}")
        except Exception as e:  # recorded: one failing request must not hide the others
            with lock:
                sample.errors.append(f"{type(e).__name__}: {str(e)[:200]}")
        done += 1


def _drive(
    engine: Engine,
    request: Request,
    work: list[tuple[str, int]],
    clients: int,
    *,
    count: int | None = None,
    until: threading.Event | None = None,
    warm: bool = True,
) -> Sample:
    """`clients` threads sending requests, `count` each or until `until` is set. First, unless
    `warm` is False, WARM_UP unrecorded requests each, so both pools hold their connections,
    as a running API's do (a new Bolt connection with its sign-in takes about 200 ms)."""
    if warm:
        _drive(engine, request, work, clients, count=WARM_UP, warm=False)
    sample, lock = Sample(), threading.Lock()
    threads = [
        threading.Thread(
            target=_client,
            args=(engine, request, work, 1000 + i, sample, lock),
            kwargs={"count": count, "until": until},
        )
        for i in range(clients)
    ]
    cpu, wall = time.process_time(), time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    sample.cores = (time.process_time() - cpu) / max(time.perf_counter() - wall, 1e-9)
    return sample


# graph-sync's work, in a process of its own (spawned: a function of this module).
def _resync(connection_id: int, times: int) -> float:
    engine = get_engine()
    started = time.perf_counter()
    for _ in range(times):
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE graph_projection SET status = 'failed', error = 'budget' "
                    "WHERE connection_id = :c"
                ),
                {"c": connection_id},
            )
        graph.reconcile(engine, today=graph_estate.TODAY)
    client.close()
    return time.perf_counter() - started


def _evaluate() -> float:
    started = time.perf_counter()
    graph.evaluate_paths(get_engine(), today=graph_estate.TODAY, rules_dir=RULES_DIR)
    client.close()
    return time.perf_counter() - started


def _during(
    background: Callable[..., float],
    args: tuple[Any, ...],
    drive: Callable[[threading.Event], Sample],
) -> tuple[Sample, float]:
    """Runs `drive` for as long as `background` runs in its own process."""
    done = threading.Event()
    with ProcessPoolExecutor(max_workers=1, mp_context=get_context("spawn")) as pool:
        future = pool.submit(background, *args)
        future.add_done_callback(lambda _f: done.set())
        sample = drive(done)
        return sample, future.result()


# ---- the estate --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def estate(migrated: Engine) -> dict[str, Any]:
    """The graph budget's estate (generated here when this file runs alone), with the map's
    hubs in the largest connection, re-projected."""
    with migrated.connect() as conn:
        resources = conn.execute(text("SELECT count(*) FROM resource")).scalar_one()
    if resources < graph_estate.RESOURCES * 0.9:
        print(f"\nestate: {graph_estate.prepare(migrated)}")
        with client.write_session() as session:
            session.run("MATCH (n) DETACH DELETE n").consume()
    c = graph_estate.largest_connection(migrated)
    hubs = graph_estate.add_map_hubs(migrated, c)
    with migrated.begin() as conn:
        conn.execute(
            text(
                "UPDATE graph_projection SET status = 'failed', error = 'budget' "
                "WHERE connection_id = :c"
            ),
            {"c": c},
        )
        account = conn.execute(
            text("SELECT account_id FROM connection WHERE id = :c"), {"c": c}
        ).scalar_one()
    graph.reconcile(migrated, today=graph_estate.TODAY)
    with migrated.connect() as conn:
        stored = conn.execute(text("SELECT count(*) FROM attack_path")).scalar_one()
    if not stored:  # alone: the evaluation condition re-evaluates stored paths
        graph.evaluate_paths(migrated, today=graph_estate.TODAY, rules_dir=RULES_DIR)
    scope = MapScope(c, str(account))
    degrees = _read(
        """
        MATCH (a:R)-[r]-() WHERE r.conn = $c
        RETURN a.uid AS uid, count(r) AS degree ORDER BY degree DESC, uid
        """,
        timeout=120,
        c=c,
    )
    foci: dict[str, str] = {f"hub {label} ({layer})": uid for label, (uid, layer) in hubs.items()}
    foci["internet"] = "internet"
    ranked = [(postgres_uid(r["uid"]), int(r["degree"])) for r in degrees]
    taken = set(foci.values())
    top = next((u, d) for u, d in ranked if u not in taken)
    foci[f"top other ({top[1]:,} edges)"] = top[0]
    median = ranked[len(ranked) // 2]
    foci[f"median ({median[1]} edges)"] = median[0]
    leaf = next((u for u, d in reversed(ranked) if d == 1 and kind_of(u) == "resource"), None)
    if leaf is not None:
        foci["leaf (1 edge)"] = leaf
    print(f"\nmap budget: connection {c}, {len(ranked):,} nodes with edges; foci {foci}")
    return {"scope": scope, "foci": foci, "connection": c}


# ---- the tests ---------------------------------------------------------------------------


def _key(answer: dict[str, Any]) -> dict[str, Any]:
    return {
        "nodes": {n["uid"]: (n["boundary"], n["expanded"]) for n in answer["nodes"]},
        "edges": {e["id"] for e in answer["edges"]},
        "groups": {g["id"]: g["count"] for g in answer["groups"]},
        "truncated": answer["truncated"],
    }


def _differences(where: str, want: dict[str, Any], got: dict[str, Any]) -> list[str]:
    if want["truncated"] != got["truncated"]:
        return [f"{where}: truncated {want['truncated']} vs {got['truncated']}"]
    if want["truncated"]:
        # The 500 kept follow each engine's sort order (collation): compare sizes only.
        sizes = [len(x["nodes"]) + len(x["groups"]) for x in (want, got)]
        return [f"{where}: cut at {sizes[0]} vs {sizes[1]}"] if sizes[0] != sizes[1] else []
    found = []
    for part in ("nodes", "edges", "groups"):
        if want[part] != got[part]:
            extra = set(got[part]) - set(want[part])
            missing = set(want[part]) - set(got[part])
            changed = {
                k
                for k in set(want[part]) & set(got[part])
                if isinstance(want[part], dict) and want[part][k] != got[part][k]
            }
            found.append(
                f"{where}: {part} differ, {len(missing)} missing "
                f"{sorted(missing, key=str)[:3]}, {len(extra)} extra "
                f"{sorted(extra, key=str)[:3]}, {len(changed)} changed {sorted(changed)[:3]}"
            )
    return found


def test_the_cypher_map_answers_what_the_sql_map_answers(
    migrated: Engine, estate: dict[str, Any]
) -> None:
    scope: MapScope = estate["scope"]
    mismatches: list[str] = []
    checked = cut = 0
    groups_seen: list[dict[str, Any]] = []
    with migrated.connect() as conn:
        for label, focus in estate["foci"].items():
            for layers in (DEFAULT_LAYERS, ALL_LAYERS):
                for depth in range(1, MAX_DEPTH + 1):
                    want = _key(
                        relationships.neighbourhood(
                            conn,
                            focus=focus,
                            scope=scope,
                            depth=depth,
                            day=graph_estate.TODAY,
                            layers=layers,
                        )
                    )
                    answer = cypher_neighbourhood(
                        conn, focus=focus, scope=scope, depth=depth, layers=layers
                    )
                    checked += 1
                    cut += bool(want["truncated"])
                    shown = "all" if layers == ALL_LAYERS else "default"
                    mismatches += _differences(
                        f"{label}, depth {depth}, layers {shown}", want, _key(answer)
                    )
                    if depth == 1 and layers == ALL_LAYERS:
                        groups_seen.extend(answer["groups"][:3])
        # A group's members: every member and the edge that links it.
        for g in groups_seen[:12]:
            members, total = relationships.group_members(
                conn,
                anchor=g["anchor_uid"],
                scope=scope,
                direction=g["direction"],
                edge_type=g["edge_type"],
                resource_type=g["resource_type"],
                day=graph_estate.TODAY,
                limit=100_000,
                offset=0,
            )
            want_members = {(m["node"]["uid"], m["edge"]["id"]) for m in members}
            page, got_total = cypher_group_page(
                anchor=g["anchor_uid"],
                scope=scope,
                direction=g["direction"],
                edge_type=g["edge_type"],
                resource_type=g["resource_type"],
                limit=100_000,
                offset=0,
            )
            if (total, want_members) != (got_total, set(page)):
                mismatches.append(
                    f"group {g['id']}: {total} members vs {got_total}, "
                    f"{len(want_members ^ set(page))} differ"
                )
    print(
        f"\nparity: {checked} neighbourhoods ({cut} cut at {MAX_NODES}), "
        f"{min(len(groups_seen), 12)} groups; {len(mismatches)} mismatches"
    )
    for m in mismatches[:20]:
        print(f"    {m}")
    assert not mismatches


def test_one_client(migrated: Engine, estate: dict[str, Any]) -> None:
    scope: MapScope = estate["scope"]
    engine = _api_engine(2)
    requests = _requests(scope)
    print("\none client, all layers (ms, p50 / p95 of", SINGLE_RUNS, "runs):")
    try:
        for label, focus in estate["foci"].items():
            cells = []
            for depth in range(1, MAX_DEPTH + 1):
                for name, request in requests.items():
                    sample = _drive(engine, request, [(focus, depth)], 1, count=SINGLE_RUNS)
                    assert not sample.errors, sample.errors[:3]
                    lat = sample.latencies_ms or [math.inf]
                    p50, p95 = _percentile(lat, 0.5), _percentile(lat, 0.95)
                    cells.append(f"d{depth} {name} {p50:6.1f}/{p95:6.1f}")
            print(f"  {label:<34} " + "  ".join(cells))
        # A group page: the first and a deep one, of the largest group of each hub.
        with engine.connect() as conn:
            for label, focus in estate["foci"].items():
                if not label.startswith("hub"):
                    continue
                groups = cypher_neighbourhood(
                    conn, focus=focus, scope=scope, depth=1, layers=ALL_LAYERS
                )["groups"]
                if not groups:
                    continue
                g = max(groups, key=lambda x: x["count"])
                for offset in (0, max(0, g["count"] - PAGE_SIZE)):
                    times: dict[str, list[float]] = {"SQL": [], "Cypher": []}
                    for _ in range(SINGLE_RUNS):
                        started = time.perf_counter()
                        relationships.group_members(
                            conn,
                            anchor=g["anchor_uid"],
                            scope=scope,
                            direction=g["direction"],
                            edge_type=g["edge_type"],
                            resource_type=g["resource_type"],
                            day=graph_estate.TODAY,
                            limit=PAGE_SIZE,
                            offset=offset,
                        )
                        times["SQL"].append((time.perf_counter() - started) * 1000)
                        started = time.perf_counter()
                        cypher_group_page(
                            anchor=g["anchor_uid"],
                            scope=scope,
                            direction=g["direction"],
                            edge_type=g["edge_type"],
                            resource_type=g["resource_type"],
                            limit=PAGE_SIZE,
                            offset=offset,
                        )
                        times["Cypher"].append((time.perf_counter() - started) * 1000)
                    print(
                        f"  group page {label} ({g['count']:,} members, offset {offset:,}): "
                        + "  ".join(
                            f"{k} {_percentile(v, 0.5):6.1f}/{_percentile(v, 0.95):6.1f}"
                            for k, v in times.items()
                        )
                    )
    finally:
        engine.dispose()


def test_concurrent_clients_idle_during_a_projection_and_during_an_evaluation(
    migrated: Engine, estate: dict[str, Any]
) -> None:
    scope: MapScope = estate["scope"]
    work = [(focus, depth) for focus in estate["foci"].values() for depth in (1, 2, 3)]
    results: dict[tuple[str, int, str], Sample] = {}
    background: dict[tuple[str, int, str], float] = {}
    for name, request in _requests(scope).items():
        for clients in CLIENTS:
            engine = _api_engine(clients)
            try:
                results[(name, clients, "idle")] = _drive(
                    engine, request, work, clients, count=IDLE_REQUESTS
                )
                (
                    results[(name, clients, "projection")],
                    background[(name, clients, "projection")],
                ) = _during(
                    _resync,
                    (estate["connection"], 3),
                    lambda until, e=engine, r=request, n=clients: _drive(
                        e, r, work, n, until=until
                    ),
                )
                (
                    results[(name, clients, "evaluation")],
                    background[(name, clients, "evaluation")],
                ) = _during(
                    _evaluate,
                    (),
                    lambda until, e=engine, r=request, n=clients: _drive(
                        e, r, work, n, until=until
                    ),
                )
            finally:
                engine.dispose()
    print("\nconcurrent clients, all layers, depths 1-3 over every focus:")
    for (name, clients, condition), sample in results.items():
        took = background.get((name, clients, condition))
        during = f" (background {took:.1f} s)" if took is not None else ""
        print(f"  {name:<6} {clients:2d} clients {condition:<10} {sample.line()}{during}")
        for error in sample.errors[:3]:
            print(f"      {error}")
    # The gate (ADR-0044, M3 amendment, D2): Cypher at 8 clients, in every condition.
    for condition in ("idle", "projection", "evaluation"):
        sample = results[("Cypher", 8, condition)]
        assert not sample.errors, sample.errors[:3]
        assert sample.latencies_ms, f"no request completed during the {condition}"
        assert _percentile(sample.latencies_ms, 0.95) <= P95_MS, condition
        assert _percentile(sample.latencies_ms, 0.99) <= P99_MS, condition
