"""The Resource map's reads against their budget (ADR-0044, round M3b): at 8 concurrent clients on
a realistic mix of requests, idle, while the largest connection is re-projected, and while the
attack paths are evaluated, p95 stays under 300 ms and p99 under 1 s, with no errors. The worst
case (every layer, depths 1 to 3, over the hubs) is printed, not asserted.

M3b moved the map here from SQL on the owner's gate of 2026-11-02, measured at 300,000 resources
with both engines present (palace, `architecture`): the same answers, p95 within 10% of SQL's.

Clients are threads of one process, as requests are in one API process. The re-projection and
the evaluation run in a process of their own, as graph-sync does, so they do not share this
process's interpreter lock. Postgres runs as argus_api with its 5 s statement timeout.

Runs after test_graph_budget.py in the same session (the `budget` profile runs both) and reuses
its estate; alone, it generates one. It adds three hubs to the largest connection (20,000,
10,000 and 5,000 neighbours: graph_estate.add_map_hubs) and re-projects it.
"""

import math
import os
import random
import threading
import time
from collections.abc import Callable
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

from argus import graph
from argus.core.config import get_settings
from argus.core.db import CONNECT_ARGS, get_engine
from argus.graph import client
from argus.graph.projection import postgres_uid
from argus.relationships import DEFAULT_LAYERS, MAX_DEPTH, MapScope, kind_of

pytestmark = [
    pytest.mark.db,
    pytest.mark.graph,
    pytest.mark.skipif(
        not os.environ.get("ARGUS_GRAPH_BUDGET"), reason="opt-in: ARGUS_GRAPH_BUDGET=1"
    ),
]
TIMEOUT_S = 5.0
P95_MS = 300.0
P99_MS = 1000.0
ALL_LAYERS = ("traffic", "identity", "network", "policy", "data")
CLIENTS = (8, 16)
IDLE_REQUESTS = 100  # per client
BUDGET_CLIENTS = 8
WARM_UP = 2  # unrecorded requests per client before each measurement
SINGLE_RUNS = 10
PAGE_SIZE = 20  # the API's default page (api/routes/resource_map.py)

# ---- the harness -------------------------------------------------------------------------


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


Request = Callable[..., Any]


def _client(
    engine: Engine,
    request: Request,
    work: list[tuple[Any, ...]],
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
        item = work[rng.randrange(len(work))]
        started = time.perf_counter()
        try:
            with engine.connect() as conn:
                request(conn, *item)
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
    work: list[tuple[Any, ...]],
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


def _conditions(
    engine: Engine,
    request: Request,
    work: list[tuple[Any, ...]],
    clients: int,
    estate: dict[str, Any],
) -> dict[str, Sample]:
    """One sample idle, one while the largest connection is re-projected, one during an
    evaluation."""
    drive = lambda until: _drive(engine, request, work, clients, until=until)  # noqa: E731
    return {
        "idle": _drive(engine, request, work, clients, count=IDLE_REQUESTS),
        "projection": _during(_resync, (estate["connection"], 3), drive)[0],
        "evaluation": _during(_evaluate, (), drive)[0],
    }


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
    ordinary = [u for u, d in ranked if u not in foci.values() and kind_of(u) == "resource"]
    return {"scope": scope, "foci": foci, "connection": c, "ordinary": ordinary}


# ---- the tests ---------------------------------------------------------------------------


def test_one_client(migrated: Engine, estate: dict[str, Any]) -> None:
    scope: MapScope = estate["scope"]
    engine = _api_engine(2)

    def read(conn: Connection, focus: str, depth: int) -> Any:
        return graph.neighbourhood(conn, focus=focus, scope=scope, depth=depth, layers=ALL_LAYERS)

    print("\none client, all layers (ms, p50 / p95 of", SINGLE_RUNS, "runs):")
    try:
        for label, focus in estate["foci"].items():
            cells = []
            for depth in range(1, MAX_DEPTH + 1):
                sample = _drive(engine, read, [(focus, depth)], 1, count=SINGLE_RUNS)
                assert not sample.errors, sample.errors[:3]
                lat = sample.latencies_ms or [math.inf]
                cells.append(f"d{depth} {_percentile(lat, 0.5):6.1f}/{_percentile(lat, 0.95):6.1f}")
            print(f"  {label:<34} " + "  ".join(cells))
    finally:
        engine.dispose()


def test_the_worst_case_at_concurrent_clients(migrated: Engine, estate: dict[str, Any]) -> None:
    """Every layer, depths 1 to 3, over every focus, hubs included: printed, not asserted."""
    scope: MapScope = estate["scope"]
    work = [(focus, depth) for focus in estate["foci"].values() for depth in (1, 2, 3)]

    def read(conn: Connection, focus: str, depth: int) -> Any:
        return graph.neighbourhood(conn, focus=focus, scope=scope, depth=depth, layers=ALL_LAYERS)

    print("\nconcurrent clients, all layers, depths 1-3 over every focus:")
    for clients in CLIENTS:
        engine = _api_engine(clients)
        try:
            for condition, sample in _conditions(engine, read, work, clients, estate).items():
                print(f"  {clients:2d} clients {condition:<10} {sample.line()}")
        finally:
            engine.dispose()


# ---- the budget: a realistic mix ---------------------------------------------------------


@dataclass(frozen=True)
class Ask:
    """One request as the screen makes it (frontend/src/views/investigate/map/mapQuery.ts)."""

    focus: str
    depth: int = 1
    layers: tuple[str, ...] = DEFAULT_LAYERS
    group: dict[str, Any] | None = None
    offset: int = 0


def _realistic_mix(estate: dict[str, Any], conn: Connection) -> list[tuple[Ask]]:
    """100 requests, sampled by the clients: what a person does on the map. Opening or expanding an
    ordinary resource at depth 1 with the default layers (the screen's defaults), sometimes one hop
    further or every layer; now and then a hub, and a group's pages, nearly always the first."""
    scope: MapScope = estate["scope"]
    rng = random.Random(7)  # noqa: S311 - a fixed mix, not a secret
    ordinary = rng.sample(estate["ordinary"], 60)
    hubs = [uid for label, uid in estate["foci"].items() if label.startswith("hub")]
    groups = [
        g
        for hub in hubs
        for g in graph.neighbourhood(conn, focus=hub, scope=scope, depth=1, layers=ALL_LAYERS)[
            "groups"
        ]
    ]
    assert groups, "the hubs lost their groups"
    asks = [Ask(u) for u in ordinary[:60]]  # opened or expanded: both are one depth-1 read
    asks += [Ask(u, depth=2) for u in ordinary[:15]]
    asks += [Ask(u, layers=ALL_LAYERS) for u in ordinary[15:20]]
    asks += [Ask(hub) for hub in hubs for _ in range(2)]  # hubs: 6 requests with three hubs
    largest = sorted(groups, key=lambda g: -g["count"])[:3]
    asks += [Ask(g["anchor_uid"], group=g) for g in groups[:12]]
    asks += [Ask(g["anchor_uid"], group=g, offset=g["count"] - PAGE_SIZE) for g in largest[:2]]
    return [(ask,) for ask in asks]


def test_a_realistic_mix_stays_within_budget(migrated: Engine, estate: dict[str, Any]) -> None:
    scope: MapScope = estate["scope"]

    def read(conn: Connection, ask: Ask) -> Any:
        if ask.group:
            g = ask.group
            return graph.group_members(
                conn,
                anchor=g["anchor_uid"],
                scope=scope,
                direction=g["direction"],
                edge_type=g["edge_type"],
                resource_type=g["resource_type"],
                limit=PAGE_SIZE,
                offset=ask.offset,
            )
        return graph.neighbourhood(
            conn, focus=ask.focus, scope=scope, depth=ask.depth, layers=ask.layers
        )

    with migrated.connect() as conn:
        work = _realistic_mix(estate, conn)
    engine = _api_engine(BUDGET_CLIENTS)
    try:
        results = _conditions(engine, read, work, BUDGET_CLIENTS, estate)
    finally:
        engine.dispose()
    print(f"\nthe budget: {len(work)} requests in the mix, {BUDGET_CLIENTS} clients")
    for condition, sample in results.items():
        print(f"  {condition:<10} {sample.line()}")
        for error in sample.errors[:3]:
            print(f"      {error}")
    print(f"Memgraph after the budget: {_memgraph_memory()}")
    for condition, sample in results.items():
        assert sample.latencies_ms, f"no request completed during the {condition}"
        assert not sample.errors, sample.errors[:3]
        assert not sample.timeouts, condition
        assert _percentile(sample.latencies_ms, 0.95) <= P95_MS, condition
        assert _percentile(sample.latencies_ms, 0.99) <= P99_MS, condition


def _memgraph_memory() -> str:
    with client.driver().session() as session:
        info = {r["storage info"]: r["value"] for r in session.run("SHOW STORAGE INFO")}
    return f"memory_res {info.get('memory_res')}, peak_memory_res {info.get('peak_memory_res')}"
