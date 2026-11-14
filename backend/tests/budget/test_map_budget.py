"""The Resource map's budget (ADR-0051): the map's reads at 300,000 resources, as the API makes
them, from several clients at once, idle and during an ingest.

The map is the product's only read that follows edges, and Postgres is its only database, so
this is the measurement the decision rests on. A request reads one hop. The query budget
(test_query_budget.py) times each map read alone; this file times what the screen does:

- a realistic mix of 100 requests, sampled by 8 clients: mostly a resource opened or expanded
  with the default layers, a fifth of them at three hops on either map, sometimes every layer,
  now and then a hub, and a group's pages. It must stay under 300 ms at p95 and 1 s at p99,
  with no timeout.
- the same mix while a writer reloads one account after another the way ingest does: every
  resource, snapshot row, edge and finding of the account written again in one transaction,
  committed, then the day's partitions analysed. It writes the values already there, so the
  estate is the same afterwards.
- the hubs alone, and then from 8 clients at once with every layer: printed, not asserted.

Three hops (owner, 2026-11-13): measured here on 2026-11-13 with a walk that went on through
every node, three hops with every layer from a resource beside the hubs took 296 ms at p50 and
390 ms at p95 with one client, and two hops 221 ms, against a 300 ms budget. The walk now stops
at pseudo-nodes and boundary nodes (relationships/graph.py), and test_the_hubs_alone times two
and three hops again on both maps; if three miss 300 ms, MAX_DEPTH goes to 2 (the owner's
fallback).

Clients are threads of one process, as requests are in one API process, and read as argus_api
with its 5 s statement timeout. The estate is the query budget's (conftest.py). A map read is
for one connection, so its hubs are what connection 1 holds: a VPC with 20,000 members (the
largest hub, the size the first map was measured at), `internet` reaching 5,000 of its
resources (by a rule and by CloudFox), and 1,666 each in the hub VPC and with the managed
policy.
"""

import math
import random
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.exc import OperationalError
from tests.budget.conftest import settle
from tests.budget.test_query_budget import ACCOUNTS, HUB_BIG_VPC, HUB_POLICY, HUB_VPC, TODAY

from argus import relationships
from argus.core.config import get_settings
from argus.core.db import CONNECT_ARGS
from argus.relationships import DEFAULT_LAYERS, Map, MapScope

pytestmark = [pytest.mark.db, pytest.mark.budget]
P95_MS = 300.0
P99_MS = 1000.0
ALL_LAYERS = ("traffic", "identity", "network", "policy", "data")
CLIENTS = 8
REQUESTS = 100  # per client, when idle
WARM_UP = 2  # unrecorded requests per client before each measurement
SINGLE_RUNS = 10
PAGE_SIZE = 20  # the API's default page (api/routes/resource_map.py)
INGEST_SECONDS = 20.0  # at least this long, and until one account has committed and been analysed
INGEST_LIMIT_SECONDS = 600.0  # a writer slower than this fails the test

HUB = MapScope(1, "200000000001")  # the account `internet` reaches
PLAIN = MapScope(7, "200000000007")  # an account with no internet line
HUBS = {
    "internet": "internet",
    "a VPC of 20,000": HUB_BIG_VPC,
    "the hub VPC": HUB_VPC,
    "the managed policy": HUB_POLICY,
}


def _uid(g: int) -> str:
    """Resource g's uid, as the generator writes it (test_query_budget.RESOURCE_UID)."""
    return f"arn:aws:ec2:us-east-1:{200000000000 + 1 + g % ACCOUNTS}:instance/i-{g}"


def _percentile(samples: list[float], p: float) -> float:
    """Nearest rank, never interpolated past the slowest sample."""
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(p * len(ordered)) - 1)]


def _api_engine(size: int) -> Engine:
    """Connections as the API's role, with its statement timeout (a role setting, which SET
    ROLE does not apply)."""
    engine = create_engine(
        get_settings().database_url(), connect_args=CONNECT_ARGS, pool_size=size, max_overflow=0
    )

    @event.listens_for(engine, "connect")
    def _as_api(dbapi_conn: Any, _record: Any) -> None:
        with dbapi_conn.cursor() as cur:
            cur.execute("SET ROLE argus_api")
            cur.execute("SET statement_timeout = '5s'")
        dbapi_conn.commit()  # outside a transaction, so the pool's reset keeps both

    return engine


@dataclass
class Sample:
    latencies_ms: list[float] = field(default_factory=list)
    timeouts: int = 0
    errors: list[str] = field(default_factory=list)
    # What each timed-out request asked for, so a failure says which reads were slow.
    timed_out: list[str] = field(default_factory=list)

    def line(self) -> str:
        if not self.latencies_ms:
            return f"no requests, {self.timeouts} timeouts, {len(self.errors)} errors"
        return (
            f"{len(self.latencies_ms):5d} requests  p50 {_percentile(self.latencies_ms, 0.5):7.1f}"
            f"  p95 {_percentile(self.latencies_ms, 0.95):7.1f}"
            f"  p99 {_percentile(self.latencies_ms, 0.99):7.1f} ms"
            f"  {self.timeouts} timeouts, {len(self.errors)} errors"
        )


@dataclass(frozen=True)
class Ask:
    """One request as the screen makes it (frontend/src/views/investigate/map/mapQuery.ts)."""

    focus: str
    scope: MapScope
    layers: tuple[str, ...] = DEFAULT_LAYERS
    depth: int = 1
    kind: Map = "resource"
    group: dict[str, Any] | None = field(default=None, hash=False)
    offset: int = 0


def _label(ask: Ask) -> str:
    """A request in words: which focus (a hub by name), which layers, a group page."""
    hub = next((name for name, uid in HUBS.items() if uid == ask.focus), None)
    owner = "connection 1" if ask.scope == HUB else "connection 7"
    focus = hub or f"a resource of {owner}"
    if ask.group is not None:
        return f"{focus}: a group page, offset {ask.offset}"
    hops = "" if ask.depth == 1 else f", {ask.depth} hops, {ask.kind} map"
    return f"{focus}: {'every layer' if ask.layers == ALL_LAYERS else 'default layers'}{hops}"


def _read(conn: Connection, ask: Ask) -> Any:
    if ask.group is not None:
        g = ask.group
        return relationships.group_members(
            conn,
            anchor=g["anchor_uid"],
            scope=ask.scope,
            direction=g["direction"],
            edge_type=g["edge_type"],
            resource_type=g["resource_type"],
            day=TODAY,
            limit=PAGE_SIZE,
            offset=ask.offset,
        )
    return relationships.neighbourhood(
        conn,
        focus=ask.focus,
        scope=ask.scope,
        day=TODAY,
        layers=ask.layers,
        depth=ask.depth,
        kind=ask.kind,
    )


def _client(
    engine: Engine,
    work: list[Ask],
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
        ask = work[rng.randrange(len(work))]
        started = time.perf_counter()
        try:
            with engine.connect() as conn:
                _read(conn, ask)
            ms = (time.perf_counter() - started) * 1000
            with lock:
                sample.latencies_ms.append(ms)
        except OperationalError as e:
            with lock:
                if "timeout" in str(e).lower() or "canceling statement" in str(e).lower():
                    sample.timeouts += 1
                    sample.timed_out.append(_label(ask))
                else:
                    sample.errors.append(f"{type(e).__name__}: {str(e)[:200]}")
        except Exception as e:  # recorded: one failing request must not hide the others
            with lock:
                sample.errors.append(f"{type(e).__name__}: {str(e)[:200]}")
        done += 1


def _drive(
    engine: Engine,
    work: list[Ask],
    clients: int,
    *,
    count: int | None = None,
    until: threading.Event | None = None,
    warm: bool = True,
) -> Sample:
    """`clients` threads sending requests, `count` each or until `until` is set. First, unless
    `warm` is False, WARM_UP unrecorded requests each, so the pool holds its connections, as
    a running API's does."""
    if warm:
        _drive(engine, work, clients, count=WARM_UP, warm=False)
    sample, lock = Sample(), threading.Lock()
    threads = [
        threading.Thread(
            target=_client,
            args=(engine, work, 1000 + i, sample, lock),
            kwargs={"count": count, "until": until},
        )
        for i in range(clients)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sample


# ---- an ingest, as the worker writes one ---------------------------------------------------

# One account's Steampipe run and what follows it, in ingest's order and in one transaction
# (inventory/load.py, relationships/engine.load_edges, findings' lifecycle): every row of the
# account is written again with the values it has, so the load is real and the estate is not
# changed. `day` is the day the account's snapshots are on.
_RELOAD = (
    "UPDATE resource SET last_seen = last_seen WHERE connection_id = :c",
    """DELETE FROM resource_snapshot s USING resource r
       WHERE s.resource_id = r.id AND s.snapshot_date = :day AND r.connection_id = :c""",
    """INSERT INTO resource_snapshot (snapshot_date, resource_id, config_id)
       SELECT :day, r.id, (SELECT min(id) FROM resource_config)
       FROM resource r WHERE r.connection_id = :c""",
    "UPDATE edge SET last_seen = last_seen WHERE connection_id = :c",
    """DELETE FROM edge_snapshot es USING edge e
       WHERE es.edge_id = e.id AND es.snapshot_date = :d AND e.connection_id = :c""",
    """INSERT INTO edge_snapshot (snapshot_date, edge_id)
       SELECT :d, id FROM edge WHERE connection_id = :c ON CONFLICT DO NOTHING""",
    "UPDATE finding SET last_seen = last_seen WHERE connection_id = :c",
)


def _ingest(
    engine: Engine, stop: threading.Event, done: list[tuple[int, float]], failed: list[str]
) -> None:
    """Reloads account after account until told to stop, the hub account first. `done` gets
    each account and how long its load and ANALYZE took, once both have finished."""
    try:
        account = 0
        while not stop.is_set():
            connection_id = 1 + account % ACCOUNTS
            started = time.perf_counter()
            with engine.begin() as conn:
                day = conn.execute(
                    text("SELECT max(snapshot_date) FROM resource_load WHERE connection_id = :c"),
                    {"c": connection_id},
                ).scalar_one()
                for statement in _RELOAD:
                    conn.execute(text(statement), {"c": connection_id, "day": day, "d": TODAY})
            with engine.begin() as conn:  # after the load has committed, as ingest does
                conn.execute(text("SELECT argus_analyze_partitions(:d)"), {"d": TODAY})
            done.append((connection_id, time.perf_counter() - started))
            account += 1
    except Exception as e:  # reported by the test: a silent writer would pass as "idle"
        failed.append(f"{type(e).__name__}: {str(e)[:300]}")


def _during_an_ingest(estate: Engine, api: Engine, work: list[Ask], clients: int) -> Sample:
    """The mix while the writer runs. The readers go on until INGEST_SECONDS have passed and at
    least one account's load has committed and been analysed, so the window holds the whole
    of a load: its writes, its commit and its ANALYZE."""
    stop, done, failed = threading.Event(), [], []
    writer = threading.Thread(target=_ingest, args=(estate, stop, done, failed))
    until = threading.Event()

    def watch() -> None:
        deadline = time.perf_counter() + INGEST_LIMIT_SECONDS
        time.sleep(INGEST_SECONDS)
        while not done and not failed and time.perf_counter() < deadline:
            time.sleep(0.2)
        until.set()

    watcher = threading.Thread(target=watch)
    started = time.perf_counter()
    writer.start()
    watcher.start()
    try:
        sample = _drive(api, work, clients, until=until)
        read_for = time.perf_counter() - started
        within = list(done)  # the loads that finished while the map was read
    finally:
        until.set()
        stop.set()
        watcher.join()
        writer.join()
        settle(estate)  # the next budget module reads a steady state again
    assert not failed, failed
    assert within, f"no account's load committed within {INGEST_LIMIT_SECONDS:.0f} s of reading"
    loads = ", ".join(f"connection {c} in {seconds:.1f} s" for c, seconds in within)
    print(f"  (read for {read_for:.1f} s; loads committed and analysed meanwhile: {loads})")
    return sample


# ---- what is asked ---------------------------------------------------------------------------


def _realistic_mix(conn: Connection) -> list[Ask]:
    """100 requests: what a person does on the map. Opening a resource or expanding one of its
    neighbours with the default layers (the screen's defaults, and the same read), sometimes
    every layer; now and then a hub, and a group's pages, nearly always the first."""
    rng = random.Random(7)  # noqa: S311 - a fixed mix, not a secret
    # Connection 1's resources are g % 36 == 0, each a front door of the internet hub;
    # connection 7's are g % 36 == 6 and have no internet line.
    doors = [(_uid(g), HUB) for g in rng.sample(range(36, 180_000, 36), 40)]
    plain = [(_uid(g), PLAIN) for g in rng.sample(range(6, 300_000, 36), 40)]
    ordinary = [pair for both in zip(doors, plain, strict=True) for pair in both]
    groups = [
        g
        for hub in HUBS.values()
        for g in relationships.neighbourhood(
            conn, focus=hub, scope=HUB, day=TODAY, layers=ALL_LAYERS
        )["groups"]
    ]
    assert groups, "the hubs lost their groups"
    asks = [Ask(u, s) for u, s in ordinary[:55]]  # opened or expanded: one hop either way
    # A fifth at three hops, on either map (the Depth control).
    asks += [Ask(u, s, depth=3) for u, s in ordinary[55:65]]
    asks += [Ask(u, s, depth=3, kind="security") for u, s in ordinary[65:75]]
    asks += [Ask(u, s, layers=ALL_LAYERS) for u, s in ordinary[75:]]
    asks += [Ask(hub, HUB, layers=ALL_LAYERS) for hub in list(HUBS.values())[:3] for _ in range(2)]
    largest = sorted(groups, key=lambda g: -g["count"])[:2]
    pages = [groups[i % len(groups)] for i in range(12)]
    asks += [Ask(g["anchor_uid"], HUB, group=g) for g in pages]
    asks += [Ask(g["anchor_uid"], HUB, group=g, offset=g["count"] - PAGE_SIZE) for g in largest]
    assert len(asks) == 100
    return asks


# ---- the tests -------------------------------------------------------------------------------


def test_the_hubs_alone(estate: Engine) -> None:
    """One client, around each hub and two ordinary resources, with the default layers and
    with every layer: printed. Every one is a single request, so each must fit the budget."""
    foci = {label: (uid, HUB) for label, uid in HUBS.items()}
    foci["a front door"] = (_uid(36_000), HUB)  # in both hub VPCs, with the managed policy
    foci["an ordinary resource"] = (_uid(36_006), PLAIN)
    api = _api_engine(2)
    print(f"\none client, one hop (ms, p50 / p95 of {SINGLE_RUNS} runs):")
    try:
        for label, (focus, scope) in foci.items():
            cells = []
            for name, layers in (("default", DEFAULT_LAYERS), ("every layer", ALL_LAYERS)):
                sample = _drive(api, [Ask(focus, scope, layers=layers)], 1, count=SINGLE_RUNS)
                assert not sample.errors, sample.errors[:3]
                assert not sample.timeouts, (label, name)
                p95 = _percentile(sample.latencies_ms, 0.95)
                cells.append(f"{name} {_percentile(sample.latencies_ms, 0.5):6.1f}/{p95:6.1f}")
                assert p95 <= P95_MS, (label, name)
            print(f"  {label:<22} " + "  ".join(cells))
        print(f"\none client, every layer, deeper (ms, p50 / p95 of {SINGLE_RUNS} runs):")
        for label in ("a front door", "an ordinary resource"):
            focus, scope = foci[label]
            cells = []
            for depth in (2, 3):
                for kind in ("resource", "security"):
                    ask = Ask(focus, scope, layers=ALL_LAYERS, depth=depth, kind=kind)
                    sample = _drive(api, [ask], 1, count=SINGLE_RUNS)
                    assert not sample.errors, sample.errors[:3]
                    assert not sample.timeouts, (label, depth, kind)
                    p95 = _percentile(sample.latencies_ms, 0.95)
                    p50 = _percentile(sample.latencies_ms, 0.5)
                    cells.append(f"{depth} hops {kind} {p50:6.1f}/{p95:6.1f}")
                    assert p95 <= P95_MS, (label, depth, kind)
            print(f"  {label:<22} " + "  ".join(cells))
    finally:
        api.dispose()


def test_a_realistic_mix_stays_within_budget_idle_and_during_an_ingest(estate: Engine) -> None:
    with estate.connect() as conn:
        work = _realistic_mix(conn)
    api = _api_engine(CLIENTS)
    measure: dict[str, Callable[[], Sample]] = {
        "idle": lambda: _drive(api, work, CLIENTS, count=REQUESTS),
        "ingest": lambda: _during_an_ingest(estate, api, work, CLIENTS),
    }
    print(f"\nthe map's budget: {len(work)} requests in the mix, {CLIENTS} clients")
    results: dict[str, Sample] = {}
    try:
        for condition, run in measure.items():
            results[condition] = run()
            print(f"  {condition:<7} {results[condition].line()}")
            for error in results[condition].errors[:3]:
                print(f"      {error}")
            for label, count in Counter(results[condition].timed_out).most_common():
                print(f"      timed out {count}x: {label}")
    finally:
        api.dispose()
    for condition, sample in results.items():
        assert sample.latencies_ms, f"no request completed ({condition})"
        assert not sample.errors, sample.errors[:3]
        assert not sample.timeouts, condition
        assert _percentile(sample.latencies_ms, 0.95) <= P95_MS, condition
        assert _percentile(sample.latencies_ms, 0.99) <= P99_MS, condition


def test_the_worst_case_from_several_clients(estate: Engine) -> None:
    """Every layer around every hub, from 8 clients at once: printed, not asserted. Nobody
    uses the map like this; it bounds what a burst of hub requests costs."""
    work = [Ask(focus, HUB, layers=ALL_LAYERS) for focus in HUBS.values()]
    api = _api_engine(CLIENTS)
    try:
        sample = _drive(api, work, CLIENTS, count=20)
    finally:
        api.dispose()
    print(f"\nthe worst case, {CLIENTS} clients, hubs only: {sample.line()}")
    assert not sample.errors, sample.errors[:3]
    assert not sample.timeouts
