"""The graph read model's budget (ADR-0044): how long Memgraph takes to be rebuilt from Postgres,
to re-sync one connection, to be verified, and to evaluate the attack paths across every
account (round M2), on a skewed estate (graph_estate.py: 300,000 resources over 36 accounts by
default). Phase 0 of round M3 adds what the evaluation costs graph-sync:
- where its time goes: kind targets, the walk in Memgraph, the cap, failing findings, scoring,
  storage
- how many paths it finds, keeps and cuts at MAX_PATHS, per entry connection
- its peak memory, measured in a process of its own, as graph-sync runs it (limit 1 GiB)
- what it writes (ADR-0044, amended 2026-11-02): nothing on a repeat, once a day to move last_seen,
  and a change in one account, which also proves a cut account still resolves
- storing every path found, with the cap lifted, three times: time, WAL, table size, dead rows
- Memgraph's own memory after the rebuild and after the evaluation

Opt-in, because it generates its own estate (minutes) and no API query reads the graph. It
needs a Postgres with more memory than compose.yaml's development 1 GiB (on 2026-10-31 a backend
was killed generating 300,000 resources there); the `budget` profile has one of 8 GiB:
    docker compose --profile budget run --rm budget
    ARGUS_GRAPH_BUDGET_RESOURCES=1000000 docker compose --profile budget run --rm budget
    docker compose --profile budget rm -sfv postgres-budget memgraph-budget   (afterwards)
"""

import os
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from datetime import date, timedelta
from multiprocessing import get_context
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text
from tests.budget import graph_estate
from tests.conftest import RULES_DIR

from argus import attackpaths, graph
from argus.attackpaths import engine as path_engine
from argus.core.db import get_engine
from argus.graph import client
from argus.graph import paths as graph_paths

pytestmark = [
    pytest.mark.db,
    pytest.mark.graph,
    pytest.mark.skipif(
        not os.environ.get("ARGUS_GRAPH_BUDGET"), reason="opt-in: ARGUS_GRAPH_BUDGET=1"
    ),
]
# Ceilings at the default 300,000 resources; scaled with the estate's size.
SCALE = graph_estate.RESOURCES / 300_000
REBUILD_S = 300 * SCALE
LARGEST_SYNC_S = 30 * SCALE
VERIFY_S = 60 * SCALE
EVALUATE_S = 300 * SCALE
# graph-sync's memory limit (charts/argus/values.yaml), with 20% left over.
GRAPH_SYNC_LIMIT_MIB = 1024
HEADROOM = 0.8
FULL_VOLUME_RUNS = 3


def _peak_mib() -> float:
    """This process's peak resident memory (VmHWM), in MiB."""
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1]) / 1024
    raise RuntimeError("no VmHWM in /proc/self/status")


def _timed(phases: dict[str, float], label: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    def timed(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        try:
            return fn(*args, **kwargs)
        finally:
            phases[label] = phases.get(label, 0.0) + time.perf_counter() - started

    return timed


def _evaluate_alone(max_paths: int | None, rules_dir: str, today: date) -> dict[str, Any]:
    """One evaluation in a fresh process, as graph-sync runs it. Returns its time and peak
    memory, the time of each phase, and the paths found, kept and cut per entry connection.
    Runs in a child: the patches below die with it."""
    if max_paths is not None:
        path_engine.MAX_PATHS = max_paths
    phases: dict[str, float] = {}
    counts: dict[str, Any] = {}
    for label, owner, name in (
        ("kind targets (Postgres)", attackpaths, "kind_targets"),
        ("walk (Memgraph) and rebuild", graph_paths, "_search"),
        ("failing findings (Postgres)", attackpaths, "failing_nodes"),
        ("assess", attackpaths, "assess"),
        ("stored ids (Postgres)", attackpaths, "stored_path_ids"),
        ("store, resolve, metrics (Postgres)", attackpaths, "store_paths"),
    ):
        setattr(owner, name, _timed(phases, label, getattr(owner, name)))
    cap = attackpaths.cap

    def counting_cap(paths: Any, *, stored: Any) -> Any:
        started = time.perf_counter()
        kept, cut = cap(paths, stored=stored)
        phases["cap"] = time.perf_counter() - started
        per_found = Counter(p.connection_id for p in paths)
        counts.update(
            found=sum(per_found.values()),
            kept=len(kept),
            cut=sum(n.total() for n in cut.values()),
            connections_cut=len(cut),
            most_found=per_found.most_common(3),
            most_cut=sorted(cut, key=lambda c: -cut[c].total())[:1],
        )
        return kept, cut

    attackpaths.cap = counting_cap
    baseline = _peak_mib()
    started = time.perf_counter()
    done = graph.evaluate_paths(get_engine(), today=today, rules_dir=Path(rules_dir))
    seconds = time.perf_counter() - started
    client.close()
    return {
        "seconds": seconds,
        "baseline_mib": baseline,
        "peak_mib": _peak_mib(),
        "phases": phases,
        "counts": counts,
        "done": done,
    }


def _in_child(max_paths: int | None, today: date = graph_estate.TODAY) -> dict[str, Any]:
    with ProcessPoolExecutor(max_workers=1, mp_context=get_context("spawn")) as pool:
        result: dict[str, Any] = pool.submit(
            _evaluate_alone, max_paths, str(RULES_DIR), today
        ).result()
        return result


def _memgraph_memory() -> str:
    with client.driver().session() as session:
        info = {r["storage info"]: r["value"] for r in session.run("SHOW STORAGE INFO")}
    return f"memory_res {info.get('memory_res')}, peak_memory_res {info.get('peak_memory_res')}"


def _report(label: str, run: dict[str, Any]) -> None:
    c = run["counts"]
    print(
        f"{label}: {run['seconds']:.1f} s, peak RSS {run['peak_mib']:.0f} MiB "
        f"(after imports {run['baseline_mib']:.0f} MiB); found {c.get('found', 0):,}, "
        f"kept {c.get('kept', 0):,}, cut {c.get('cut', 0):,} in "
        f"{c.get('connections_cut', 0)} connections; most found per entry connection "
        f"{c.get('most_found')}"
    )
    rest = run["seconds"] - sum(run["phases"].values())
    for phase, seconds in [*run["phases"].items(), ("the rest", rest)]:
        print(f"    {phase:<38} {seconds:7.1f} s")


def _table_state(engine: Engine) -> dict[str, Any]:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT pg_total_relation_size('attack_path') AS total,
                       pg_relation_size('attack_path') AS heap,
                       pg_indexes_size('attack_path') AS indexes,
                       s.n_live_tup, s.n_dead_tup, s.autovacuum_count, s.n_tup_upd, s.n_tup_hot_upd,
                       pg_current_wal_lsn() AS lsn
                FROM pg_stat_user_tables s WHERE s.relname = 'attack_path'
                """
            )
        ).one()
        return dict(row._mapping)


def _wal_bytes(engine: Engine, since: str) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), CAST(:l AS pg_lsn))"),
                {"l": str(since)},
            ).scalar_one()
        )


def _measured(engine: Engine, label: str, max_paths: int | None, today: date) -> dict[str, Any]:
    """One evaluation, what it took and what it wrote."""
    time.sleep(2)  # table statistics reach pg_stat_user_tables within a second
    before = _table_state(engine)
    run = _in_child(max_paths, today)
    run["wal_mib"] = _wal_bytes(engine, before["lsn"]) / 2**20
    time.sleep(2)
    after = _table_state(engine)
    run["updates"] = after["n_tup_upd"] - before["n_tup_upd"]
    done = run["done"]
    _report(label, run)
    print(
        f"    {done['new']:,} new, {done['changed']:,} changed, {done['resolved']:,} resolved; "
        f"WAL {run['wal_mib']:,.0f} MiB; {run['updates']:,} updates, "
        f"{after['n_tup_hot_upd'] - before['n_tup_hot_upd']:,} HOT; "
        f"{after['n_dead_tup']:,} dead rows"
    )
    return run


def _later_evaluations(engine: Engine, capped: dict[str, Any]) -> tuple[dict[str, Any], date]:
    """What later evaluations write (ADR-0044, amended 2026-11-02): nothing on a repeat, every path
    once a day for last_seen, and only what changed when one account changes."""
    paths = capped["done"]
    repeat = _measured(engine, "the same day again, nothing changed", None, graph_estate.TODAY)
    assert (repeat["done"]["new"], repeat["done"]["changed"], repeat["done"]["resolved"]) == (
        0,
        0,
        0,
    )
    assert repeat["updates"] == 0
    tomorrow = graph_estate.TODAY + timedelta(days=1)
    daily = _measured(engine, "the next day: last_seen moves once", None, tomorrow)
    assert daily["done"]["changed"] == paths["paths"]
    # An account with paths past the cap loses internet entries: its paths from there resolve.
    cut_account = capped["counts"]["most_cut"][0]
    with client.write_session() as session:
        session.run(
            "MATCH (:R {uid: 'internet'})-[r]->(t:R) WHERE t.conn = $c "
            "WITH r, t ORDER BY t.uid LIMIT 50 DELETE r",
            {"c": cut_account},
        ).consume()
    changed = _measured(engine, f"one account changed ({cut_account})", None, tomorrow)
    assert changed["done"]["resolved"] > 0
    assert changed["updates"] < paths["paths"] / 2
    return daily, tomorrow


def test_rebuild_resync_verify_and_paths_within_budget(migrated: Engine) -> None:
    print(f"\nestate: {graph_estate.prepare(migrated)}")
    with client.write_session() as session:
        session.run("MATCH (n) DETACH DELETE n").consume()

    started = time.perf_counter()
    done = graph.reconcile(migrated, today=graph_estate.TODAY)
    rebuild = time.perf_counter() - started
    assert done == {"synced": graph_estate.ACCOUNTS, "failed": 0, "removed": 0}
    with migrated.connect() as conn:
        # Every account projected with its inventory, not as bare stubs (an estate without
        # resource_load rows did that unnoticed until 2026-11-01).
        assert not conn.execute(
            text("SELECT count(*) FROM graph_projection WHERE node_count = 0")
        ).scalar_one()
    after_rebuild = _memgraph_memory()

    started = time.perf_counter()
    assert graph.reconcile(migrated, today=graph_estate.TODAY) == {
        "synced": 0,
        "failed": 0,
        "removed": 0,
    }
    noop = time.perf_counter() - started

    with migrated.begin() as conn:
        largest, edges = conn.execute(
            text(
                "SELECT connection_id, edge_count FROM graph_projection "
                "ORDER BY edge_count DESC LIMIT 1"
            )
        ).one()
        conn.execute(
            text(
                "UPDATE graph_projection SET status = 'failed', error = 'budget' "
                "WHERE connection_id = :c"
            ),
            {"c": largest},
        )
    started = time.perf_counter()
    graph.reconcile(migrated, today=graph_estate.TODAY)
    resync = time.perf_counter() - started

    started = time.perf_counter()
    assert graph.verify(migrated, today=graph_estate.TODAY) == {
        "checked": graph_estate.ACCOUNTS,
        "drifted": 0,
    }
    verify = time.perf_counter() - started

    # The evaluation as graph-sync runs it, with today's cap: a process of its own.
    capped = _in_child(None)
    paths = capped["done"]
    assert paths is not None and paths["paths"] > 0
    after_evaluation = _memgraph_memory()
    with migrated.connect() as conn:
        crossing = conn.execute(
            text("SELECT count(*) FROM attack_path WHERE cardinality(connection_ids) > 1")
        ).scalar_one()

    print(
        f"graph budget at {graph_estate.RESOURCES:,} resources: full rebuild {rebuild:.1f} s, "
        f"no-op reconcile {noop:.2f} s, re-sync of the largest connection ({edges:,} edges) "
        f"{resync:.1f} s, verify {verify:.1f} s, attack paths {capped['seconds']:.1f} s "
        f"({paths['paths']:,} paths, {crossing:,} across accounts, {paths['cut']:,} cut)"
    )
    print(f"Memgraph after the rebuild: {after_rebuild}; after the evaluation: {after_evaluation}")
    _report(f"evaluation, MAX_PATHS {path_engine.MAX_PATHS:,}", capped)
    assert capped["counts"]["found"] == paths["paths"] + paths["cut"]

    daily, tomorrow = _later_evaluations(migrated, capped)

    # Every path found stored (D3d: the cap's value is measured before it is decided).
    full = [
        _measured(migrated, f"full volume, evaluation {run + 1}", 10**9, tomorrow)
        for run in range(FULL_VOLUME_RUNS)
    ]
    time.sleep(2)  # table statistics reach pg_stat_user_tables within a second
    table = _table_state(migrated)
    print(
        f"attack_path after {FULL_VOLUME_RUNS} full evaluations: "
        f"{table['total'] / 2**20:,.0f} MiB ({table['heap'] / 2**20:,.0f} heap, "
        f"{table['indexes'] / 2**20:,.0f} indexes), {table['n_live_tup']:,} live and "
        f"{table['n_dead_tup']:,} dead rows, {table['autovacuum_count']} autovacuums"
    )

    assert rebuild < REBUILD_S
    assert resync < LARGEST_SYNC_S
    assert verify < VERIFY_S
    assert capped["seconds"] < EVALUATE_S
    assert capped["peak_mib"] < GRAPH_SYNC_LIMIT_MIB * HEADROOM
    assert daily["seconds"] < EVALUATE_S
    assert daily["peak_mib"] < GRAPH_SYNC_LIMIT_MIB * HEADROOM
    assert all(run["seconds"] < EVALUATE_S for run in full)
