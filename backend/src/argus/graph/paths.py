"""Attack paths over the graph read model, across accounts (ADR-0044, round M2).

One evaluation covers every projected connection: Memgraph holds each connection's latest scan
state (however old: scans may be 30 days apart), so a role another account can assume no longer
ends a path at the account boundary. It runs in the graph loop, after a reconcile that changed
Memgraph, under the graph lock, so Memgraph stays still while it reads. Scan Jobs and ingest
never evaluate paths.

    Memgraph (catalog)   the internet edges, the breadth-first walk from each seed, the moves
                         into the reached nodes, the security groups of the entries
    Postgres             each kind's targets and the failing findings (argus.attackpaths), on
                         the days graph_projection says each connection was projected from
    attackpaths          the search's rebuild, the path cap per entry connection, severity,
                         and the storage: upsert, resolve, path metrics

A path belongs to the account where the attacker gets in: the connection of the first node on it
that a connection owns, which is the entry's unless the entry is not inventoried (an outsider's
principal, an endpoint only CloudFox saw), else the connection that drew its internet edge. It
records every connection on it. A path the
evaluation no longer finds is resolved only when every connection on it is resolvable: projected
from its newest ingested run, with inventory and edge loads, its newest Steampipe and CloudFox
runs complete, and none of its paths cut by the cap. A partial run, a failed sync or a disabled
account never looks like a fix.

graph_projection records the run each connection's paths were evaluated from (paths_run_id) and
when; paths_state() compares it with the newest ingested run, so Attack paths says when its
paths are behind the scans (owner's decision, 2026-11-01).
"""

import logging
import time
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, Engine, text

from argus import attackpaths, connections, ingest
from argus.attackpaths import Chain, Step
from argus.core.config import get_settings
from argus.graph import client
from argus.graph.projection import graph_uid, postgres_uid, try_lock, unlock

log = logging.getLogger(__name__)
SEED_BATCH = 500
NODE_BATCH = 10_000
# Behind the scans for longer than the loop explains (a tick, the integrity check, a full rebuild
# of a large estate): the graph is not catching up, it has failed (Memgraph down, a sync error).
STALLED_AFTER = "10 minutes"
DAY_KEYS = ("resource_day", "rule_day", "cloudfox_day")

_STATE_SQL = f"""
  SELECT g.connection_id, c.account_id, g.source_run_id, g.status, g.resource_day, g.rule_day,
         g.cloudfox_day, r.run_id AS latest_run_id
  FROM graph_projection g
  JOIN ({connections.DIRECTORY_SQL}) c ON c.id = g.connection_id
  LEFT JOIN ({ingest.LATEST_INGESTED_RUNS_SQL}) r ON r.connection_id = g.connection_id
"""  # noqa: S608 - exported SQL only
_STAMP_SQL = """
  UPDATE graph_projection SET paths_run_id = source_run_id, paths_evaluated_at = now()
  WHERE connection_id = ANY(CAST(:cs AS bigint[])) AND status = 'synced'
"""
_PATHS_STATE_SQL = f"""
  SELECT c.id, r.run_id, r.ingested_at < now() - CAST(:stalled AS interval) AS stalled,
         g.status, g.paths_run_id, g.paths_evaluated_at
  FROM ({connections.DIRECTORY_SQL}) c
  JOIN ({ingest.LATEST_INGESTED_RUNS_SQL}) r ON r.connection_id = c.id
  LEFT JOIN graph_projection g ON g.connection_id = c.id
  WHERE c.enabled AND (CAST(:c AS bigint) IS NULL OR c.id = :c)
"""  # noqa: S608 - exported SQL only


def _batches(items: list[str], size: int) -> Iterator[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _state(conn: Connection) -> tuple[dict[int, Any], dict[int, dict[str, str]]]:
    """graph_projection with each connection's newest ingested run, and its newest edge runs'
    statuses ({connection: {tool: status}})."""
    rows = {r.connection_id: r for r in conn.execute(text(_STATE_SQL))}
    edge_runs: dict[int, dict[str, str]] = {}
    for r in conn.execute(text(ingest.LATEST_EDGE_RUNS_SQL)):
        edge_runs.setdefault(r.connection_id, {})[r.tool] = r.status
    return rows, edge_runs


def _as_postgres(chain: Chain) -> Chain:
    """A chain with Postgres's uids: an account's wildcard pseudo-node loses the account the
    graph gave it (projection.graph_uid), so path_id and node_uids are as before M2."""
    steps = tuple(
        replace(s, source_uid=postgres_uid(s.source_uid), target_uid=postgres_uid(s.target_uid))
        for s in chain.steps
    )
    return Chain(postgres_uid(chain.entry_uid), postgres_uid(chain.target_uid), steps)


Found = tuple[dict[str, list[Chain]], dict[str, int | None], dict[int | None, dict[str, Step]]]


def _search(targets: attackpaths.Targets) -> Found:
    """The chains of every kind over the whole graph, the connection of each node seen, and each
    connection's own best internet step per entry."""
    entry_steps = []
    conns: dict[str, int | None] = {}
    for row in client.read("internet_edges"):
        entry_steps.append(attackpaths.step(row))
        conns[row["target"]] = row["target_conn"]
    seeds = attackpaths.entries(entry_steps)
    by_conn: dict[int | None, list[Step]] = defaultdict(list)
    for s in entry_steps:
        by_conn[s.conn].append(s)
    own_entries = {c: attackpaths.entries(steps) for c, steps in by_conn.items()}
    reached: dict[str, dict[str, int]] = {seed: {seed: 0} for seed in seeds}
    for batch in _batches(sorted(seeds), SEED_BATCH):
        for row in client.read("reached_from", seeds=batch):
            depth = reached[row["seed"]]
            for uid, steps_away, conn in row["reached"]:
                if uid not in depth or steps_away < depth[uid]:
                    depth[uid] = int(steps_away)
                conns.setdefault(uid, conn)
    nodes = sorted({n for depths in reached.values() for n in depths})
    known = set(nodes)
    moves: list[Step] = []
    for batch in _batches(nodes, NODE_BATCH):
        moves += [
            attackpaths.step(row)
            for row in client.read("moves_into", nodes=batch)
            if row["source"] in known
        ]
    found = attackpaths.rebuild(seeds, reached, attackpaths.incoming(moves), targets)
    return found, conns, own_entries


def evaluate_paths(
    engine: Engine, *, today: date | None = None, rules_dir: Path | None = None
) -> dict[str, int] | None:
    """One evaluation over every projected connection, dated `today` (UTC). Returns what it did,
    or None when another process holds the graph lock."""
    today = today or datetime.now(UTC).date()
    rules_dir = rules_dir or get_settings().rules_dir
    lock = try_lock(engine)
    if lock is None:
        return None
    try:
        return _evaluate(engine, today=today, rules_dir=rules_dir)
    finally:
        unlock(lock)


def _evaluate(engine: Engine, *, today: date, rules_dir: Path) -> dict[str, int]:
    started = time.perf_counter()
    kinds = attackpaths.load_path_kinds(rules_dir)
    with engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        rows, edge_runs = _state(conn)
        synced = sorted(c for c, r in rows.items() if r.status == "synced")
        days = {c: {k: getattr(rows[c], k) for k in DAY_KEYS} for c in synced}
        account_of = {c: rows[c].account_id for c in synced}
        targets = attackpaths.kind_targets(
            conn, kinds=kinds, days=days, scope=lambda c, uid: graph_uid(uid, account_of[c])
        )
        conn.rollback()

    found, conns, own_entries = _search(targets)

    def owner(chain: Chain) -> int:
        for uid in chain.node_uids[1:]:  # the entry first, then where the path goes
            owned = conns.get(uid)
            if owned is not None:
                return owned
        drawn_by = chain.steps[0].conn  # the connection whose rules or CloudFox saw the door
        if drawn_by is None:
            raise ValueError(f"no connection owns the entry {chain.entry_uid!r}")
        return drawn_by

    def accounts(chain: Chain) -> list[int]:
        seen = [owner(chain)]
        for s in chain.steps:
            for c in (s.conn, conns.get(s.target_uid)):
                if c is not None and c not in seen:
                    seen.append(c)
        return seen

    def own_entry(chain: Chain) -> Chain:
        """An entry several accounts' rules draw (an outsider trusted in each) keeps the owner's
        internet step when it is as sure as the one chosen, so the path does not list an account
        it never enters."""
        first = chain.steps[0]
        mine = own_entries.get(owner(chain), {}).get(chain.entry_uid)
        if mine is None or mine.id == first.id or mine.rank[:2] != first.rank[:2]:
            return chain
        return Chain(chain.entry_uid, chain.target_uid, (mine, *chain.steps[1:]))

    capped, cut = attackpaths.cap(found, owner)
    chains = {kind: [_as_postgres(own_entry(c)) for c in cs] for kind, cs in capped.items()}
    for connection_id, n in sorted(cut.items()):
        log.warning("attack paths cut at the cap", extra={"connection": connection_id, "cut": n})
    entry_uids = sorted({c.entry_uid for cs in chains.values() for c in cs})
    groups: dict[str, set[str]] = {}
    for batch in _batches(entry_uids, NODE_BATCH):
        for row in client.read("member_groups", entries=batch):
            groups.setdefault(row["entry"], set()).add(row["grp"])
    on_path = {uid for cs in chains.values() for c in cs for uid in c.node_uids}
    on_path |= {g for gs in groups.values() for g in gs}

    resolvable = [
        c
        for c in synced
        if rows[c].source_run_id == rows[c].latest_run_id
        and all(days[c][k] is not None for k in DAY_KEYS)
        and edge_runs.get(c, {}).get("steampipe") == "complete"
        and edge_runs.get(c, {}).get("cloudfox") == "complete"
        and c not in cut
    ]
    counted = [c for c in synced if days[c]["rule_day"] or days[c]["cloudfox_day"]]
    with engine.begin() as conn:
        # Every connection that owns a node, a failed sync's too: its findings are in Postgres.
        owners = sorted(set(synced) | {c for c in conns.values() if c is not None})
        failing = attackpaths.failing_nodes(conn, connection_ids=owners, uids=sorted(on_path))
        paths = attackpaths.assess(
            kinds, chains, failing=failing, groups=groups, owner=owner, accounts=accounts
        )
        stored = attackpaths.store_paths(
            conn, paths=paths, day=today, resolvable=resolvable, counted=counted
        )
        conn.execute(text(_STAMP_SQL), {"cs": synced})
    done = {**stored, "cut": sum(cut.values()), "connections": len(synced)}
    log.info(
        "attack paths evaluated",
        extra={
            **done,
            "day": today.isoformat(),
            "seconds": round(time.perf_counter() - started, 1),
        },
    )
    return done


def paths_state(conn: Connection, *, connection_id: int | None = None) -> dict[str, Any]:
    """Whether the attack paths of one connection (None: every enabled one with data) are behind
    its scans: `behind` when a connection's paths were not evaluated from its newest ingested
    run, `failed` when its graph sync failed or it has been behind for STALLED_AFTER (Memgraph
    down fails no sync, but nothing catches up), `evaluated_at` the oldest evaluation among them
    (None: never evaluated). Postgres only: the API reads it."""
    rows = conn.execute(
        text(_PATHS_STATE_SQL), {"c": connection_id, "stalled": STALLED_AFTER}
    ).all()
    evaluated = [r.paths_evaluated_at for r in rows if r.paths_evaluated_at is not None]
    behind = [r for r in rows if r.paths_run_id is None or r.paths_run_id != r.run_id]
    return {
        "evaluated_at": min(evaluated) if evaluated else None,
        "behind": bool(behind),
        "failed": any(r.status == "failed" for r in rows) or any(r.stalled for r in behind),
    }
