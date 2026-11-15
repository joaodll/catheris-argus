"""Writing routes: only what changed, inside the evaluation's one transaction (ADR-0052 §2, M2).

- A route found for the first time is inserted, open.
- A route found again keeps its row; its targets are rewritten only when its digest changed,
  and the first evaluation of a day moves its Last seen. A fixed route found again reopens.
- A route no longer found is fixed only when every connection it crosses has complete newest
  runs (§4, H1). Steampipe and CloudFox are always required. For a kind with moves, Prowler and
  the vulnerabilities collector are required too, wherever they have run, because footholds,
  triggers and kind 6 read their findings. A route that is not fixed keeps its crossed set.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlalchemy import Connection, text

from argus.attackpaths.kinds import RouteKind
from argus.attackpaths.routes import FoundRoute, FoundTarget

ALWAYS = ("steampipe", "cloudfox")
WHERE_RUN = ("prowler", "vulnerabilities")
# (connection id, tool) -> (newest ingested run id, its status)
Runs = Mapping[tuple[int, str], tuple[int, str]]


@dataclass
class Written:
    routes: int = 0
    opened: int = 0
    changed: int = 0
    resolved: int = 0


def resolvable(
    crossed: list[int], kind: RouteKind | None, runs: Runs, existing: set[int] | None = None
) -> bool:
    """Whether a route no longer found counts as fixed: every connection it crosses has
    complete newest runs of the tools it reads. A kind gone from this release reads them all.
    A connection deleted since (not in `existing`) has no runs and no edges: it blocks nothing."""
    moves = kind is None or kind.entry != "only"
    for c in crossed:
        if existing is not None and c not in existing:
            continue
        for tool in ALWAYS:
            if runs.get((c, tool), (0, ""))[1] != "complete":
                return False
        if moves:
            for tool in WHERE_RUN:
                run = runs.get((c, tool))
                if run is not None and run[1] != "complete":
                    return False
    return True


def _target_row(route_id: int, seq: int, severity: str, t: FoundTarget) -> dict[str, Any]:
    s = t.steps
    return {
        "r": route_id,
        "q": seq,
        "tu": t.target,
        "ti": t.target_id,
        "sev": severity,
        "cls": t.cls,
        "lk": t.likelihood,
        "st": [x.type for x in s],
        "su": [x.source for x in s],
        "tg": [x.target for x in s],
        "si": [x.source_id for x in s],
        "di": [x.target_id for x in s],
        "ei": [x.id for x in s],
        "og": [x.origin for x in s],
        "cn": [x.conn for x in s],
        "dy": [x.day for x in s],
        "lv": [x.level for x in s],
        "rs": [x.reason for x in s],
        "rf": [x.ref for x in s],
    }


_INSERT_TARGET = text("""
    INSERT INTO route_target (route_id, seq, target_uid, target_resource_id, severity, class,
      likelihood, step_type, step_source_uid, step_target_uid, step_source_id, step_target_id,
      step_edge_id, step_origin, step_connection_id, step_day, step_level, step_reason, step_ref)
    VALUES (:r, :q, :tu, :ti, :sev, :cls, :lk, CAST(:st AS text[]), CAST(:su AS text[]),
      CAST(:tg AS text[]), CAST(:si AS bigint[]), CAST(:di AS bigint[]), CAST(:ei AS bigint[]),
      CAST(:og AS text[]), CAST(:cn AS bigint[]), CAST(:dy AS date[]), CAST(:lv AS text[]),
      CAST(:rs AS text[]), CAST(:rf AS text[]))
""")
_INSERT_NODES = text("""
    INSERT INTO route_node (route_id, resource_id)
    SELECT :r, n FROM unnest(CAST(:n AS bigint[])) AS n ON CONFLICT DO NOTHING
""")


def _children(conn: Connection, items: list[tuple[int, FoundRoute]]) -> None:
    """Insert each route's listed targets and the resources on their steps."""
    targets: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    for route_id, r in items:
        listed = r.listed()
        ids = {r.entry.target_id}
        for seq, t in enumerate(listed, start=1):
            targets.append(_target_row(route_id, seq, r.kind.severity, t))
            for s in t.steps:
                ids.update((s.source_id, s.target_id))
        nodes.append({"r": route_id, "n": sorted(i for i in ids if i is not None)})
    if targets:
        conn.execute(_INSERT_TARGET, targets)
    if nodes:
        conn.execute(_INSERT_NODES, nodes)


_EXISTING = text("""
    SELECT id, kind, entry_uid, digest, state, last_seen, crossed_connection_ids AS crossed
    FROM route
""")
_INSERT_ROUTE = text("""
    INSERT INTO route (kind, entry_uid, entry_resource_id, connection_id,
      crossed_connection_ids, severity, worst_class, target_count, listed_count, first_seen,
      last_seen, state, digest)
    VALUES (:k, :e, :ei, :c, CAST(:x AS bigint[]), :sev, :cls, :n, :ln, :d, :d, 'open', :dg)
    RETURNING id
""")
_UPDATE_ROUTE = text("""
    UPDATE route SET entry_resource_id = :ei, connection_id = :c,
      crossed_connection_ids = CAST(:x AS bigint[]), severity = :sev, worst_class = :cls,
      target_count = :n, listed_count = :ln, last_seen = :d, digest = :dg,
      state = CASE WHEN state = 'resolved' THEN 'reopened' ELSE state END, resolved_on = NULL
    WHERE id = :id
""")
_STAMP = text("UPDATE route SET last_seen = :d WHERE id = ANY(CAST(:ids AS bigint[]))")
_RESOLVE = text("""
    UPDATE route SET state = 'resolved', resolved_on = :d WHERE id = ANY(CAST(:ids AS bigint[]))
""")
_CLEAR = (
    text("DELETE FROM route_target WHERE route_id = ANY(CAST(:ids AS bigint[]))"),
    text("DELETE FROM route_node WHERE route_id = ANY(CAST(:ids AS bigint[]))"),
)


def _header(r: FoundRoute, today: date) -> dict[str, Any]:
    return {
        "k": r.kind.id,
        "e": r.entry_uid,
        "ei": r.entry.target_id,
        "c": r.connection_id,
        "x": r.crossed_ids(),
        "sev": r.kind.severity,
        "cls": r.worst_class,
        "n": r.count,
        "ln": len(r.targets),
        "d": today,
        "dg": r.digest(),
    }


def write(
    conn: Connection,
    found: list[FoundRoute],
    *,
    kinds: Mapping[str, RouteKind],
    runs: Runs,
    today: date,
    existing: set[int] | None = None,
) -> Written:
    """Apply one evaluation's routes. The caller's transaction holds every write, so a failure
    before its commit leaves the stored routes as they were (§9 M2)."""
    stored = {(r.kind, r.entry_uid): r for r in conn.execute(_EXISTING)}
    out = Written(routes=len(found))
    inserted: list[tuple[int, FoundRoute]] = []
    rewrite: list[tuple[int, FoundRoute]] = []
    stamp: list[int] = []
    for r in found:
        row = stored.pop((r.kind.id, r.entry_uid), None)
        if row is None:
            route_id = conn.execute(_INSERT_ROUTE, _header(r, today)).scalar_one()
            inserted.append((route_id, r))
            out.opened += 1
        elif row.state == "resolved" or bytes(row.digest) != r.digest():
            rewrite.append((row.id, r))
            out.opened += row.state == "resolved"
            out.changed += row.state != "resolved"
        elif row.last_seen < today:
            stamp.append(row.id)
    if rewrite:
        ids = [i for i, _ in rewrite]
        for clear in _CLEAR:
            conn.execute(clear, {"ids": ids})
        conn.execute(_UPDATE_ROUTE, [{**_header(r, today), "id": i} for i, r in rewrite])
    _children(conn, inserted + rewrite)
    if stamp:
        conn.execute(_STAMP, {"d": today, "ids": stamp})
    gone = [
        row.id
        for row in stored.values()
        if row.state != "resolved"
        and resolvable(list(row.crossed), kinds.get(row.kind), runs, existing)
    ]
    if gone:
        conn.execute(_RESOLVE, {"d": today, "ids": gone})
    out.resolved = len(gone)
    return out


def purge_resolved(conn: Connection, *, cutoff: date) -> int:
    """Retention (§9 L1): fixed routes fixed before the history kept, their targets and nodes
    with them (ON DELETE CASCADE)."""
    deleted: int = conn.execute(
        text("DELETE FROM route WHERE state = 'resolved' AND resolved_on < :c"), {"c": cutoff}
    ).rowcount
    return deleted
