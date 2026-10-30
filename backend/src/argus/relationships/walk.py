"""A bounded walk over edges, in SQL (CLAUDE.md: multi-hop queries are recursive SQL with a depth
limit, run in ingest).

walk() follows a set of moves, given as a query of (source_uid, target_uid) rows, from each seed
up to max_depth steps, and returns each node a seed reaches with its fewest steps. A cycle ends
because every row is one step deeper and the depth is capped; rows are bounded by seeds x nodes x
depth (UNION drops repeats). Flow mode uses it (ADR-0036); the attack-path search is meant to.
"""

from typing import Any

from sqlalchemy import Connection, text

_WALK = """
WITH RECURSIVE t AS ({moves}),
w(seed, node, depth) AS (
  SELECT s, s, 0 FROM unnest(CAST(:seeds AS text[])) AS s
  UNION
  SELECT w.seed, t.target_uid, w.depth + 1
  FROM w JOIN t ON t.source_uid = w.node
  WHERE w.depth < :max_depth
)
SELECT seed, node, min(depth) AS depth FROM w GROUP BY seed, node
"""


def walk(
    conn: Connection,
    *,
    moves_sql: str,
    params: dict[str, Any],
    seeds: list[str],
    max_depth: int,
) -> dict[str, dict[str, int]]:
    """{seed: {node: fewest steps}}, the seed itself at 0. moves_sql is a fixed query of the
    caller's module, never input."""
    reached: dict[str, dict[str, int]] = {seed: {seed: 0} for seed in seeds}
    if not seeds:
        return reached
    rows = conn.execute(
        text(_WALK.format(moves=moves_sql)),
        {**params, "seeds": seeds, "max_depth": max_depth},
    )
    for r in rows:
        reached.setdefault(r.seed, {})[r.node] = int(r.depth)
    return reached
