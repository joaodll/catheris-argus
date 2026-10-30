"""The attack-path search (ADR-0037): from every internet entry of one connection, the shortest
chain of attacker steps to what matters, whatever rule or tool drew each step.

    seeds   what the internet reaches: the targets of ROUTES_TO from `internet` (Argus's
            internet-entry), PUBLIC_UNVERIFIED (Argus cannot tell) and INTERNET_REACHABLE
            (CloudFox). What Argus's rules call restricted (PUBLIC_RESTRICTED) seeds through
            that edge alone, whatever CloudFox says: a closed door's paths are latent, their
            confidence blocked (ADR-0037, amended 2026-10-21). Also, from Argus's rules, a
            principal outsiders control (OUTSIDER) and a user whose credential may leak
            (HAS_CREDENTIAL; ADR-0037 second amendment, wave 2)
    moves   ROUTES_TO, TRIGGERS, RUNS_AS, CAN_ASSUME, IS_ADMIN, CAN_PRIVESC_TO, ACCESSES,
            CAN_ESCALATE_TO, CAN_CONNECT_TO and CAN_RUN_ON between resources (the effective
            edges of the day)
    targets each path kind's own query (backend/rules/attack_paths/<kind>.toml); a kind whose
            target is the entry itself (entry "only": an exposed door, ADR-0037 second
            amendment) is one step, one that may also be the entry ("too": a workload that is a
            door) is one step or more, every other kind ("never") takes at least one move

relationships.walk() (recursive SQL, depth-limited) finds the fewest steps from each seed to
every node it reaches; this module then rebuilds one path per (seed, target) backwards, one
step shallower at a time, taking the most confident edge when several fit (a rule's edge
before CloudFox's for the same step). A kind may name the types its last step must have
(lateral movement ends with CAN_CONNECT_TO). Read-only: the caller writes the paths.
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import Connection, text

from argus import relationships
from argus.attackpaths.confidence import LEVELS, Confidence, edge_confidence

MAX_DEPTH = 8  # attacker steps after the entry
MAX_PATHS = 5000  # per connection and day; the rest is cut, in a fixed order, and logged
MOVE_TYPES = (
    "ROUTES_TO",
    "TRIGGERS",
    "RUNS_AS",
    "CAN_ASSUME",
    "IS_ADMIN",
    "CAN_PRIVESC_TO",
    "ACCESSES",
    # ADR-0037 second amendment, wave 3: by permission name, the network, Systems Manager.
    "CAN_ESCALATE_TO",
    "CAN_CONNECT_TO",
    "CAN_RUN_ON",
)
ENTRY_TYPES = ("ROUTES_TO", "PUBLIC_UNVERIFIED", "INTERNET_REACHABLE")
# Entries only Argus's rules draw: a closed door, an outsider's principal, a user's credential.
RULE_ENTRY_TYPES = ("PUBLIC_RESTRICTED", "OUTSIDER", "HAS_CREDENTIAL")
INTERNET = "internet"

_EDGES = relationships.EFFECTIVE_EDGES_SQL
_TYPES = ", ".join(f"'{t}'" for t in MOVE_TYPES)
_MOVES_SQL = f"""
  SELECT m.source_uid, m.target_uid FROM ({_EDGES}) m
  WHERE m.type IN ({_TYPES}) AND m.source_uid <> 'internet'
"""  # noqa: S608 - fixed fragments, no input
_MOVE_EDGES_SQL = f"""
  SELECT m.id, m.source_uid, m.target_uid, m.type, m.origin, m.attributes FROM ({_EDGES}) m
  WHERE m.type IN ({_TYPES}) AND m.source_uid <> 'internet'
    AND m.source_uid = ANY(CAST(:nodes AS text[])) AND m.target_uid = ANY(CAST(:nodes AS text[]))
"""  # noqa: S608 - fixed fragments, no input
_ENTRY_EDGES_SQL = f"""
  SELECT m.id, m.source_uid, m.target_uid, m.type, m.origin, m.attributes FROM ({_EDGES}) m
  WHERE m.source_uid = 'internet'
    AND m.type IN ('ROUTES_TO', 'PUBLIC_UNVERIFIED', 'INTERNET_REACHABLE', 'PUBLIC_RESTRICTED',
                   'OUTSIDER', 'HAS_CREDENTIAL')
"""  # noqa: S608 - fixed fragments, no input


@dataclass(frozen=True)
class Step:
    id: int
    source_uid: str
    target_uid: str
    type: str
    origin: str
    confidence: Confidence

    @property
    def rank(self) -> tuple[int, int, int]:
        """Best first when sorted descending: more confident, a rule's, the oldest edge."""
        return (LEVELS.index(self.confidence), int(self.origin.startswith("rule:")), -self.id)


@dataclass(frozen=True)
class Chain:
    entry_uid: str
    target_uid: str
    steps: tuple[Step, ...]  # internet -> entry first

    @property
    def node_uids(self) -> tuple[str, ...]:
        return (INTERNET, *(s.target_uid for s in self.steps))

    @property
    def confidence(self) -> Confidence:
        return min((s.confidence for s in self.steps), key=LEVELS.index)


def _step(row: Any) -> Step:
    level, _why = edge_confidence(row.type, row.origin, row.attributes or {}, row.source_uid)
    return Step(row.id, row.source_uid, row.target_uid, row.type, row.origin, level)


def entries(conn: Connection, params: dict[str, Any]) -> dict[str, Step]:
    """Each seed with its best internet step. A resource Argus's rules call restricted seeds
    through its PUBLIC_RESTRICTED edge (blocked), even when CloudFox calls it public."""
    restricted: dict[str, Step] = {}
    best: dict[str, Step] = {}
    for row in conn.execute(text(_ENTRY_EDGES_SQL), params):
        if row.type in RULE_ENTRY_TYPES and not row.origin.startswith("rule:"):
            continue
        if row.type == "PUBLIC_RESTRICTED":
            restricted[row.target_uid] = _step(row)
            continue
        if row.type == "ROUTES_TO" and not row.origin.startswith("rule:"):
            continue  # only Argus's internet-entry draws ROUTES_TO from the internet
        step = _step(row)
        if row.target_uid not in best or step.rank > best[row.target_uid].rank:
            best[row.target_uid] = step
    return {**best, **restricted}


# {kind id: (its target uids, the types its last step must have (empty: any), whether the
# target is the entry itself: "only", "too" or "never")}, searched and capped in this order.
Entry = Literal["only", "too", "never"]
Targets = dict[str, tuple[set[str], tuple[str, ...], Entry]]


def search(
    conn: Connection, *, params: dict[str, Any], targets: Targets
) -> tuple[dict[str, list[Chain]], int]:
    """{kind id: chains} for `targets` (Targets), and how many were cut by MAX_PATHS, kinds
    kept in the order given. `params` are the effective-edges view's (connection_id, rule_day,
    cloudfox_day)."""
    seeds = entries(conn, params)
    reached = relationships.walk(
        conn, moves_sql=_MOVES_SQL, params=params, seeds=sorted(seeds), max_depth=MAX_DEPTH
    )
    nodes = sorted({n for depths in reached.values() for n in depths})
    incoming: dict[str, list[Step]] = defaultdict(list)
    if nodes:
        for row in conn.execute(text(_MOVE_EDGES_SQL), {**params, "nodes": nodes}):
            incoming[row.target_uid].append(_step(row))
    for steps in incoming.values():
        steps.sort(key=lambda s: s.rank, reverse=True)

    def back(seed: str, node: str) -> list[Step]:
        """The seed's shortest way to `node`: one step shallower at a time, the best edge."""
        depth = reached[seed]
        path: list[Step] = []
        while node != seed:
            step = next(s for s in incoming[node] if depth.get(s.source_uid) == depth[node] - 1)
            path.append(step)
            node = step.source_uid
        return path[::-1]

    found: dict[str, list[Chain]] = {kind: [] for kind in targets}
    for kind, (uids, last_types, entry) in targets.items():
        if entry != "never":  # the door itself is what matters: one step from the internet
            found[kind] = [Chain(s, s, (seeds[s],)) for s in sorted(seeds) if s in uids]
        if entry == "only":
            continue
        for seed in sorted(seeds):
            depth = reached.get(seed, {})
            # At least one move: the entry alone is an exposure kind's (or this kind's, above).
            for target in sorted(uids & depth.keys() - {seed}):
                last = [
                    s
                    for s in incoming[target]
                    if s.source_uid in depth and (not last_types or s.type in last_types)
                ]
                # The closest predecessor whose own way does not pass through the target; among
                # equals, the best edge.
                last.sort(key=lambda s: (depth[s.source_uid], *(-x for x in s.rank)))
                for step in last:
                    way = back(seed, step.source_uid)
                    if all(s.target_uid != target for s in way):
                        found[kind].append(Chain(seed, target, (seeds[seed], *way, step)))
                        break
    total = sum(len(chains) for chains in found.values())
    cut = max(0, total - MAX_PATHS)
    if cut:
        budget = MAX_PATHS
        for kind in targets:  # kinds in the order given, each kind's chains by seed, target
            found[kind] = found[kind][:budget]
            budget -= len(found[kind])
    return found, cut
