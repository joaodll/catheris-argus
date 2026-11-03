"""The attack-path search (ADR-0037): from every internet entry, the shortest chain of attacker
steps to what matters, whatever rule or tool drew each step and whichever account each step is
in (ADR-0044, M2: one search over the graph read model, across accounts).

    seeds   what the internet reaches: the targets of ROUTES_TO from `internet` (Argus's
            internet-entry), PUBLIC_UNVERIFIED (Argus cannot tell) and INTERNET_REACHABLE
            (CloudFox). What Argus's rules call restricted (PUBLIC_RESTRICTED) seeds through
            that edge alone, whatever CloudFox says: a closed door's paths are latent, their
            confidence blocked (ADR-0037, amended 2026-10-21). Also, from Argus's rules, a
            principal outsiders control (OUTSIDER) and a user whose credential may leak
            (HAS_CREDENTIAL; ADR-0037 second amendment, wave 2)
    moves   ROUTES_TO, TRIGGERS, RUNS_AS, CAN_ASSUME, IS_ADMIN, CAN_PRIVESC_TO, ACCESSES,
            CAN_ESCALATE_TO, CAN_CONNECT_TO and CAN_RUN_ON between resources (each connection's
            effective edges, as the graph holds them)
    targets each path kind's own query (backend/rules/attack_paths/<kind>.toml); a kind whose
            target is the entry itself (entry "only": an exposed door, ADR-0037 second
            amendment) is one step, one that may also be the entry ("too": a workload that is a
            door) is one step or more, every other kind ("never") takes at least one move

Pure functions over rows: the graph read model (argus.graph) supplies the internet edges, the
fewest steps from each seed to every node it reaches (a breadth-first walk of at most MAX_DEPTH
moves) and the moves into the reached nodes. rebuild() then rebuilds one path per (seed,
target) backwards, one step shallower at a time, taking the most confident edge when several fit
(a rule's edge before CloudFox's for the same step). A kind may name the types its last step
must have (lateral movement ends with CAN_CONNECT_TO).
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from argus.attackpaths.confidence import LEVELS, Confidence

MAX_DEPTH = 8  # attacker steps after the entry
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


@dataclass(frozen=True)
class Step:
    id: int
    source_uid: str
    target_uid: str
    type: str
    origin: str
    confidence: Confidence
    # The connection whose effective edge this is (None for a manual edge).
    conn: int | None = None

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


def step(row: Mapping[str, Any]) -> Step:
    """A step from a graph edge row: id, source, target, type, origin, confidence (computed by
    edge_confidence when the edge was projected), conn."""
    return Step(
        int(row["id"]),
        row["source"],
        row["target"],
        row["type"],
        row["origin"],
        row["confidence"],
        row.get("conn"),
    )


def entries(steps: Iterable[Step]) -> dict[str, Step]:
    """Each seed with its best internet step, from the edges leaving `internet`. A resource
    Argus's rules call restricted seeds through its PUBLIC_RESTRICTED edge (blocked), even when
    CloudFox calls it public."""
    restricted: dict[str, Step] = {}
    best: dict[str, Step] = {}
    for s in steps:
        if s.type not in ENTRY_TYPES and s.type not in RULE_ENTRY_TYPES:
            continue
        if s.type in RULE_ENTRY_TYPES and not s.origin.startswith("rule:"):
            continue
        if s.type == "PUBLIC_RESTRICTED":
            # One per door: the best of its restricted edges (several accounts' rules could
            # draw one; the same answer however the graph orders them).
            if s.target_uid not in restricted or s.rank > restricted[s.target_uid].rank:
                restricted[s.target_uid] = s
            continue
        if s.type == "ROUTES_TO" and not s.origin.startswith("rule:"):
            continue  # only Argus's internet-entry draws ROUTES_TO from the internet
        if s.target_uid not in best or s.rank > best[s.target_uid].rank:
            best[s.target_uid] = s
    return {**best, **restricted}


def incoming(steps: Iterable[Step]) -> dict[str, list[Step]]:
    """The moves into each node, best first."""
    into: dict[str, list[Step]] = defaultdict(list)
    for s in steps:
        if s.source_uid != INTERNET and s.type in MOVE_TYPES:
            into[s.target_uid].append(s)
    for found in into.values():
        found.sort(key=lambda s: s.rank, reverse=True)
    return into


# {kind id: (its target uids, the types its last step must have (empty: any), whether the
# target is the entry itself: "only", "too" or "never")}, searched in this order.
Entry = Literal["only", "too", "never"]
Targets = dict[str, tuple[set[str], tuple[str, ...], Entry]]


def rebuild(
    seeds: dict[str, Step],
    reached: dict[str, dict[str, int]],
    into: Mapping[str, list[Step]],
    targets: Targets,
) -> dict[str, list[Chain]]:
    """{kind id: chains} for `targets`, kinds in the order given, each kind's chains by seed
    then target. `reached` is {seed: {node: fewest moves}} (the seed itself at 0), `into` the
    moves into each reached node, best first (incoming())."""

    def back(seed: str, node: str) -> list[Step]:
        """The seed's shortest way to `node`: one step shallower at a time, the best edge."""
        depth = reached[seed]
        path: list[Step] = []
        while node != seed:
            s = next(s for s in into.get(node, ()) if depth.get(s.source_uid) == depth[node] - 1)
            path.append(s)
            node = s.source_uid
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
                    for s in into.get(target, ())
                    if s.source_uid in depth and (not last_types or s.type in last_types)
                ]
                # The closest predecessor whose own way does not pass through the target; among
                # equals, the best edge.
                last.sort(key=lambda s: (depth[s.source_uid], *(-x for x in s.rank)))
                for s in last:
                    way = back(seed, s.source_uid)
                    if all(w.target_uid != target for w in way):
                        found[kind].append(Chain(seed, target, (seeds[seed], *way, s)))
                        break
    return found
