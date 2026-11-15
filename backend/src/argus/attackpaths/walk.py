"""The walk: from every way in, which kind targets an attacker reaches, and by which steps.

In-process, over every connection's standing edges at once (ADR-0052 §1), so a route can cross
accounts. The search is the old one (`d0fb438` attackpaths/search.py), reused by reading it: a
breadth-first walk from each entry to every node within MAX_DEPTH moves, then for each target
the closest last step whose own way back avoids the target, one step shallower at a time,
taking the best edge.

Strongest first (§6 A4): the walk runs once with only the moves Argus holds as configured or
checked, then again with assumptions allowed for the targets the first did not reach, so a
Conditional route never hides a Confirmed one that takes more steps.

What the edges alone can't say, the walk adds as its own steps (P1 R0):
- a scanned account is not an outsider (§6 A3): its OUTSIDER edges are left out, and a trust
  naming its root becomes a step from each of its principals allowed sts:AssumeRole on the role
  (MAY_ASSUME, `assume-permission`) and from its administrator;
- route53-target is not a move: a name gives no reach, the target's own door does.
Footholds and authentication steps are added to each chain afterwards (routes.py).
"""

import fnmatch
import re
from collections import defaultdict, deque
from collections.abc import Iterator, Mapping, Sequence, Set
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from argus.attackpaths.kinds import scope
from argus.attackpaths.levels import INTERNET, LEVELS, Level, edge_level

MAX_DEPTH = 8  # attacker moves after the entry
MOVE_TYPES = (
    "ROUTES_TO",
    "TRIGGERS",
    "RUNS_AS",
    "CAN_ASSUME",
    "IS_ADMIN",
    "CAN_PRIVESC_TO",
    "ACCESSES",
    "CAN_ESCALATE_TO",
    "CAN_CONNECT_TO",
    "CAN_RUN_ON",
)
ENTRY_TYPES = ("ROUTES_TO", "PUBLIC_UNVERIFIED", "INTERNET_REACHABLE")
# Entries only Argus's rules draw: a closed door, an outsider's principal, a user's credential.
RULE_ENTRY_TYPES = ("PUBLIC_RESTRICTED", "OUTSIDER", "HAS_CREDENTIAL")
MAY_ASSUME = "MAY_ASSUME"
EDGE_TYPES = tuple(sorted({*MOVE_TYPES, *ENTRY_TYPES, *RULE_ENTRY_TYPES, MAY_ASSUME}))
# The edge types whose attributes the walk judges by; every other edge comes without them.
JUDGED_ATTRIBUTES = ("CAN_ASSUME", "OUTSIDER", "MAY_ASSUME", "PUBLIC_RESTRICTED")
NOT_MOVES = ("rule:route53-target@",)
CLOUDFRONT_ORIGIN = "rule:cloudfront-origin@"
# The floors of the strongest-first walk: the weakest level a move may have in each pass.
FLOORS: tuple[Level, ...] = ("supported", "candidate")
# Prowler's checks that make a source anyone may write to (a trigger then fires for anyone).
PUBLIC_WRITE_CHECKS = (
    "s3_bucket_policy_public_write_access",
    "s3_bucket_public_write_acl",
    "sns_topics_not_publicly_accessible",
    "sqs_queues_not_publicly_accessible",
)
_ROOT = re.compile(r"^(?:arn:aws[a-z-]*:iam::([0-9]{12}):root|([0-9]{12}))$")
_ARN_ACCOUNT = re.compile(r"^arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:([0-9]{12}):")


@dataclass(frozen=True, slots=True)
class Step:
    """One step of a route: an edge, or one the walk made (id None)."""

    id: int | None
    source: str
    target: str
    type: str
    origin: str
    level: Level
    reason: str
    conn: int | None
    day: date | None
    source_id: int | None = None
    target_id: int | None = None
    # An evidence reference, never a value: a CVE id, or the edges a walk-made step joins.
    ref: str = ""
    # Connections the step reads beside its own (a cross-account step: the principal's).
    also: tuple[int, ...] = ()

    @property
    def rank(self) -> tuple[int, int, int]:
        """Best first when sorted descending: more sure, a rule's, the oldest edge."""
        return (LEVELS.index(self.level), int(self.origin.startswith("rule:")), -(self.id or 0))


@dataclass
class Graph:
    """Every move and every way in, indexed for the walk."""

    seeds: dict[str, Step]
    # Per floor: the moves out of each node, and into each node best first.
    out: dict[Level, dict[str, list[str]]]
    into: dict[Level, dict[str, list[Step]]]
    types: dict[str, str] = field(default_factory=dict)


def account_of(uid: str) -> str | None:
    """The account in an ARN, a root principal or a bare account id; None otherwise."""
    m = _ROOT.match(uid)
    if m:
        return m.group(1) or m.group(2)
    m = _ARN_ACCOUNT.match(uid)
    return m.group(1) if m else None


def build(
    rows: Sequence[Mapping[str, Any]],
    *,
    scanned: Mapping[str, int],
    public_write: set[str],
    exposed: Set[str] = frozenset(),
) -> tuple[list[Step], list[Step]]:
    """(steps, cross-account steps) from the standing edges. `scanned`: account id ->
    connection of every enabled connection. `public_write`: resources anyone may write to.
    `exposed`: buckets public themselves; a distribution reaches its origin bucket only then
    (kind 6: reading through a distribution is a static site, and gives no write, so no
    trigger, behind it)."""
    steps: list[Step] = []
    may_assume: dict[str, list[tuple[Step, tuple[str, ...], bool]]] = defaultdict(list)
    root_trusts: list[Step] = []
    for r in rows:
        if r["origin"].startswith(NOT_MOVES):
            continue
        if r["origin"].startswith(CLOUDFRONT_ORIGIN) and r["target_uid"] not in exposed:
            continue
        conn = r["connection_id"]
        source, target = scope(r["source_uid"], conn), scope(r["target_uid"], conn)
        attributes = r["attributes"] or {}
        type_ = r["type"]
        if type_ == "OUTSIDER" and account_of(target) in scanned:
            continue  # a scanned account is not an outsider (A3)
        source_account = account_of(source)
        cross = (
            type_ == "CAN_ASSUME"
            and source_account is not None
            and source_account != account_of(target)
        )
        level, reason = edge_level(type_, r["origin"], attributes, source, cross_account=cross)
        if type_ == "TRIGGERS" and source in public_write:
            level, reason = "supported", "trigger_public_write"
        step = Step(
            int(r["id"]),
            source,
            target,
            type_,
            r["origin"],
            level,
            reason,
            conn,
            r["day"],
            r["source_resource_id"],
            r["target_resource_id"],
        )
        if type_ == MAY_ASSUME:
            if source_account is not None:
                patterns = tuple(str(p).lower() for p in attributes.get("resources") or ())
                may_assume[source_account].append(
                    (step, patterns, bool(attributes.get("truncated")))
                )
            continue
        if type_ == "CAN_ASSUME" and _ROOT.match(source) and source_account in scanned:
            root_trusts.append(step)  # joined below with the account's own principals
            continue
        steps.append(step)
    return steps, _cross_account(root_trusts, may_assume, scanned)


def _cross_account(
    trusts: list[Step],
    may_assume: Mapping[str, list[tuple[Step, tuple[str, ...], bool]]],
    scanned: Mapping[str, int],
) -> list[Step]:
    """A trust naming account X's root, X scanned: whoever in X may call sts:AssumeRole on the
    role assumes it, and so may X's administrator (A3). Candidate: the principal's side is
    matched by name, its conditions and boundaries are not evaluated."""
    made: list[Step] = []
    for t in trusts:
        account = account_of(t.source)
        if account is None:
            continue
        own = account == account_of(t.target)
        prefix = "account" if own else "cross_account"
        x_conn = scanned[account]
        made.append(
            Step(
                None,
                f"admin:{account}",
                t.target,
                "CAN_ASSUME",
                t.origin,
                "candidate",
                f"{prefix}_admin",
                t.conn,
                t.day,
                None,
                t.target_id,
                ref=str(t.id),
                also=(x_conn,),
            )
        )
        role = t.target.lower()
        for m, patterns, truncated in may_assume.get(account, ()):
            if not (truncated or any(fnmatch.fnmatchcase(role, p) for p in patterns)):
                continue
            made.append(
                Step(
                    None,
                    m.source,
                    t.target,
                    "CAN_ASSUME",
                    t.origin,
                    "candidate",
                    f"{prefix}_identity",
                    t.conn,
                    t.day,
                    m.source_id,
                    t.target_id,
                    ref=f"{m.id}/{t.id}",
                    also=(x_conn,),
                )
            )
    return made


def entries(steps: list[Step]) -> dict[str, Step]:
    """Each seed with its best step in from the internet. A door Argus's rules call restricted
    seeds through its PUBLIC_RESTRICTED edge (blocked: a latent route), even when CloudFox
    calls it public."""
    restricted: dict[str, Step] = {}
    best: dict[str, Step] = {}
    for s in steps:
        if s.source != INTERNET:
            continue
        if s.type not in ENTRY_TYPES and s.type not in RULE_ENTRY_TYPES:
            continue
        if s.type in RULE_ENTRY_TYPES and not s.origin.startswith("rule:"):
            continue
        if s.type == "ROUTES_TO" and not s.origin.startswith("rule:"):
            continue  # only internet-entry draws ROUTES_TO from the internet
        pick = restricted if s.type == "PUBLIC_RESTRICTED" else best
        if s.target not in pick or s.rank > pick[s.target].rank:
            pick[s.target] = s
    return {**best, **restricted}


def graph(steps: list[Step], cross: list[Step], types: dict[str, str]) -> Graph:
    moves = [s for s in (*steps, *cross) if s.source != INTERNET and s.type in MOVE_TYPES]
    out: dict[Level, dict[str, list[str]]] = {}
    into: dict[Level, dict[str, list[Step]]] = {}
    for floor in FLOORS:
        least = LEVELS.index(floor)
        o: dict[str, list[str]] = defaultdict(list)
        i: dict[str, list[Step]] = defaultdict(list)
        for s in moves:
            if LEVELS.index(s.level) >= least:
                o[s.source].append(s.target)
                i[s.target].append(s)
        for found in i.values():
            found.sort(key=lambda s: s.rank, reverse=True)
        out[floor], into[floor] = dict(o), dict(i)
    return Graph(entries(steps), out, into, types)


def _depths(seed: str, out: Mapping[str, list[str]]) -> dict[str, int]:
    """Fewest moves from the seed to every node it reaches, never through the internet."""
    depth = {seed: 0}
    queue = deque([seed])
    while queue:
        node = queue.popleft()
        d = depth[node]
        if d == MAX_DEPTH:
            continue
        for nxt in out.get(node, ()):
            if nxt not in depth and nxt != INTERNET:
                depth[nxt] = d + 1
                queue.append(nxt)
    return depth


@dataclass(frozen=True)
class Target:
    uids: set[str]
    last_types: tuple[str, ...]
    entry: str  # "only", "too", "never"


def chains(g: Graph, targets: Mapping[str, Target]) -> Iterator[tuple[str, str, list[Step]]]:
    """(kind id, seed, steps entry first) for every target a seed reaches, one chain per
    (kind, seed, target): from the strongest floor that reaches it, then the fewest moves."""
    for seed in sorted(g.seeds):
        entry = g.seeds[seed]
        done: dict[str, set[str]] = {k: set() for k in targets}
        for kind, t in targets.items():
            if t.entry != "never" and seed in t.uids:
                done[kind].add(seed)
                yield kind, seed, [entry]
        for floor in FLOORS:
            depth = _depths(seed, g.out[floor])
            into = g.into[floor]
            for kind, t in targets.items():
                if t.entry == "only":
                    continue
                for target in sorted(t.uids & depth.keys() - {seed} - done[kind]):
                    way = _last(seed, target, depth, into, t)
                    if way is not None:
                        done[kind].add(target)
                        yield kind, seed, [entry, *way]


def _last(
    seed: str,
    target: str,
    depth: Mapping[str, int],
    into: Mapping[str, list[Step]],
    t: Target,
) -> list[Step] | None:
    """The closest last step into the target whose own way back avoids it; the best edge
    among equals."""
    last = [
        s
        for s in into.get(target, ())
        if s.source in depth and (not t.last_types or s.type in t.last_types)
    ]
    last.sort(key=lambda s: (depth[s.source], *(-x for x in s.rank)))
    for s in last:
        way = _back(seed, s.source, depth, into)
        if all(w.target != target for w in way):
            return [*way, s]
    return None


def _back(
    seed: str, node: str, depth: Mapping[str, int], into: Mapping[str, list[Step]]
) -> list[Step]:
    """The seed's shortest way to `node`: one step shallower at a time, the best edge."""
    path: list[Step] = []
    while node != seed:
        s = next(s for s in into.get(node, ()) if depth.get(s.source) == depth[node] - 1)
        path.append(s)
        node = s.source
    return path[::-1]
