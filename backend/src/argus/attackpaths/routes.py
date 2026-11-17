"""From chains to routes: one route per (kind, entry), its worst targets listed (ADR-0052 §2-§5).

Each chain gets the steps no edge stands for (P1 R0):
- a foothold, "takes control of X", before every move that uses X's role or X's network
  position (RUNS_AS, CAN_CONNECT_TO), and on a workload whose environment a kind reads
  (internet-to-workload-secret). Its evidence: a public exploit on X (compromise_cve), IMDSv1
  before X's role on an instance (compromise_imdsv1), or none (compromise_assumed);
- for internet-to-data, "authenticates to X" on a database reached with no credential or role
  step before it (data_auth_assumed).

Then each target has a class (levels.route_class), a likelihood and the kind's severity, and the
route lists its LIST_N worst: the most sure first, then the fewest steps. `crossed` is every
connection any target's chain touches, listed or not (§9 H1).
"""

import hashlib
import heapq
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from argus.attackpaths.kinds import RouteKind
from argus.attackpaths.levels import (
    AUTHENTICATES,
    CLASSES,
    FOOTHOLD,
    RouteClass,
    route_class,
)
from argus.attackpaths.walk import Step, Target

LIST_N = 25  # targets listed per route (W3.2)
CONTROL_MOVES = ("RUNS_AS", "CAN_CONNECT_TO")
INSTANCE = "aws_ec2_instance"
DATABASES = ("aws_rds_db_instance", "aws_rds_db_cluster")
AUTH_STEPS = ("ACCESSES", "HAS_CREDENTIAL")
DATA_KIND = "internet-to-data"
ENV_KIND = "internet-to-workload-secret"
IMDS_CHECK = "ec2_instance_imdsv2_enabled"
# Prowler's checks that make a bucket public itself: a distribution's origin bucket counts as a
# data route only then (kind 6, ADR-0052 §6; all in Prowler 5.50.0's list).
EXPOSURE_CHECKS = (
    "s3_bucket_public_access",
    "s3_bucket_public_list_acl",
    "s3_bucket_public_write_acl",
    "s3_bucket_policy_public_write_access",
)


@dataclass(frozen=True)
class Evidence:
    """What the steps read beyond the edges: findings only (ADR-0052 §9 L3)."""

    exploitable: Mapping[str, str]  # resource uid -> a CVE id with a public exploit
    imds_v1: set[str]  # instances failing ec2_instance_imdsv2_enabled
    exposed: set[str]  # buckets failing an exposure check
    types: Mapping[str, str]  # resource uid -> type


def targets_for(
    kinds: list[RouteKind], found: Mapping[str, set[str]], evidence: Evidence
) -> dict[str, Target]:
    """Each kind's search: its targets, last-step types and entry rule."""
    return {k.id: Target(found.get(k.id, set()), k.last_steps, k.entry) for k in kinds}


def _foothold(on: Step, evidence: Evidence, *, for_role: bool) -> Step:
    x = on.source
    cve = evidence.exploitable.get(x)
    if cve:
        reason, ref = "compromise_cve", cve
    elif for_role and evidence.types.get(x) == INSTANCE and x in evidence.imds_v1:
        reason, ref = "compromise_imdsv1", ""
    else:
        reason, ref = "compromise_assumed", ""
    return Step(
        None, x, x, FOOTHOLD, "walk", "candidate", reason, on.conn, on.day, on.source_id,
        on.source_id, ref=ref,
    )  # fmt: skip


def complete(kind: str, chain: list[Step], evidence: Evidence) -> list[Step]:
    """The chain with the walk's own steps added (footholds, authentication)."""
    out: list[Step] = [chain[0]]
    for s in chain[1:]:
        if s.type in CONTROL_MOVES:
            out.append(_foothold(s, evidence, for_role=s.type == "RUNS_AS"))
        out.append(s)
    last = chain[-1]
    end = Step(
        None, last.target, last.target, "", "walk", "candidate", "", last.conn, last.day,
        last.target_id, last.target_id,
    )  # fmt: skip
    if kind == ENV_KIND:
        out.append(_foothold(end, evidence, for_role=False))
    if (
        kind == DATA_KIND
        and evidence.types.get(last.target) in DATABASES
        and not any(s.type in AUTH_STEPS for s in chain)
    ):
        out.append(
            Step(
                None,
                last.target,
                last.target,
                AUTHENTICATES,
                "walk",
                "candidate",
                "data_auth_assumed",
                last.conn,
                last.day,
                last.target_id,
                last.target_id,
            )
        )
    return out


def likelihood(steps: list[Step]) -> str:
    """How likely, apart from how sure (§6 A2): the entry's reach, then the footholds' evidence."""
    entry = steps[0]
    if entry.level == "unknown":
        return "unknown"
    if entry.level != "confirmed":
        return "lower"
    if any(s.reason == "compromise_assumed" for s in steps):
        return "lower"
    return "higher"


_Key = tuple[int, int, tuple[int, ...]]


@dataclass(frozen=True)
class FoundTarget:
    target: str
    target_id: int | None
    cls: RouteClass
    likelihood: str
    steps: tuple[Step, ...]

    @property
    def order(self) -> tuple[int, int, str]:
        """Worst first when sorted ascending: the most sure, the fewest steps, then by uid."""
        return (-CLASSES.index(self.cls), len(self.steps), self.target)


@dataclass
class FoundRoute:
    kind: RouteKind
    entry: Step
    # The LIST_N worst so far, as a heap whose root is the least bad of them (listed() sorts).
    targets: list[tuple[_Key, int, FoundTarget]] = field(default_factory=list)
    count: int = 0
    crossed: set[int] = field(default_factory=set)

    @property
    def entry_uid(self) -> str:
        return self.entry.target

    @property
    def connection_id(self) -> int | None:
        return self.entry.conn

    def add(self, t: FoundTarget) -> None:
        self.count += 1
        for s in t.steps:
            if s.conn is not None:
                self.crossed.add(s.conn)
            self.crossed.update(s.also)
        # A max-heap of the LIST_N worst by order, kept as negated tuples.
        item = (_neg(t.order), self.count, t)
        if len(self.targets) < LIST_N:
            heapq.heappush(self.targets, item)
        elif item[:2] > self.targets[0][:2]:
            heapq.heapreplace(self.targets, item)

    def listed(self) -> list[FoundTarget]:
        return sorted((x[2] for x in self.targets), key=lambda t: t.order)

    def crossed_ids(self) -> list[int]:
        """The entry's connection first, then the rest in order."""
        own = self.connection_id
        return [own, *sorted(self.crossed - {own})] if own is not None else sorted(self.crossed)

    def digest(self) -> bytes:
        """What a row holds, so an unchanged route writes nothing (§2)."""
        h = hashlib.sha256(f"{self.kind.version}|{self.count}|{self.crossed_ids()}".encode())
        for t in self.listed():
            h.update(f"|{t.target}:{t.cls}:{t.likelihood}".encode())
            for s in t.steps:
                h.update(
                    f";{s.type},{s.source},{s.target},{s.id},{s.origin},{s.level},{s.reason},"
                    f"{s.ref},{s.conn},{s.day}".encode()
                )
        return h.digest()

    @property
    def worst_class(self) -> RouteClass:
        return self.listed()[0].cls


def _neg(order: tuple[int, int, str]) -> _Key:
    """An order reversed (the uid by code points, a shorter uid first among prefixes), so the
    heap's root is the worst of the targets kept."""
    return (-order[0], -order[1], (*(-ord(c) for c in order[2]), 1))


def collect(
    kinds: Mapping[str, RouteKind],
    found: Iterable[tuple[str, str, list[Step]]],
    evidence: Evidence,
) -> list[FoundRoute]:
    """Every (kind, entry) route from the walk's chains."""
    routes: dict[tuple[str, str], FoundRoute] = {}
    for kind_id, seed, chain in found:
        steps = complete(kind_id, chain, evidence)
        cls = route_class([(s.level, s.reason) for s in steps])
        route = routes.get((kind_id, seed))
        if route is None:
            route = routes[(kind_id, seed)] = FoundRoute(kinds[kind_id], chain[0])
        route.add(
            FoundTarget(chain[-1].target, chain[-1].target_id, cls, likelihood(steps), tuple(steps))
        )
    return [r for r in routes.values() if r.connection_id is not None]
