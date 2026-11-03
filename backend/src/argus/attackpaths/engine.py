"""The attack-path engine (ADR-0009, ADR-0011; ADR-0037 replaced the path rules with one search).

A path kind is a TOML file in <rules dir>/attack_paths: id, version, name, category, severity,
technique (MITRE ATT&CK), description, remediation, optionally `last_steps` (the edge types the
path's last step must have), `entry_only` (the target is the entry itself: one step, an
exposed door) or `entry_too` (the entry itself or what it reaches), and one read-only SQL
query that selects the kind's target uids. The query reads the views of one connection on one
day, each exported by the module that owns its tables
(inventory, relationships, findings) or, for `d`, by this module, so this engine names none of
them:

    r(uid, type, native_id, name, region, vpc_id, config)       resources
    e(id, source_uid, target_uid, type, origin, attributes)      effective edges
    f(resource_uid, check_id, severity)                          failing findings now
    d(uid, ports, admin_port)                                    the doors (doors.py)

The search (search.py) finds, from every internet entry, the shortest chain to each target.
Severity starts from the kind's; it goes up one level when the entry step is confirmed (Argus's
internet rules checked it) and down one level when nothing on the path, nor a security group of
its entry, has a failing finding. A path's confidence is its weakest step's (confidence.py).

An account can have more paths than anyone reads: cap() keeps the MAX_PATHS worst of each account,
assessed, and every path found that already has a row. What it cuts has no row, and is counted
(attack_paths.not_listed) so Attack paths can say so (ADR-0044, amended 2026-11-02).

The search runs over the graph read model, across accounts (ADR-0044, M2): argus.graph
orchestrates one evaluation over every connection's latest scan state and calls this module for
the kinds' targets (in Postgres, on the days the graph was projected from), the scoring
(assess), the cap and the storage (store_paths). A path belongs to its entry's connection and
records every connection it passes through. Paths have a stable path_id (kind id + ordered nodes),
are written only when something about them changed, and are resolved only when an evaluation no
longer finds them and every connection on them has complete evidence (its newest Steampipe and
CloudFox runs complete), so a partial run never looks like a fix.
"""

import hashlib
import tomllib
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from functools import cache
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, text

from argus import findings, inventory, metrics, relationships
from argus.attackpaths.confidence import LEVELS
from argus.attackpaths.doors import DOORS_SQL
from argus.attackpaths.search import Chain, Targets

SEVERITIES = ("informational", "low", "medium", "high", "critical")
MAX_PATHS = 5000  # new rows per entry connection and evaluation: its worst paths (cap())
VIEWS = f"""
WITH r AS ({inventory.RESOURCES_ON_DAY_SQL}),
e AS ({relationships.EFFECTIVE_EDGES_SQL}),
f AS ({findings.FAILING_FINDINGS_SQL}),
d AS ({DOORS_SQL})
"""


@dataclass(frozen=True)
class PathKind:
    id: str
    version: int
    name: str
    category: str
    severity: str
    technique: str
    description: str
    remediation: str
    # The kind's targets: one read-only query returning uids.
    sql: str
    # The types the last step must have; empty: any move.
    last_steps: tuple[str, ...] = ()
    # The target is the entry itself (an exposed door): one step, no move.
    entry_only: bool = False
    # The target may be the entry itself as well as what it reaches (a workload that is a door).
    entry_too: bool = False


@dataclass(frozen=True)
class FoundPath:
    kind: PathKind
    chain: Chain
    severity: str
    # Why it has that severity (shown on the path page): the kind's level moves up when the
    # entry is confirmed and down when nothing on the path has a failing finding.
    has_failing: bool
    entry_confirmed: bool
    # The entry's connection, which owns the path (owner's decision, 2026-10-31), and every
    # connection the path passes through, the entry's first (ADR-0044, M2).
    connection_id: int
    connection_ids: tuple[int, ...]

    @property
    def path_id(self) -> bytes:
        return hashlib.sha256("|".join((self.kind.id, *self.chain.node_uids)).encode()).digest()


def load_path_kinds(rules_dir: Path) -> list[PathKind]:
    kinds = []
    for file in sorted((rules_dir / "attack_paths").glob("*.toml")):
        d = tomllib.loads(file.read_text())
        kind = PathKind(
            id=d["id"],
            version=int(d["version"]),
            name=d["name"],
            category=d["category"],
            severity=d["severity"],
            technique=d["technique"],
            description=d["description"],
            remediation=d["remediation"],
            sql=d["sql"],
            last_steps=tuple(d.get("last_steps", ())),
            entry_only=bool(d.get("entry_only", False)),
            entry_too=bool(d.get("entry_too", False)),
        )
        if file.stem != kind.id or kind.severity not in SEVERITIES:
            raise ValueError(
                f"{file.name}: id must match the file name; severity must be one of {SEVERITIES}"
            )
        if kind.entry_only and (kind.last_steps or kind.entry_too):
            raise ValueError(f"{file.name}: an entry_only kind takes no step after the entry")
        kinds.append(kind)
    if not kinds:
        raise ValueError(f"no attack-path kinds in {rules_dir / 'attack_paths'}")
    return kinds


@cache
def kinds_by_id(rules_dir: Path) -> dict[str, PathKind]:
    """The kind files, read once per process: the path page shows a kind's name, technique,
    description and remediation. Kinds change with a release (the image), not at run time."""
    return {kind.id: kind for kind in load_path_kinds(rules_dir)}


def _adjust(base: str, *, has_failing: bool, confirmed: bool, blocked: bool = False) -> str:
    """Up one level for a confirmed entry, down one with no failing finding on the path, and
    down one for a latent (blocked) path: what one change would open (ADR-0037, amended)."""
    level = (
        SEVERITIES.index(base)
        + (1 if confirmed else 0)
        - (0 if has_failing else 1)
        - (1 if blocked else 0)
    )
    return SEVERITIES[max(0, min(level, len(SEVERITIES) - 1))]


def kind_targets(
    conn: Connection,
    *,
    kinds: list[PathKind],
    days: dict[int, dict[str, Any]],
    scope: Callable[[int, str], str] = lambda _connection, uid: uid,
) -> Targets:
    """Each kind's targets over every connection, most severe kind first. `days` is {connection
    id: its resource_day, rule_day and cloudfox_day}, the days the graph read model was projected
    from, so the views here and the graph describe the same state. `scope` names a connection's
    target as the graph does (an account's wildcard pseudo-node). Read-only."""
    ordered = sorted(kinds, key=lambda k: -SEVERITIES.index(k.severity))
    targets: Targets = {
        kind.id: (
            set(),
            kind.last_steps,
            "only" if kind.entry_only else "too" if kind.entry_too else "never",
        )
        for kind in ordered
    }
    for connection_id, day in sorted(days.items()):
        params = {"connection_id": connection_id, **day}
        for kind in ordered:
            found = conn.execute(text(VIEWS + kind.sql), params)
            targets[kind.id][0].update(scope(connection_id, uid) for (uid,) in found)
    return targets


def failing_nodes(conn: Connection, *, connection_ids: list[int], uids: list[str]) -> set[str]:
    """The uids among `uids` with a failing finding now, in any of the connections."""
    failing: set[str] = set()
    for connection_id in connection_ids:
        failing.update(
            conn.execute(
                text(
                    f"WITH f AS ({findings.FAILING_FINDINGS_SQL}) "  # noqa: S608 - constant
                    "SELECT DISTINCT resource_uid FROM f "
                    "WHERE resource_uid = ANY(CAST(:nodes AS text[]))"
                ),
                {"connection_id": connection_id, "nodes": uids},
            ).scalars()
        )
    return failing


def assess(
    kinds: list[PathKind],
    chains: dict[str, list[Chain]],
    *,
    failing: set[str],
    groups: dict[str, set[str]],
    owner: Callable[[Chain], int],
    accounts: Callable[[Chain], list[int]],
) -> list[FoundPath]:
    """Each chain with its severity (ADR-0037): the kind's, up one level for a confirmed entry,
    down one with no failing finding on the path nor on a security group of its entry
    (`groups`), down one for a latent (blocked) path. `owner` is the entry's connection,
    `accounts` every connection on the path, the entry's first."""
    by_id = {kind.id: kind for kind in kinds}
    found: dict[bytes, FoundPath] = {}
    for kind_id, kind_chains in chains.items():
        kind = by_id[kind_id]
        for chain in kind_chains:
            has_failing = any(uid in failing for uid in chain.node_uids) or bool(
                groups.get(chain.entry_uid, set()) & failing
            )
            confirmed = chain.steps[0].confidence == "confirmed"
            path = FoundPath(
                kind,
                chain,
                _adjust(
                    kind.severity,
                    has_failing=has_failing,
                    confirmed=confirmed,
                    blocked=chain.confidence == "blocked",
                ),
                has_failing,
                confirmed,
                owner(chain),
                tuple(accounts(chain)),
            )
            found[path.path_id] = path
    return list(found.values())


LATENT = "latent"
_NOT_LISTED_DIMS = (*SEVERITIES, LATENT)


def _worst_first(path: FoundPath) -> tuple[int, int, int, bytes]:
    """Assessed severity, then confidence, then fewer steps; path_id only keeps it deterministic."""
    return (
        -SEVERITIES.index(path.severity),
        -LEVELS.index(path.chain.confidence),
        len(path.chain.steps),
        path.path_id,
    )


def stored_path_ids(conn: Connection) -> set[bytes]:
    """Every path that has a row, open or resolved."""
    return {bytes(i) for i in conn.execute(text("SELECT path_id FROM attack_path")).scalars()}


def cap(
    paths: list[FoundPath], *, stored: set[bytes]
) -> tuple[list[FoundPath], dict[int, Counter[str]]]:
    """Which paths found keep a row: each entry connection's MAX_PATHS worst (ADR-0044, amended
    2026-11-02), so a new path that matters always enters, and every path that already has one, so
    no row goes stale and a resolved path found again reopens. MAX_PATHS limits new rows: stored
    rows are bounded by what is found. Returns those paths and, per connection, the ones cut by
    severity (`latent` for blocked paths, which the list hides unless asked)."""
    by_owner: dict[int, list[FoundPath]] = defaultdict(list)
    for path in paths:
        by_owner[path.connection_id].append(path)
    kept: list[FoundPath] = []
    cut: dict[int, Counter[str]] = {}
    for connection_id, mine in by_owner.items():
        mine.sort(key=_worst_first)
        kept += mine[:MAX_PATHS]
        for path in mine[MAX_PATHS:]:
            if path.path_id in stored:
                kept.append(path)
            else:
                dimension = LATENT if path.chain.confidence == "blocked" else path.severity
                cut.setdefault(connection_id, Counter())[dimension] += 1
    return kept, cut


# What may change on a path with the same path_id, whose nodes are part of its id.
_FACTS = (
    "rule_version",
    "category",
    "severity",
    "connection_id",
    "connection_ids",
    "edge_ids",
    "base_severity",
    "entry_confirmed",
    "has_failing",
    "confidence",
)
_COLUMNS = ("path_id", "rule_id", "entry_uid", "target_uid", "node_uids", *_FACTS)
_STAGE_CHUNK = 5000
# The paths this evaluation keeps, for the three statements below: a path that is not here was not
# found, since every stored path found is kept. A large array of ids would cost far more (the M2
# amendment rejected it), and each statement here writes only what differs.
_STAGE_SQL = f"""
  CREATE TEMPORARY TABLE staged_path ON COMMIT DROP AS
  SELECT {", ".join(_COLUMNS)}, true AS stored FROM attack_path WITH NO DATA
"""  # noqa: S608 - constants only
_STAGE_ROW_SQL = f"""
  INSERT INTO staged_path ({", ".join(_COLUMNS)}, stored)
  VALUES ({", ".join(f":{c}" for c in _COLUMNS)}, :stored)
"""  # noqa: S608 - constants only
# The first evaluation of a day moves last_seen on every path found. A later one that day writes
# only real changes, and a resolved path found again reopens.
_UPDATE_SQL = f"""
  UPDATE attack_path p SET
    {", ".join(f"{c} = s.{c}" for c in _FACTS)},
    last_seen = GREATEST(p.last_seen, :d), state = 'open', resolved_on = NULL
  FROM staged_path s
  WHERE p.path_id = s.path_id
    AND (p.state <> 'open' OR p.last_seen < :d
         OR ({", ".join(f"p.{c}" for c in _FACTS)})
            IS DISTINCT FROM ({", ".join(f"s.{c}" for c in _FACTS)}))
"""  # noqa: S608 - constants only
# No anti-join against attack_path: on a table the statistics call empty, that plan rescans the rows
# this statement has just inserted (5 minutes for 105,000 paths; budget, 2026-11-02).
_INSERT_SQL = f"""
  INSERT INTO attack_path ({", ".join(_COLUMNS)}, state, first_seen, last_seen)
  SELECT {", ".join(f"s.{c}" for c in _COLUMNS)}, 'open', :d, :d FROM staged_path s
  WHERE NOT s.stored
"""  # noqa: S608 - constants only
# An open path this evaluation did not find is resolved, when every account it passes through is
# resolvable: its evidence is complete (ADR-0044, M2). A path of a kind this release no longer has
# is never found again, so it resolves the same way.
_RESOLVE_SQL = """
  UPDATE attack_path p SET state = 'resolved', resolved_on = :d
  WHERE p.state = 'open' AND p.connection_ids <@ CAST(:resolvable AS bigint[])
    AND NOT EXISTS (SELECT 1 FROM staged_path s WHERE s.path_id = p.path_id)
"""


def _stage(conn: Connection, paths: list[FoundPath], stored: set[bytes]) -> None:
    conn.execute(text(_STAGE_SQL))
    for i in range(0, len(paths), _STAGE_CHUNK):
        conn.execute(
            text(_STAGE_ROW_SQL),
            [
                {
                    "path_id": p.path_id,
                    "stored": p.path_id in stored,
                    "rule_id": p.kind.id,
                    "entry_uid": p.chain.entry_uid,
                    "target_uid": p.chain.target_uid,
                    "node_uids": list(p.chain.node_uids),
                    "rule_version": p.kind.version,
                    "category": p.kind.category,
                    "severity": p.severity,
                    "connection_id": p.connection_id,
                    "connection_ids": list(p.connection_ids),
                    "edge_ids": [s.id for s in p.chain.steps],
                    "base_severity": p.kind.severity,
                    "entry_confirmed": p.entry_confirmed,
                    "has_failing": p.has_failing,
                    "confidence": p.chain.confidence,
                }
                for p in paths[i : i + _STAGE_CHUNK]
            ],
        )
    # Statistics on attack_path are out of date within this transaction, so the resolve may plan a
    # nested loop over this table: the index keeps that cheap.
    conn.execute(text("CREATE UNIQUE INDEX ON staged_path (path_id)"))
    conn.execute(text("ANALYZE staged_path"))


def store_paths(
    conn: Connection,
    *,
    paths: list[FoundPath],
    stored: set[bytes],
    cut: dict[int, Counter[str]],
    day: date,
    resolvable: list[int],
    counted: list[int],
) -> dict[str, int]:
    """Writes what changed among the `paths` cap() kept (`stored`: those that have a row, as
    stored_path_ids() read them in this transaction; the graph lock makes this the only writer),
    resolves what the evaluation no longer finds in the `resolvable` connections, and puts path
    metrics for the `counted` ones (each connection with an edge load), on `day`. In the caller's
    transaction: run it once per evaluation. A staged table lives only in that transaction."""
    _stage(conn, paths, stored)
    changed = conn.execute(text(_UPDATE_SQL), {"d": day}).rowcount
    new = conn.execute(text(_INSERT_SQL), {"d": day}).rowcount
    resolved = 0
    if resolvable:
        resolved = conn.execute(
            text(_RESOLVE_SQL), {"d": day, "resolvable": sorted(resolvable)}
        ).rowcount
    put_path_metrics(conn, connection_ids=counted, day=day, cut=cut)
    return {"paths": len(paths), "new": new, "changed": changed, "resolved": resolved}


NOT_LISTED = "attack_paths.not_listed"
PATH_METRICS = ["attack_paths.open_by_category", "attack_paths.open_by_severity", NOT_LISTED]


def put_path_metrics(
    conn: Connection,
    *,
    connection_ids: list[int],
    day: date,
    cut: dict[int, Counter[str]],
) -> None:
    # Every severity starts at 0: an evaluation that found no path is "0 open paths", which
    # the Overview must tell apart from "CloudFox has not run" (no rows). Latent (blocked)
    # paths are not counted: they are what one change would open, not what is open. What the cap
    # cut starts at 0 too: all connections takes each one's latest value, so a cut that went away
    # needs its zero.
    if not connection_ids:
        return
    values: dict[int, dict[tuple[str, str], float]] = {
        c: {
            **{("attack_paths.open_by_severity", severity): 0 for severity in SEVERITIES},
            **{(NOT_LISTED, dim): cut[c][dim] if c in cut else 0 for dim in _NOT_LISTED_DIMS},
        }
        for c in connection_ids
    }
    for connection_id, category, severity, n in conn.execute(
        text(
            "SELECT connection_id, category, severity, count(*) FROM attack_path "
            "WHERE connection_id = ANY(CAST(:cs AS bigint[])) "
            "AND state = 'open' AND confidence IS DISTINCT FROM 'blocked' "
            "GROUP BY connection_id, category, severity"
        ),
        {"cs": list(connection_ids)},
    ):
        mine = values[connection_id]
        mine[("attack_paths.open_by_category", category)] = (
            mine.get(("attack_paths.open_by_category", category), 0) + n
        )
        mine[("attack_paths.open_by_severity", severity)] += n
    for connection_id, mine in sorted(values.items()):
        metrics.put(conn, day=day, connection_id=connection_id, values=mine, replace=PATH_METRICS)
    metrics.rollup(conn, day=day, metrics=PATH_METRICS)


def not_listed(
    conn: Connection, *, connection_id: int | None, as_of: date
) -> dict[str, Any] | None:
    """What the cap cut in the connection's latest evaluation (None: all connections): how many
    paths, how many latent ones, and the worst severity among the paths. None: never evaluated."""
    found = metrics.latest(
        conn,
        connection_id=metrics.ALL_CONNECTIONS if connection_id is None else connection_id,
        metric=NOT_LISTED,
        as_of=as_of,
    )
    if not found:
        return None
    present = [s for s in reversed(SEVERITIES) if found.get(s)]
    return {
        "paths": sum(int(found.get(s, 0)) for s in SEVERITIES),
        "latent": int(found.get(LATENT, 0)),
        "worst": present[0] if present else None,
    }
