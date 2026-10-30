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
Kinds are searched in severity order, so the path cap cuts the least severe first.

Effective edges are each family's (relationship rules, CloudFox) latest snapshot on or before
the day, plus manual edges, so a failed run does not make paths disappear. Paths are upserted
with a stable path_id (kind id + ordered nodes) and resolved only when a complete run no longer
produces them.
"""

import hashlib
import logging
import tomllib
from dataclasses import dataclass
from datetime import date
from functools import cache
from pathlib import Path

from sqlalchemy import Connection, Engine, text

from argus import findings, inventory, metrics, relationships
from argus.attackpaths.doors import DOORS_SQL
from argus.attackpaths.search import Chain, Targets, search

log = logging.getLogger(__name__)

SEVERITIES = ("informational", "low", "medium", "high", "critical")
VIEWS = f"""
WITH r AS ({inventory.RESOURCES_ON_DAY_SQL}),
e AS ({relationships.EFFECTIVE_EDGES_SQL}),
f AS ({findings.FAILING_FINDINGS_SQL}),
d AS ({DOORS_SQL})
"""
# A failing finding on a security group attached to the entry is the door's (Prowler's
# security-group checks sit on the group; ADR-0037, second amendment).
_ENTRY_GROUPS_SQL = f"""
  SELECT DISTINCT g.source_uid, g.target_uid FROM ({relationships.EFFECTIVE_EDGES_SQL}) g
  WHERE g.type = 'MEMBER_OF' AND g.source_uid = ANY(CAST(:entries AS text[]))
"""  # noqa: S608 - exported SQL constants only


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


def _effective_days(conn: Connection, connection_id: int, day: date) -> dict[str, date | None]:
    return {
        "resource_day": inventory.effective_day(conn, connection_id=connection_id, day=day),
        **relationships.effective_days(conn, connection_id=connection_id, day=day),
    }


def find_paths(
    engine: Engine, *, kinds: list[PathKind], connection_id: int, day: date
) -> list[FoundPath]:
    found: list[FoundPath] = []
    with engine.connect() as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        conn.execute(text(relationships.NO_JIT))
        params = {"connection_id": connection_id, **_effective_days(conn, connection_id, day)}
        # Most severe first: the path cap cuts the least severe kinds.
        ordered = sorted(kinds, key=lambda k: -SEVERITIES.index(k.severity))
        targets: Targets = {
            kind.id: (
                {uid for (uid,) in conn.execute(text(VIEWS + kind.sql), params)},
                kind.last_steps,
                "only" if kind.entry_only else "too" if kind.entry_too else "never",
            )
            for kind in ordered
        }
        chains, cut = search(conn, params=params, targets=targets)
        entries = sorted({c.entry_uid for cs in chains.values() for c in cs})
        groups: dict[str, set[str]] = {}
        for entry, group in conn.execute(text(_ENTRY_GROUPS_SQL), {**params, "entries": entries}):
            groups.setdefault(entry, set()).add(group)
        on_path = {uid for cs in chains.values() for c in cs for uid in c.node_uids}
        on_path |= {g for gs in groups.values() for g in gs}
        failing = set(
            conn.execute(
                text(
                    f"WITH f AS ({findings.FAILING_FINDINGS_SQL}) "  # noqa: S608 - constant
                    "SELECT DISTINCT resource_uid FROM f "
                    "WHERE resource_uid = ANY(CAST(:nodes AS text[]))"
                ),
                {**params, "nodes": sorted(on_path)},
            ).scalars()
        )
        conn.rollback()
    if cut:
        log.warning("attack paths cut at the cap", extra={"connection": connection_id, "cut": cut})
    by_id = {kind.id: kind for kind in kinds}
    for kind_id, kind_chains in chains.items():
        kind = by_id[kind_id]
        for chain in kind_chains:
            has_failing = any(uid in failing for uid in chain.node_uids) or bool(
                groups.get(chain.entry_uid, set()) & failing
            )
            confirmed = chain.steps[0].confidence == "confirmed"
            found.append(
                FoundPath(
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
                )
            )
    unique = {p.path_id: p for p in found}
    return list(unique.values())


def evaluate_paths(
    engine: Engine, *, rules_dir: Path, connection_id: int, day: date, resolve: bool
) -> dict[str, int]:
    """Searches every kind's paths and upserts them. resolve=False (the day's evidence is
    incomplete) records what was found but closes nothing."""
    kinds = load_path_kinds(rules_dir)
    paths = find_paths(engine, kinds=kinds, connection_id=connection_id, day=day)
    with engine.begin() as conn:
        if paths:
            conn.execute(
                text("""
                INSERT INTO attack_path (path_id, rule_id, rule_version, category, severity,
                                         connection_id, entry_uid, target_uid, node_uids,
                                         edge_ids, state, first_seen, last_seen, base_severity,
                                         entry_confirmed, has_failing, confidence)
                VALUES (:pid, :rule, :version, :category, :severity, :c, :entry, :target,
                        :nodes, :edges, 'open', :d, :d, :base, :confirmed, :failing, :conf)
                ON CONFLICT (path_id) DO UPDATE SET
                  severity = EXCLUDED.severity, rule_version = EXCLUDED.rule_version,
                  category = EXCLUDED.category,
                  edge_ids = EXCLUDED.edge_ids, base_severity = EXCLUDED.base_severity,
                  entry_confirmed = EXCLUDED.entry_confirmed, has_failing = EXCLUDED.has_failing,
                  confidence = EXCLUDED.confidence,
                  last_seen = GREATEST(attack_path.last_seen, EXCLUDED.last_seen),
                  state = 'open', resolved_on = NULL
            """),
                [
                    {
                        "pid": p.path_id,
                        "rule": p.kind.id,
                        "version": p.kind.version,
                        "category": p.kind.category,
                        "severity": p.severity,
                        "c": connection_id,
                        "entry": p.chain.entry_uid,
                        "target": p.chain.target_uid,
                        "nodes": list(p.chain.node_uids),
                        "edges": [s.id for s in p.chain.steps],
                        "d": day,
                        "base": p.kind.severity,
                        "confirmed": p.entry_confirmed,
                        "failing": p.has_failing,
                        "conf": p.chain.confidence,
                    }
                    for p in paths
                ],
            )
        resolved = 0
        if resolve:
            resolved = conn.execute(
                text("""
                UPDATE attack_path SET state = 'resolved', resolved_on = :d
                WHERE connection_id = :c AND state = 'open'
                  AND (last_seen < :d OR rule_id <> ALL(CAST(:kinds AS text[])))
            """),
                # A path of a kind this release no longer has (a rule before ADR-0037) can
                # never be found again: a complete run closes it, the same day too.
                {"d": day, "c": connection_id, "kinds": [k.id for k in kinds]},
            ).rowcount
        put_path_metrics(conn, connection_id=connection_id, day=day)
    return {"paths": len(paths), "resolved": resolved}


PATH_METRICS = ["attack_paths.open_by_category", "attack_paths.open_by_severity"]


def put_path_metrics(conn: Connection, *, connection_id: int, day: date) -> None:
    # Every severity starts at 0: an evaluation that found no path is "0 open paths", which
    # the Overview must tell apart from "CloudFox has not run" (no rows). Latent (blocked)
    # paths are not counted: they are what one change would open, not what is open.
    values: dict[tuple[str, str], float] = {
        ("attack_paths.open_by_severity", severity): 0 for severity in SEVERITIES
    }
    for category, severity, n in conn.execute(
        text(
            "SELECT category, severity, count(*) FROM attack_path WHERE connection_id = :c "
            "AND state = 'open' AND confidence IS DISTINCT FROM 'blocked' "
            "GROUP BY category, severity"
        ),
        {"c": connection_id},
    ):
        values[("attack_paths.open_by_category", category)] = (
            values.get(("attack_paths.open_by_category", category), 0) + n
        )
        values[("attack_paths.open_by_severity", severity)] = (
            values.get(("attack_paths.open_by_severity", severity), 0) + n
        )
    metrics.put(conn, day=day, connection_id=connection_id, values=values, replace=PATH_METRICS)
    metrics.rollup(conn, day=day, metrics=PATH_METRICS)
