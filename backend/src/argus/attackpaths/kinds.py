"""The kinds of attack route: versioned files in <rules dir>/attack_paths/*.toml (ADR-0052).

Each kind names its targets with one read-only query over four views of one connection:

    r   its resources on its latest inventory day, uid and type only (never a configuration)
    e   its standing edges (each family's latest load) and every manual edge
    f   its open, unmuted failing misconfigurations
    d   its doors: what the internet reaches, with the ports and whether one is an
        administrative port, and whether it is public by its own policy (doors.py)

bound to :connection_id, :resource_day, :rule_day and :cloudfox_day.
"""

import tomllib
from dataclasses import dataclass
from datetime import date
from functools import cache
from pathlib import Path
from typing import Literal

from sqlalchemy import Connection, text

from argus import findings, inventory, relationships
from argus.attackpaths.doors import DOORS_SQL

SEVERITIES = ("informational", "low", "medium", "high", "critical")
Entry = Literal["only", "too", "never"]
VIEWS = f"""
WITH r AS ({inventory.RESOURCE_TYPES_ON_DAY_SQL}),
e AS ({relationships.EFFECTIVE_EDGES_SQL}),
f AS ({findings.FAILING_FINDINGS_SQL}),
d AS ({DOORS_SQL})
"""


@dataclass(frozen=True)
class RouteKind:
    id: str
    version: int
    name: str
    category: str
    severity: str
    technique: str
    description: str
    remediation: str
    sql: str
    # The types the last step must have; empty: any move.
    last_steps: tuple[str, ...] = ()
    # "only": the target is the door itself (an exposure, one step); "too": the door or what it
    # reaches; "never": what it reaches, at least one move.
    entry: Entry = "never"


def load_kinds(rules_dir: Path) -> list[RouteKind]:
    """Every kind file, most severe first (the order targets are searched in)."""
    kinds = []
    for file in sorted((rules_dir / "attack_paths").glob("*.toml")):
        d = tomllib.loads(file.read_text())
        entry: Entry = "only" if d.get("entry_only") else "too" if d.get("entry_too") else "never"
        kind = RouteKind(
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
            entry=entry,
        )
        if file.stem != kind.id or kind.severity not in SEVERITIES:
            raise ValueError(
                f"{file.name}: id must match the file name; severity must be one of {SEVERITIES}"
            )
        if kind.entry == "only" and kind.last_steps:
            raise ValueError(f"{file.name}: an entry_only kind takes no step after the entry")
        if d.get("entry_only") and d.get("entry_too"):
            raise ValueError(f"{file.name}: entry_only and entry_too exclude each other")
        kinds.append(kind)
    if not kinds:
        raise ValueError(f"no attack-path kinds in {rules_dir / 'attack_paths'}")
    return sorted(kinds, key=lambda k: (-SEVERITIES.index(k.severity), k.id))


@cache
def kinds_by_id(rules_dir: Path) -> dict[str, RouteKind]:
    """The kind files, read once per process: a route's page shows its kind's words. Kinds
    change with a release, not at run time."""
    return {k.id: k for k in load_kinds(rules_dir)}


def kind_targets(
    conn: Connection,
    kinds: list[RouteKind],
    *,
    connection_id: int,
    resource_day: date | None,
    rule_day: date | None,
    cloudfox_day: date | None,
) -> dict[str, set[str]]:
    """{kind id: target uids} in one connection. `any:` targets are scoped to the connection,
    as the walk scopes them: a wildcard grant in one account never joins another's."""
    params = {
        "connection_id": connection_id,
        "resource_day": resource_day,
        "rule_day": rule_day,
        "cloudfox_day": cloudfox_day,
    }
    found: dict[str, set[str]] = {}
    for kind in kinds:
        rows = conn.execute(text(VIEWS + kind.sql), params).scalars()  # a kind file, not input
        found[kind.id] = {scope(uid, connection_id) for uid in rows if uid}
    return found


def scope(uid: str, connection_id: int | None) -> str:
    """`any:<service>` is every store of a service in one account: one node per connection."""
    return f"{uid}@{connection_id}" if uid.startswith("any:") and connection_id else uid
