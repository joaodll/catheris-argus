"""Recompute one connection's Risk rows after it changed (ADR-0049 section 5).

Called in the transaction of every check of reach (after a Steampipe, Prowler or CloudFox
ingest, and after a re-derive) and of every vulnerabilities ingest, and for every connection
whose last refresh used another combination set (at start, under the re-derive lock).

Missing data never removes a row: findings are resolved only by complete runs, and a door that
turned `unknown` (the data its verdict needs is missing) is held while the resource was already
at risk through it. A row leaves only when a load that covered the fact shows it gone.
"""

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import Connection, text

from argus import connections, findings, inventory, relationships
from argus.cloudfox import ENV_EXPOSURE_CHECK, PUBLIC_ENDPOINT_CHECK
from argus.metrics import summary
from argus.risk.combinations import (
    COMBINATION_IDS,
    DOOR_COMBINATIONS,
    TIERS,
    Facts,
    combination_set,
    matched,
    sort_key,
    tier_of,
)

_NO_FINDINGS = findings.FindingFacts(0, 0, 0, None, 0, 0, None, False)
# Every column a refresh writes, in this order (the row tuple compared to tell a change).
_COLUMNS = (
    "connection_id",
    "provider",
    "resource_type",
    "tier",
    "combinations",
    "sort_key",
    "first_seen",
    "door_held_since",
    "door",
    "admin",
    "env_secret",
    "credential_kinds",
    "exploitable_cves",
    "high_cves",
    "max_epss",
    "high_misconfigurations",
    "worst_misconfiguration",
)


@dataclass(frozen=True)
class Refreshed:
    at_risk: int  # resources at risk after the refresh
    written: int  # rows inserted or changed
    removed: int  # rows that left


def _today() -> date:
    return datetime.now(UTC).date()


def _existing(conn: Connection, connection_id: int) -> dict[int, dict[str, Any]]:
    rows = conn.execute(
        text(
            f"SELECT resource_id, {', '.join(_COLUMNS)} FROM resource_risk "  # noqa: S608
            "WHERE connection_id = :c"
        ),
        {"c": connection_id},
    )
    return {r.resource_id: dict(r._mapping) for r in rows}


def _provider(conn: Connection, connection_id: int) -> str:
    provider: str = conn.execute(
        text(f"SELECT provider FROM ({connections.DIRECTORY_SQL}) c WHERE c.id = :c"),  # noqa: S608
        {"c": connection_id},
    ).scalar_one()
    return provider


def _facts(
    door: bool,
    found: findings.FindingFacts,
    admin: bool,
    credentials: tuple[str, ...],
) -> Facts:
    return Facts(
        door=door,
        admin=admin,
        credentials=credentials,
        exploitable_cves=found.exploitable_cves,
        exploitable_fixable_cves=found.exploitable_fixable_cves,
        high_cves=found.high_cves,
        max_epss=found.max_epss,
        high_misconfigurations=found.high_misconfigurations,
        other_high_misconfigurations=found.other_high_misconfigurations,
        worst_misconfiguration=found.worst_misconfiguration,
        secret=found.secret,
    )


def refresh(conn: Connection, *, connection_id: int, day: date) -> Refreshed:
    """One connection's rows as its stored facts stand now; `day` is the run's day, recorded as
    when a resource first became at risk. Writes only what changed, then the risk.resources
    counts and the connection's risk_load."""
    # One refresh of a connection at a time: two at once could each miss the other's new row
    # and write it again with its own first-seen day.
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtext('argus.risk.refresh'), :c)"),
        {"c": connection_id},
    )
    as_of = max(day, _today())
    reach = relationships.internet_reach(conn, connection_id=connection_id, day=as_of)
    # No rule load stands (none yet, or retention purged an account scanned too long ago): the
    # doors, administrators and credentials are unknown, not gone. A row keeps the edge facts
    # it had, its door held; the findings' facts are still current.
    no_rules = reach.day is None
    doors = {d.resource_id: d.reach for d in reach.doors.values() if d.resource_id is not None}
    principals = relationships.principal_facts(conn, connection_id=connection_id, day=as_of)
    found = findings.resource_finding_facts(
        conn,
        connection_id=connection_id,
        own_fact_checks=(PUBLIC_ENDPOINT_CHECK, *findings.PROWLER_EXPOSURE_CHECKS),
        secret_check=ENV_EXPOSURE_CHECK,
    )
    existing = _existing(conn, connection_id)
    candidates = set(found) | set(principals.credentials) | set(existing)
    assets = inventory.current_assets_among(
        conn, connection_id=connection_id, resource_ids=sorted(candidates)
    )
    provider = _provider(conn, connection_id)

    rows: dict[int, tuple[Any, ...]] = {}
    for resource_id, resource_type in assets.items():
        old = existing.get(resource_id)
        reach_now = "unknown" if no_rules else doors.get(resource_id)
        door = reach_now == "confirmed"
        held_since: date | None = None
        if reach_now == "unknown" and old is not None and old["door"]:
            door, held_since = True, old["door_held_since"] or day
        if no_rules and old is not None:
            admin, credentials = old["admin"], tuple(old["credential_kinds"])
        else:
            admin = resource_id in principals.admins
            credentials = principals.credentials.get(resource_id, ())
        args = (found.get(resource_id, _NO_FINDINGS), admin, credentials)
        facts = _facts(door, *args)
        combos = matched(facts)
        if held_since is not None and not DOOR_COMBINATIONS.intersection(combos):
            # The held door no longer carries any combination: judge it without one.
            facts, held_since = _facts(False, *args), None
            combos = matched(facts)
        if not combos:
            continue
        rows[resource_id] = (
            connection_id,
            provider,
            resource_type,
            tier_of(combos),
            list(combos),
            sort_key(combos, facts),
            old["first_seen"] if old else day,
            held_since,
            facts.door,
            facts.admin,
            facts.secret,
            list(facts.credentials),
            facts.exploitable_cves,
            facts.high_cves,
            _epss(facts.max_epss),
            facts.high_misconfigurations,
            facts.worst_misconfiguration,
        )

    gone = sorted(set(existing) - set(rows))
    if gone:
        conn.execute(
            text("DELETE FROM resource_risk WHERE resource_id = ANY(CAST(:ids AS bigint[]))"),
            {"ids": gone},
        )
    changed = [
        {"resource_id": rid, **dict(zip(_COLUMNS, row, strict=True))}
        for rid, row in sorted(rows.items())
        if rid not in existing or _stored(existing[rid]) != row
    ]
    if changed:
        names = ", ".join(_COLUMNS)
        values = ", ".join(f":{c}" for c in _COLUMNS)
        updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in _COLUMNS)
        conn.execute(
            text(
                f"INSERT INTO resource_risk (resource_id, {names}) "  # noqa: S608
                f"VALUES (:resource_id, {values}) "
                f"ON CONFLICT (resource_id) DO UPDATE SET {updates}"
            ),
            changed,
        )
    conn.execute(
        text("""
            INSERT INTO risk_load (connection_id, refreshed_on, combination_set)
            VALUES (:c, :d, :s)
            ON CONFLICT (connection_id) DO UPDATE
              SET refreshed_on = greatest(risk_load.refreshed_on, EXCLUDED.refreshed_on),
                  combination_set = EXCLUDED.combination_set,
                  refreshed_at = now()
        """),
        {"c": connection_id, "d": day, "s": combination_set()},
    )
    _put_counts(conn, connection_id=connection_id, day=day, rows=rows)
    return Refreshed(at_risk=len(rows), written=len(changed), removed=len(gone))


def _epss(value: float | None) -> float | None:
    """EPSS at the precision a real column keeps, so a value read back compares equal and an
    unchanged row is never rewritten."""
    return None if value is None else round(value, 4)


def _stored(row: dict[str, Any]) -> tuple[Any, ...]:
    """A stored row as refresh() builds one."""
    return tuple(_epss(row[c]) if c == "max_epss" else row[c] for c in _COLUMNS)


def _put_counts(
    conn: Connection, *, connection_id: int, day: date, rows: dict[int, tuple[Any, ...]]
) -> None:
    """risk.resources for the connection, every tier and combination zero-filled, then all
    connections (metrics.summary.put_family)."""
    tier_at = _COLUMNS.index("tier")
    combos_at = _COLUMNS.index("combinations")
    values: dict[tuple[str, str], float] = {(summary.RISK_RESOURCES, "total"): float(len(rows))}
    values |= {(summary.RISK_RESOURCES, f"tier:{t}"): 0.0 for t in TIERS}
    values |= {(summary.RISK_RESOURCES, f"combination:{c}"): 0.0 for c in COMBINATION_IDS}
    for row in rows.values():
        values[(summary.RISK_RESOURCES, f"tier:{row[tier_at]}")] += 1
        for c in row[combos_at]:
            values[(summary.RISK_RESOURCES, f"combination:{c}")] += 1
    summary.put_family(conn, summary.RISK, connection_id=connection_id, day=day, values=values)


def stale_connections(conn: Connection) -> list[int]:
    """Enabled connections never refreshed, or refreshed with another combination set: the
    ones a start refreshes (after an upgrade, the screen would otherwise wait weeks for the
    next scans)."""
    rows = conn.execute(
        text(f"""
            SELECT c.id FROM ({connections.DIRECTORY_SQL}) c
            LEFT JOIN risk_load l ON l.connection_id = c.id
            WHERE c.enabled AND (l.connection_id IS NULL OR l.combination_set <> :s)
            ORDER BY c.id
        """),  # noqa: S608 - an exported SQL constant only
        {"s": combination_set()},
    )
    return [r.id for r in rows]
