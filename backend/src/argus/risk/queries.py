"""The Risk screen's read side (ADR-0049 section 7).

The list reads resource_risk only, worst first through its order indexes, and only enabled
connections: the same scope the tiles count (store.rollup_family), so a tile opens exactly what
it counts.
"""

from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlalchemy import Connection, text

from argus import connections

_ROW_COLUMNS = (
    "rr.resource_id, rr.connection_id, rr.provider, rr.resource_type, rr.tier, rr.combinations, "
    "rr.first_seen, rr.door_held_since, rr.door, rr.admin, rr.env_secret, rr.credential_kinds, "
    "rr.exploitable_cves, rr.high_cves, rr.max_epss, rr.high_misconfigurations, "
    "rr.worst_misconfiguration"
)


@dataclass(frozen=True)
class RiskFilters:
    """A list filter matches any of its values; empty, it does not filter."""

    connection_ids: tuple[int, ...] = ()
    providers: tuple[str, ...] = ()
    tiers: tuple[str, ...] = ()
    combinations: tuple[str, ...] = ()
    resource_types: tuple[str, ...] = ()


def _any(values: tuple[Any, ...]) -> list[Any] | None:
    return list(values) or None


_WHERE = f"""
    FROM resource_risk rr
    JOIN ({connections.DIRECTORY_SQL}) c ON c.id = rr.connection_id
    WHERE c.enabled
      AND (CAST(:conns AS bigint[]) IS NULL OR rr.connection_id = ANY(CAST(:conns AS bigint[])))
      AND (CAST(:providers AS text[]) IS NULL OR rr.provider = ANY(CAST(:providers AS text[])))
      AND (CAST(:tiers AS text[]) IS NULL OR rr.tier = ANY(CAST(:tiers AS text[])))
      AND (CAST(:combos AS text[]) IS NULL OR rr.combinations && CAST(:combos AS text[]))
      AND (CAST(:types AS text[]) IS NULL OR rr.resource_type = ANY(CAST(:types AS text[])))
"""


def list_risk(
    conn: Connection, *, filters: RiskFilters, limit: int, offset: int
) -> tuple[list[dict[str, Any]], int]:
    """One page of at-risk resources, worst first, and how many match."""
    params = {
        "conns": _any(filters.connection_ids),
        "providers": _any(filters.providers),
        "tiers": _any(filters.tiers),
        "combos": _any(filters.combinations),
        "types": _any(filters.resource_types),
    }
    rows = conn.execute(
        text(f"""
            SELECT {_ROW_COLUMNS} {_WHERE}
            ORDER BY rr.sort_key DESC, rr.resource_id
            LIMIT :limit OFFSET :offset
        """),
        {**params, "limit": limit, "offset": offset},
    )
    page = [dict(r._mapping) for r in rows]
    total: int = conn.execute(
        text(f"SELECT count(*) {_WHERE}"),
        params,
    ).scalar_one()
    return page, total


def risk_types(conn: Connection, *, connection_ids: tuple[int, ...]) -> list[str]:
    """The resource types at risk in scope (enabled connections), for the Type filter."""
    rows = conn.execute(
        text(f"""
            SELECT DISTINCT rr.resource_type
            FROM resource_risk rr JOIN ({connections.DIRECTORY_SQL}) c ON c.id = rr.connection_id
            WHERE c.enabled
              AND (CAST(:conns AS bigint[]) IS NULL
                   OR rr.connection_id = ANY(CAST(:conns AS bigint[])))
            ORDER BY 1
        """),  # noqa: S608 - an exported SQL constant only
        {"conns": _any(connection_ids)},
    )
    return [r.resource_type for r in rows]


@dataclass(frozen=True)
class RiskScope:
    """What the screen's scope was computed from: whether any of its enabled connections was
    ever refreshed, and the newest day a refresh reflects (None: never)."""

    computed: bool
    data_through: date | None


def risk_scope(conn: Connection, *, connection_ids: tuple[int, ...]) -> RiskScope:
    """The scope's risk_load: its enabled connections (all of them when none is named)."""
    row = conn.execute(
        text(f"""
            SELECT count(l.connection_id) AS refreshed, max(l.refreshed_on) AS through
            FROM ({connections.DIRECTORY_SQL}) c
            LEFT JOIN risk_load l ON l.connection_id = c.id
            WHERE c.enabled
              AND (CAST(:conns AS bigint[]) IS NULL OR c.id = ANY(CAST(:conns AS bigint[])))
        """),  # noqa: S608 - an exported SQL constant only
        {"conns": _any(connection_ids)},
    ).one()
    return RiskScope(computed=row.refreshed > 0, data_through=row.through)
