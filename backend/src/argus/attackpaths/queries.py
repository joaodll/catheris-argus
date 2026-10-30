"""Read side of attack_path: ranked paths for drill-downs, and one path with its steps."""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from argus.connections import DIRECTORY_SQL

_COLUMNS = """
    p.id, encode(p.path_id, 'hex') AS path_id, p.rule_id, p.rule_version, p.category,
    p.severity, p.connection_id, c.name AS connection, p.entry_uid, p.target_uid,
    p.node_uids, p.edge_ids, p.state, p.first_seen, p.last_seen, p.resolved_on,
    p.base_severity, p.entry_confirmed, p.has_failing, p.confidence
"""


@dataclass(frozen=True)
class PathFilters:
    """The Attack paths list's filters; an empty tuple does not filter."""

    connection_id: int | None = None
    state: str = "open"
    severities: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    # The kinds (their file ids, backend/rules/attack_paths): finer than a category.
    kinds: tuple[str, ...] = ()
    # How sure: confirmed, supported, candidate, unknown, blocked (ADR-0037). Empty: every
    # level but blocked, whose latent paths are shown only when asked for.
    confidences: tuple[str, ...] = ()
    # Only paths through this node (Attack paths through a resource, ADR-0033).
    through_uid: str | None = None


_SEVERITY_RANK = (
    "array_position(ARRAY['critical','high','medium','low','informational'], p.severity)"
)
# The list's orders: a fixed map, never a column name from a client.
ORDERS = {
    "severity": f"{_SEVERITY_RANK}, p.first_seen, p.id",
    "first_seen_desc": f"p.first_seen DESC, {_SEVERITY_RANK}, p.id",
    "first_seen_asc": f"p.first_seen, {_SEVERITY_RANK}, p.id",
    "last_seen_desc": f"p.last_seen DESC, {_SEVERITY_RANK}, p.id",
    "last_seen_asc": f"p.last_seen, {_SEVERITY_RANK}, p.id",
}


def list_paths(
    conn: Connection,
    *,
    limit: int,
    offset: int,
    filters: PathFilters | None = None,
    order: str = "severity",
) -> tuple[list[dict[str, Any]], int]:
    """One page of paths, and how many match the filters (also past the last page, so the UI
    can move to it)."""
    filters = filters or PathFilters()
    rows = conn.execute(
        text(f"""
        WITH m AS (
        SELECT {_COLUMNS}
        FROM attack_path p JOIN ({DIRECTORY_SQL}) c ON c.id = p.connection_id
        WHERE p.state = :s AND (CAST(:c AS bigint) IS NULL OR p.connection_id = :c)
          AND (CAST(:sev AS text[]) IS NULL OR p.severity = ANY(CAST(:sev AS text[])))
          AND (CAST(:cat AS text[]) IS NULL OR p.category = ANY(CAST(:cat AS text[])))
          AND (CAST(:kind AS text[]) IS NULL OR p.rule_id = ANY(CAST(:kind AS text[])))
          AND (CASE WHEN CAST(:conf AS text[]) IS NULL
                    THEN p.confidence IS DISTINCT FROM 'blocked'
                    ELSE p.confidence = ANY(CAST(:conf AS text[])) END)
          AND (CAST(:node AS text) IS NULL OR p.node_uids @> ARRAY[CAST(:node AS text)])
        )
        SELECT t.total, pg.* FROM (SELECT count(*) AS total FROM m) t
        LEFT JOIN LATERAL (SELECT * FROM m p ORDER BY {ORDERS[order]} LIMIT :l OFFSET :o) pg
          ON true
    """),  # noqa: S608 - exported SQL constants only
        {
            "s": filters.state,
            "c": filters.connection_id,
            "sev": list(filters.severities) or None,
            "cat": list(filters.categories) or None,
            "kind": list(filters.kinds) or None,
            "conf": list(filters.confidences) or None,
            "node": filters.through_uid,
            "l": limit,
            "o": offset,
        },
    )
    found = [dict(r._mapping) for r in rows]
    total = int(found[0]["total"]) if found else 0
    paths = [{k: v for k, v in r.items() if k != "total"} for r in found if r["id"] is not None]
    return paths, total


def get_path(conn: Connection, path_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        text(f"""
        SELECT {_COLUMNS}
        FROM attack_path p JOIN ({DIRECTORY_SQL}) c ON c.id = p.connection_id
        WHERE p.id = :id
    """),  # noqa: S608 - exported SQL constants only
        {"id": path_id},
    ).first()
    return dict(row._mapping) if row else None


def path_facets(conn: Connection, *, connection_id: int | None) -> dict[str, list[str]]:
    """The categories, kinds and confidence levels that have paths: the list filters'
    options."""
    rows = conn.execute(
        text("""
        SELECT DISTINCT category, rule_id, confidence FROM attack_path
        WHERE CAST(:c AS bigint) IS NULL OR connection_id = :c
    """),
        {"c": connection_id},
    ).all()
    return {
        "categories": sorted({r.category for r in rows}),
        "kinds": sorted({r.rule_id for r in rows}),
        "confidences": sorted({r.confidence for r in rows if r.confidence}),
    }
