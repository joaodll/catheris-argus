"""Read side of inventory: the Resources list and its filter options, and a resource as it
was on a given day."""

from dataclasses import dataclass
from datetime import date
from typing import Any, Literal

from sqlalchemy import Connection, text

from argus.core.db import count_sql, like_contains

# Exported SQL. Other modules embed these instead of naming inventory's tables, so a change
# to resource, resource_config or resource_snapshot is made here and nowhere else.

# The view relationship rules read as `r`: one connection's resources as of
# :resource_day (bind it to effective_day()).
RESOURCES_ON_DAY_SQL = """
  SELECT res.resource_uid AS uid, res.type, res.native_id, res.name, res.region, res.vpc_id,
         cfg.config
  FROM resource_snapshot s
  JOIN resource res ON res.id = s.resource_id
  JOIN resource_config cfg ON cfg.id = s.config_id
  WHERE s.snapshot_date = :resource_day AND res.connection_id = :connection_id
"""


# The ids of one connection's resources in the regions a run scanned: :c and :regions. A global
# resource is reported from any region, so it is always among them.
RESOURCES_IN_REGIONS_SQL = """
  SELECT id FROM resource
  WHERE connection_id = :c AND (region = 'global' OR region = ANY(CAST(:regions AS text[])))
"""


def resource_id_sql(param: str) -> str:
    """A scalar subquery: the id of the resource whose uid is bound to :param, or NULL."""
    # The parameter name is code, never input.
    return f"(SELECT id FROM resource WHERE resource_uid = :{param})"  # noqa: S608


def uid_by_native_id(
    conn: Connection, *, connection_id: int, native_id: str, types: tuple[str, ...]
) -> str | None:
    """The uid of the most recently seen resource with this native id (a name a tool reported)
    and one of these types."""
    uid: str | None = conn.execute(
        text(
            "SELECT resource_uid FROM resource WHERE connection_id = :c AND native_id = :n "
            "AND type = ANY(CAST(:t AS text[])) ORDER BY last_seen DESC LIMIT 1"
        ),
        {"c": connection_id, "n": native_id, "t": list(types)},
    ).scalar_one_or_none()
    return uid


def effective_day(conn: Connection, *, connection_id: int, day: date) -> date | None:
    """The inventory that stands for `day`: the connection's latest load on or before it,
    however old (owner's decision, 2026-11-01: every screen shows each account's latest scan;
    scans may be 60 days apart, and retention is the only limit). A primary-key read of
    resource_load (migration 0036). A load with no resource counts, so an account whose
    resources all went away reads empty, and a failed run records no load, so the previous
    one still stands."""
    value: date | None = conn.execute(
        text(
            "SELECT max(snapshot_date) FROM resource_load "
            "WHERE connection_id = :c AND snapshot_date <= :d"
        ),
        {"c": connection_id, "d": day},
    ).scalar()
    return value


def delete_loads_before(conn: Connection, *, cutoff: date) -> int:
    """Retention: resource_load rows older than the history kept (their snapshots are gone)."""
    deleted: int = conn.execute(
        text("DELETE FROM resource_load WHERE snapshot_date < :c"), {"c": cutoff}
    ).rowcount
    return deleted


ResourceOrder = Literal["name_asc", "name_desc", "last_seen_desc", "last_seen_asc"]

# Resources without a name sort by their native id, as the UI shows them.
_ORDERS: dict[str, str] = {
    "name_asc": "coalesce(r.name, r.native_id), r.id",
    "name_desc": "coalesce(r.name, r.native_id) DESC, r.id DESC",
    "last_seen_desc": "r.last_seen DESC, r.id",
    "last_seen_asc": "r.last_seen, r.id",
}
# The searched text, exactly as the trigram index resource_search is defined (migration 0008).
_SEARCH = r"(coalesce(r.name, '') || E'\n' || r.native_id || E'\n' || r.resource_uid)"
_FILTERS = f"""
  WHERE (CAST(:c AS bigint[]) IS NULL OR r.connection_id = ANY(CAST(:c AS bigint[])))
    AND (CAST(:t AS text[]) IS NULL OR r.type = ANY(CAST(:t AS text[])))
    AND (CAST(:rg AS text[]) IS NULL OR r.region = ANY(CAST(:rg AS text[])))
    AND (NOT CAST(:assets AS boolean) OR r.asset)
    AND (CAST(:deleted AS boolean) OR r.deleted_on IS NULL)
    AND (CAST(:fs_from AS date) IS NULL OR r.first_seen >= CAST(:fs_from AS date))
    AND (CAST(:fs_to AS date) IS NULL OR r.first_seen <= CAST(:fs_to AS date))
    AND (CAST(:del_from AS date) IS NULL OR r.deleted_on >= CAST(:del_from AS date))
    AND (CAST(:del_to AS date) IS NULL OR r.deleted_on <= CAST(:del_to AS date))
    AND (CAST(:p AS text) IS NULL OR {_SEARCH} ILIKE :p ESCAPE '\\')
"""


@dataclass(frozen=True)
class ResourceFilters:
    """What the Resources list is narrowed to. An empty tuple or None does not filter; a tuple
    matches any of its values. Deleted resources are left out unless asked for, or unless a
    removed-on bound is set, which keeps removed resources only. `assets`: only the types the
    Overview counts as assets (is_asset, stored as resource.asset by migration 0045). `within`:
    parameter-free SQL exported by another module, each selecting the resource ids to keep, all
    of them applied (the Vulnerabilities and Misconfigurations filters,
    findings.VULNERABLE_RESOURCES_SQL and its siblings)."""

    connection_ids: tuple[int, ...] = ()
    resource_types: tuple[str, ...] = ()
    regions: tuple[str, ...] = ()
    q: str | None = None
    include_deleted: bool = False
    assets: bool = False
    first_seen_from: date | None = None
    first_seen_to: date | None = None
    deleted_from: date | None = None
    deleted_to: date | None = None
    within: tuple[str, ...] = ()


def _any(values: tuple[Any, ...]) -> list[Any] | None:
    return list(values) if values else None


def _params(f: ResourceFilters) -> dict[str, Any]:
    removed = f.deleted_from is not None or f.deleted_to is not None
    return {
        "c": _any(f.connection_ids),
        "t": _any(f.resource_types),
        "rg": _any(f.regions),
        "assets": f.assets,
        "deleted": f.include_deleted or removed,
        "fs_from": f.first_seen_from,
        "fs_to": f.first_seen_to,
        "del_from": f.deleted_from,
        "del_to": f.deleted_to,
        "p": like_contains(f.q) if f.q else None,
    }


def list_resources(
    conn: Connection,
    *,
    limit: int,
    offset: int,
    filters: ResourceFilters = ResourceFilters(),  # noqa: B008 - frozen, never mutated
    order: ResourceOrder = "name_asc",
) -> tuple[list[dict[str, Any]], int]:
    """One page of resources matching the filters, in `order`, and how many match (with a
    search, at most SEARCH_COUNT_CAP + 1)."""
    f = filters
    where = _FILTERS + "".join(f" AND r.id IN ({within})" for within in f.within)
    params = _params(f)
    rows = conn.execute(
        text(f"""
        SELECT r.id, r.resource_uid, r.connection_id, r.provider, r.region, r.type, r.native_id,
               r.name, r.vpc_id, r.first_seen, r.last_seen, r.deleted_on
        FROM resource r
        {where}
        ORDER BY {_ORDERS[order]} LIMIT :l OFFSET :o
    """),  # noqa: S608 - fixed fragments only
        {**params, "l": limit, "o": offset},
    )
    total = conn.execute(
        text(count_sql(f"FROM resource r {where}", search=bool(f.q))),
        params,
    ).scalar_one()
    return [dict(r._mapping) for r in rows], int(total)


def resource_facets(
    conn: Connection, *, connection_ids: tuple[int, ...] = ()
) -> dict[str, list[str]]:
    """The types and regions in the inventory of these connections (all when empty), for the
    Type and Region filters."""
    params = {"c": _any(connection_ids)}
    where = "WHERE CAST(:c AS bigint[]) IS NULL OR connection_id = ANY(CAST(:c AS bigint[]))"
    types = conn.execute(
        text(f"SELECT DISTINCT type FROM resource {where} ORDER BY type"),  # noqa: S608
        params,
    )
    regions = conn.execute(
        text(f"SELECT DISTINCT region FROM resource {where} ORDER BY region"),  # noqa: S608
        params,
    )
    return {"types": [r.type for r in types], "regions": [r.region for r in regions]}


def resource_names(conn: Connection, resource_ids: list[int]) -> dict[int, str]:
    """The display name of each of these resources: its name, or its native id when it has
    none. Called with one page of ids, so the input is bounded."""
    if not resource_ids:
        return {}
    rows = conn.execute(
        text(
            "SELECT id, coalesce(name, native_id) AS label FROM resource "
            "WHERE id = ANY(CAST(:ids AS bigint[]))"
        ),
        {"ids": resource_ids},
    )
    return {r.id: r.label for r in rows}


def resource_at(conn: Connection, *, resource_id: int, day: date) -> dict[str, Any] | None:
    """The resource with its configuration as of `day`. The configuration was redacted at
    ingest; it is returned whole for display and never queried into here. `seen_on` is None
    when the resource was not in that day's inventory."""
    head = conn.execute(
        text("""
        SELECT id, resource_uid, connection_id, provider, region, type, native_id, name, vpc_id,
               tags, first_seen, last_seen, deleted_on
        FROM resource WHERE id = :r
    """),
        {"r": resource_id},
    ).one_or_none()
    if head is None:
        return None
    resource = dict(head._mapping)
    snapshot_day = effective_day(conn, connection_id=resource["connection_id"], day=day)
    config = None
    if snapshot_day is not None:
        config = conn.execute(
            text("""
            SELECT c.config FROM resource_snapshot s JOIN resource_config c ON c.id = s.config_id
            WHERE s.snapshot_date = :d AND s.resource_id = :r
        """),
            {"d": snapshot_day, "r": resource_id},
        ).scalar()
    resource["as_of"] = day
    resource["seen_on"] = snapshot_day if config is not None else None
    resource["config"] = config
    return resource
