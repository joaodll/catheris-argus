"""Read side of inventory: the Resources list and its filter options, and a resource as it
was on a given day."""

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Literal

from sqlalchemy import Connection, text

from argus.core.db import count_sql, like_contains

# A day's inventory is the latest snapshot within this window (the ingest carry-forward), so a
# failed Steampipe run does not make every resource vanish.
CARRY_FORWARD_DAYS = 31

# Exported SQL. Other modules embed these instead of naming inventory's tables, so a change
# to resource, resource_config or resource_snapshot is made here and nowhere else.

# The view relationship and attack-path rules read as `r`: one connection's resources as of
# :resource_day (bind it to effective_day()).
RESOURCES_ON_DAY_SQL = """
  SELECT res.resource_uid AS uid, res.type, res.native_id, res.name, res.region, res.vpc_id,
         cfg.config
  FROM resource_snapshot s
  JOIN resource res ON res.id = s.resource_id
  JOIN resource_config cfg ON cfg.id = s.config_id
  WHERE s.snapshot_date = :resource_day AND res.connection_id = :connection_id
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
    """The snapshot that stands for `day`: the latest on or before it, within the window."""
    value: date | None = conn.execute(
        text("""
        SELECT max(s.snapshot_date) FROM resource_snapshot s JOIN resource r ON r.id = s.resource_id
        WHERE r.connection_id = :c AND s.snapshot_date BETWEEN :start AND :d
    """),
        {"c": connection_id, "d": day, "start": day - timedelta(days=CARRY_FORWARD_DAYS)},
    ).scalar()
    return value


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
  WHERE (CAST(:c AS bigint) IS NULL OR r.connection_id = :c)
    AND (CAST(:t AS text) IS NULL OR r.type = :t)
    AND (CAST(:rg AS text) IS NULL OR r.region = :rg)
    AND (CAST(:deleted AS boolean) OR r.deleted_on IS NULL)
    AND (CAST(:p AS text) IS NULL OR {_SEARCH} ILIKE :p ESCAPE '\\')
"""


@dataclass(frozen=True)
class ResourceFilters:
    """What the Resources list is narrowed to; None does not filter. Deleted resources are left
    out unless asked for. `within`: parameter-free SQL exported by another module, selecting
    the resource ids to keep (the Vulnerabilities filter, findings.VULNERABLE_RESOURCES_SQL)."""

    connection_id: int | None = None
    resource_type: str | None = None
    region: str | None = None
    q: str | None = None
    include_deleted: bool = False
    within: str | None = None


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
    where = f"{_FILTERS} AND r.id IN ({f.within})" if f.within else _FILTERS
    params = {
        "c": f.connection_id,
        "t": f.resource_type,
        "rg": f.region,
        "deleted": f.include_deleted,
        "p": like_contains(f.q) if f.q else None,
    }
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


def resource_facets(conn: Connection, *, connection_id: int | None) -> dict[str, list[str]]:
    """The types and regions in the inventory, for the Type and Region filters."""
    params = {"c": connection_id}
    where = "WHERE CAST(:c AS bigint) IS NULL OR connection_id = :c"
    types = conn.execute(
        text(f"SELECT DISTINCT type FROM resource {where} ORDER BY type"),  # noqa: S608
        params,
    )
    regions = conn.execute(
        text(f"SELECT DISTINCT region FROM resource {where} ORDER BY region"),  # noqa: S608
        params,
    )
    return {"types": [r.type for r in types], "regions": [r.region for r in regions]}


# Exported SQL: one row per inventoried resource, as a node of the Resource map (ADR-0033).
# Joined by uid, so another module can place resources on a graph without naming the table.
RESOURCE_NODES_SQL = """
  SELECT id, resource_uid AS uid, type, coalesce(name, native_id) AS name, region,
         connection_id, deleted_on
  FROM resource
"""


def resource_nodes(conn: Connection, uids: list[str]) -> dict[str, dict[str, Any]]:
    """The inventoried resources among these uids, as map nodes. Bounded by the caller (a map
    response holds at most 500 nodes)."""
    if not uids:
        return {}
    rows = conn.execute(
        text(f"SELECT * FROM ({RESOURCE_NODES_SQL}) n WHERE n.uid = ANY(CAST(:u AS text[]))"),  # noqa: S608 - constant SQL
        {"u": uids},
    )
    return {r.uid: dict(r._mapping) for r in rows}


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
