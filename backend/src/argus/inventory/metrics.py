"""Inventory rollups for the Overview and the Resources summary: assets by type and by region,
and the assets added and removed each load, per connection and for all.

The names are defined once by their reader, metrics.summary.ASSETS. Assets only: the types
inventory.is_asset counts (stored as resource.asset, migration 0045)."""

from datetime import date

from sqlalchemy import Connection, text

from argus import metrics
from argus.metrics import summary

ASSETS = summary.ASSETS
# The state metrics a failed Steampipe run carries forward (pipeline._fail); the events are a
# flow, and a failed run added and removed nothing.
INVENTORY_METRICS = list(ASSETS.state_metrics)


def _values(conn: Connection, connection_id: int, day: date) -> dict[tuple[str, str], float]:
    values = ASSETS.zero()
    total = 0
    for resource_type, region, n in conn.execute(
        text("""
            SELECT r.type, r.region, count(*) FROM resource_snapshot s JOIN resource r
              ON r.id = s.resource_id
            WHERE s.snapshot_date = :d AND r.connection_id = :c AND r.asset
            GROUP BY r.type, r.region
        """),
        {"d": day, "c": connection_id},
    ):
        for key in ((summary.ASSETS_BY_TYPE, resource_type), (summary.ASSETS_BY_REGION, region)):
            values[key] = values.get(key, 0) + n
        total += n
    values[(summary.ASSETS_TOTAL, "")] = total  # the marker: written on every load, 0 included
    # A connection's first load is its starting inventory, not additions (owner, 2026-11-06).
    first_load = not conn.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM resource_load "
            "WHERE connection_id = :c AND snapshot_date < :d)"
        ),
        {"c": connection_id, "d": day},
    ).scalar_one()
    added, removed = conn.execute(
        text("""
            SELECT count(*) FILTER (WHERE first_seen = :d),
                   count(*) FILTER (WHERE deleted_on = :d)
            FROM resource
            WHERE connection_id = :c AND asset AND (first_seen = :d OR deleted_on = :d)
        """),
        {"c": connection_id, "d": day},
    ).one()
    values[(ASSETS.events, "added")] = 0 if first_load else added
    values[(ASSETS.events, "removed")] = removed
    values[(ASSETS.events, "baseline")] = 1 if first_load else 0
    return values


def put_inventory_metrics(conn: Connection, *, connection_id: int, day: date) -> None:
    """After a Steampipe load: the day's assets of one connection, then all connections on that
    day and on every later day that carried this connection's previous counts."""
    values = _values(conn, connection_id, day)
    metrics.put(conn, day=day, connection_id=connection_id, values=values, replace=ASSETS.metrics)
    carried = metrics.carried_days(
        conn, after=day, metrics=[ASSETS.marker[0]], connection_id=connection_id
    )
    for rolled in [day, *carried]:
        rollup_inventory_metrics(conn, day=rolled)


def rollup_inventory_metrics(conn: Connection, *, day: date) -> None:
    """All connections' assets on a day: each enabled connection's latest load, however old,
    summed (store.rollup_family on the always-written total)."""
    metrics.rollup_family(conn, day=day, metrics=ASSETS.metrics, marker=ASSETS.marker)
