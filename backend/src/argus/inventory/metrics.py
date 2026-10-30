"""Inventory rollups for the Overview: assets by type, per connection and for all."""

from datetime import date

from sqlalchemy import Connection, text

from argus import metrics
from argus.inventory.steampipe import is_asset

INVENTORY_METRICS = ["assets.by_type", "assets.total"]


def put_inventory_metrics(conn: Connection, *, connection_id: int, day: date) -> None:
    values: dict[tuple[str, str], float] = {}
    total = 0
    for resource_type, n in conn.execute(
        text("""
            SELECT r.type, count(*) FROM resource_snapshot s JOIN resource r
              ON r.id = s.resource_id
            WHERE s.snapshot_date = :d AND r.connection_id = :c
            GROUP BY r.type
        """),
        {"d": day, "c": connection_id},
    ):
        if not is_asset(resource_type):
            continue
        values[("assets.by_type", resource_type)] = n
        total += n
    values[("assets.total", "")] = total
    metrics.put(
        conn, day=day, connection_id=connection_id, values=values, replace=INVENTORY_METRICS
    )
    metrics.rollup(conn, day=day, metrics=INVENTORY_METRICS)
