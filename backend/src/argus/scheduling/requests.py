"""Creating run requests. Every path that asks for collection goes through here."""

from datetime import date, timedelta

from sqlalchemy import Connection, Engine, text

from argus import connections
from argus.collection import TOOL_ORDER
from argus.connections import ConnectionRow
from argus.core import audit

MAX_BACKFILL_DAYS = 400


def request_backfill(
    conn: Connection, *, connection: ConnectionRow, days: int, today: date, actor: str
) -> int:
    """Queues one request per day and tool, oldest day first and in tool order, so the worker
    builds history in date order. Returns the number of requests queued."""
    if connection.kind != "demo":
        raise ValueError("backfill is only possible for demo connections")
    if not 1 <= days <= MAX_BACKFILL_DAYS:
        raise ValueError(f"days must be between 1 and {MAX_BACKFILL_DAYS}")
    rows = [
        {"c": connection.id, "t": tool, "d": today - timedelta(days=offset), "a": actor}
        for offset in range(days - 1, -1, -1)
        for tool in TOOL_ORDER
    ]
    conn.execute(
        text(
            "INSERT INTO run_request (connection_id, tool, reason, snapshot_date, requested_by) "
            "VALUES (:c, :t, 'backfill', :d, :a)"
        ),
        rows,
    )
    return len(rows)


def create_demo_connection(
    engine: Engine, *, name: str, seed: int, days: int, today: date, actor: str
) -> tuple[ConnectionRow, int]:
    """The single implementation behind the UI's "add Demo connection" and the seed command:
    the connection, its backfill and the audit entry, in one transaction."""
    with engine.begin() as conn:
        connection = connections.create_demo(conn, name=name, seed=seed, actor=actor)
        queued = request_backfill(conn, connection=connection, days=days, today=today, actor=actor)
        audit.record(
            conn,
            actor=actor,
            action="connection.create",
            target_type="connection",
            target_id=str(connection.id),
            detail={"kind": "demo", "seed": seed, "backfill_days": days},
        )
    return connection, queued
