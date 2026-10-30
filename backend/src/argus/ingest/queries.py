"""Read side of scan_run: the Runs tab, the Overview's context bar, and the scan time each
data list reflects."""

from collections.abc import Sequence
from datetime import date
from typing import Any

from sqlalchemy import Connection, text

from argus.connections import DIRECTORY_SQL

# The Runs list's filters, shared by the page and its count. Constant SQL, parameters only.
_RUN_FILTERS = """
        WHERE (CAST(:c AS bigint) IS NULL OR s.connection_id = :c)
          AND (CAST(:t AS text) IS NULL OR s.tool = :t)
          AND (CAST(:s AS text) IS NULL OR s.status = :s)
          AND (NOT :mp OR cardinality(s.denied_actions) > 0)
"""
# Sort orders the API accepts, mapped to fixed SQL: the request never reaches the query text.
RUN_ORDERS = {
    "started_desc": "s.started_at DESC, s.id DESC",
    "started_asc": "s.started_at ASC, s.id ASC",
}


def list_runs(
    conn: Connection,
    *,
    limit: int,
    offset: int,
    connection_id: int | None,
    tool: str | None,
    status: str | None,
    missing_permissions: bool = False,
    order: str = "started_desc",
) -> tuple[list[dict[str, Any]], int]:
    """One page of runs, newest first by default, and how many match the filters."""
    params = {"c": connection_id, "t": tool, "s": status, "mp": missing_permissions}
    rows = conn.execute(
        text(f"""
        SELECT s.id, s.run_uid, s.raw_path, s.connection_id, c.name AS connection, s.tool,
               s.tool_version, s.source,
               s.snapshot_date, s.status, s.started_at, s.finished_at,
               extract(epoch FROM s.finished_at - s.started_at)::int AS duration_seconds,
               s.exit_code, s.throttle_events, s.api_regions, s.region_scope, s.ingested_at,
               s.denied_actions, s.raw_encryption, s.command, s.incomplete_tables,
               s.refused_actions, s.not_applicable_tables, s.refused_tables,
               right(coalesce(s.log_tail, ''), 2000) AS log_tail
        FROM scan_run s JOIN ({DIRECTORY_SQL}) c ON c.id = s.connection_id
        {_RUN_FILTERS}
        ORDER BY {RUN_ORDERS[order]} LIMIT :l OFFSET :o
    """),  # noqa: S608 - exported SQL constants and a fixed ORDER BY only
        {**params, "l": limit, "o": offset},
    )
    total = conn.execute(
        text(f"SELECT count(*) FROM scan_run s {_RUN_FILTERS}"),  # noqa: S608 - constant
        params,
    ).scalar_one()
    return [dict(r._mapping) for r in rows], int(total)


def last_runs(conn: Connection, *, connection_id: int) -> list[dict[str, Any]]:
    """The latest run per tool (and per connection, for "all connections" = 0)."""
    rows = conn.execute(
        text(f"""
        SELECT DISTINCT ON (s.connection_id, s.tool) s.connection_id, c.name AS connection,
               s.tool, s.status, s.snapshot_date, s.finished_at
        FROM scan_run s JOIN ({DIRECTORY_SQL}) c ON c.id = s.connection_id
        WHERE CAST(:c AS bigint) = 0 OR s.connection_id = :c
        ORDER BY s.connection_id, s.tool, s.id DESC
    """),  # noqa: S608 - exported SQL constants only
        {"c": connection_id},
    )
    return [dict(r._mapping) for r in rows]


def data_through(
    conn: Connection,
    *,
    connection_id: int | None = None,
    tools: Sequence[str],
    connection_ids: Sequence[int] = (),
) -> date | None:
    """The newest day an ingested run of these tools covers: the scan time a list of their
    data reflects. Over one connection, several (`connection_ids`), or all when neither is
    given. A failed run contributes nothing; None means no data yet."""
    ids = [connection_id] if connection_id is not None else list(connection_ids)
    found: date | None = conn.execute(
        text("""
        SELECT max(snapshot_date) FROM scan_run
        WHERE (CAST(:c AS bigint[]) IS NULL OR connection_id = ANY(CAST(:c AS bigint[])))
          AND tool = ANY(CAST(:t AS text[]))
          AND status IN ('complete', 'partial') AND ingested_at IS NOT NULL
    """),
        {"c": ids or None, "t": list(tools)},
    ).scalar_one()
    return found


def synthetic_raw_paths_before(conn: Connection, *, day: date) -> list[str]:
    """Raw paths of ingested synthetic runs older than `day`: regenerable from their seed, so
    retention may prune them sooner than real output."""
    rows = conn.execute(
        text("""
        SELECT raw_path FROM scan_run
        WHERE source = 'synthetic' AND ingested_at IS NOT NULL
          AND snapshot_date < :d AND raw_path <> ''
    """),
        {"d": day},
    ).scalars()
    return list(rows)
