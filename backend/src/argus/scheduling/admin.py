"""What administrators do with schedules and runs, from the UI: create, change and delete
schedules (validated cron, minimum interval), and Run now (with the cooldown). Every write is
audited in the caller's transaction."""

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Literal

from sqlalchemy import Connection, text

from argus.collection import TOOL_ORDER
from argus.connections import DIRECTORY_SQL
from argus.core import audit
from argus.core.db import like_contains
from argus.scheduling.claims import ORIGIN_SQL, cancel, cancel_queued, recently_completed
from argus.scheduling.schedules import check_cron
from argus.settings import read_collection

Tool = Literal["steampipe", "prowler", "cloudfox", "vulnerabilities"]


@dataclass(frozen=True)
class ScheduleView:
    id: int
    name: str
    tools: list[str]
    cron: str
    explanation: str
    next_runs: list[datetime]
    all_connections: bool
    connection_ids: list[int]
    enabled: bool
    updated_at: datetime
    updated_by: str


@dataclass(frozen=True)
class RunNowResult:
    queued: list[dict[str, object]]
    refused: list[dict[str, object]]


_SCHEDULE_SELECT = """
        SELECT s.id, s.name, s.tools, s.cron, s.all_connections, s.enabled, s.updated_at,
               s.updated_by,
               COALESCE(array_agg(sc.connection_id) FILTER (WHERE sc.connection_id IS NOT NULL),
                        '{}') AS connection_ids
        FROM schedule s LEFT JOIN schedule_connection sc ON sc.schedule_id = s.id
"""


def _view(r: Any) -> ScheduleView:
    check = check_cron(r.cron, min_interval_minutes=1)
    return ScheduleView(
        r.id,
        r.name,
        list(r.tools),
        r.cron,
        check.explanation,
        check.next_runs,
        r.all_connections,
        list(r.connection_ids),
        r.enabled,
        r.updated_at,
        r.updated_by,
    )


def list_schedules(
    conn: Connection, *, q: str | None, limit: int, offset: int
) -> tuple[list[ScheduleView], int]:
    """One page of schedules by name, those whose name contains `q` (any case), and how many
    match."""
    params = {"p": like_contains(q) if q else None}
    where = "WHERE (CAST(:p AS text) IS NULL OR s.name ILIKE :p ESCAPE '\\')"
    rows = conn.execute(
        text(f"{_SCHEDULE_SELECT} {where} GROUP BY s.id ORDER BY s.name, s.id LIMIT :l OFFSET :o"),
        {**params, "l": limit, "o": offset},
    ).all()
    total = conn.execute(
        text(f"SELECT count(*) FROM schedule s {where}"),  # noqa: S608 - constant
        params,
    ).scalar_one()
    return [_view(r) for r in rows], int(total)


def get_schedule(conn: Connection, schedule_id: int) -> ScheduleView | None:
    row = conn.execute(
        text(f"{_SCHEDULE_SELECT} WHERE s.id = :i GROUP BY s.id"),
        {"i": schedule_id},
    ).one_or_none()
    return _view(row) if row else None


def _ordered(tools: list[Tool]) -> list[Tool]:
    """The schedule's tools, each once, in tool order (the order its runs are queued in)."""
    chosen = [t for t in TOOL_ORDER if t in tools]
    if not chosen:
        raise ValueError("a schedule needs at least one tool")
    return chosen


def _scope(conn: Connection, schedule_id: int, connection_ids: list[int] | None) -> None:
    conn.execute(text("DELETE FROM schedule_connection WHERE schedule_id = :s"), {"s": schedule_id})
    if connection_ids:
        conn.execute(
            text("INSERT INTO schedule_connection (schedule_id, connection_id) VALUES (:s, :c)"),
            [{"s": schedule_id, "c": c} for c in connection_ids],
        )


def create_schedule(
    conn: Connection,
    *,
    name: str,
    tools: list[Tool],
    cron: str,
    connection_ids: list[int] | None,
    enabled: bool,
    actor: str,
    client_ip: str | None = None,
) -> int:
    chosen = _ordered(tools)
    check_cron(cron, min_interval_minutes=read_collection(conn).schedule_min_interval_minutes)
    schedule_id: int = conn.execute(
        text("""
        INSERT INTO schedule (name, tools, cron, all_connections, enabled, updated_by)
        VALUES (:n, :t, :c, :all, :e, :a) RETURNING id
    """),
        {"n": name, "t": chosen, "c": cron, "all": not connection_ids, "e": enabled, "a": actor},
    ).scalar_one()
    _scope(conn, schedule_id, connection_ids)
    audit.record(
        conn,
        actor=actor,
        action="schedule.create",
        target_type="schedule",
        target_id=str(schedule_id),
        client_ip=client_ip,
        detail={"tools": chosen, "cron": cron, "connections": connection_ids or "all"},
    )
    return schedule_id


def update_schedule(
    conn: Connection,
    *,
    schedule_id: int,
    name: str,
    tools: list[Tool],
    cron: str,
    connection_ids: list[int] | None,
    enabled: bool,
    actor: str,
    client_ip: str | None = None,
) -> None:
    chosen = _ordered(tools)
    check_cron(cron, min_interval_minutes=read_collection(conn).schedule_min_interval_minutes)
    updated = conn.execute(
        text("""
        UPDATE schedule SET name = :n, tools = :t, cron = :c, all_connections = :all,
          enabled = :e, updated_by = :a, updated_at = now()
        WHERE id = :i
    """),
        {
            "i": schedule_id,
            "n": name,
            "t": chosen,
            "c": cron,
            "all": not connection_ids,
            "e": enabled,
            "a": actor,
        },
    ).rowcount
    if not updated:
        raise LookupError(schedule_id)
    _scope(conn, schedule_id, connection_ids)
    # Queued runs the schedule no longer covers (disabled, a tool or an account taken out)
    # would otherwise still start, up to the stagger window later.
    cancelled = cancel_queued(conn, schedule_id=schedule_id)
    audit.record(
        conn,
        actor=actor,
        action="schedule.update",
        target_type="schedule",
        target_id=str(schedule_id),
        client_ip=client_ip,
        detail={"tools": chosen, "cron": cron, "enabled": enabled, "cancelled": cancelled},
    )


def delete_schedule(
    conn: Connection, *, schedule_id: int, actor: str, client_ip: str | None = None
) -> None:
    """Deletes a schedule and cancels its queued runs. History is kept: finished requests and
    their runs stay, without the link to the schedule."""
    cancelled = cancel_queued(conn, schedule_id=schedule_id, whole_schedule=True)
    if not conn.execute(text("DELETE FROM schedule WHERE id = :i"), {"i": schedule_id}).rowcount:
        raise LookupError(schedule_id)
    audit.record(
        conn,
        actor=actor,
        action="schedule.delete",
        target_type="schedule",
        target_id=str(schedule_id),
        client_ip=client_ip,
        detail={"cancelled": cancelled},
    )


def cancel_request(
    conn: Connection, *, request_id: int, actor: str, client_ip: str | None = None
) -> None:
    """Cancels one queued run request (a waiting retry, a staggered scheduled run, a Run now).
    A cancelled request is never retried. Raises LookupError when it is not queued: a running
    request is not stopped from here."""
    if not cancel(conn, request_id):
        raise LookupError(request_id)
    audit.record(
        conn,
        actor=actor,
        action="run.cancel",
        target_type="run_request",
        target_id=str(request_id),
        client_ip=client_ip,
    )


def run_now(
    conn: Connection,
    *,
    connection_ids: list[int],
    tools: list[Tool] | None,
    actor: str,
    client_ip: str | None = None,
    today: date | None = None,
) -> RunNowResult:
    """Queues the tools (default: every tool, in order) for each connection, except where the
    same tool and account is queued, running, or finished within the cooldown."""
    cooldown = read_collection(conn).run_now_cooldown_minutes
    day = today or datetime.now(UTC).date()
    queued: list[dict[str, object]] = []
    refused: list[dict[str, object]] = []
    for connection_id in connection_ids:
        for tool in [t for t in TOOL_ORDER if tools is None or t in tools]:
            item: dict[str, object] = {"connection_id": connection_id, "tool": tool}
            if recently_completed(
                conn, connection_id=connection_id, tool=tool, cooldown_minutes=cooldown
            ):
                refused.append(
                    {
                        **item,
                        "reason": f"queued, running or finished within the last {cooldown} minutes",
                    }
                )
                continue
            conn.execute(
                text("""
                INSERT INTO run_request (connection_id, tool, reason, snapshot_date, requested_by)
                VALUES (:c, :t, 'manual', :d, :a)
            """),
                {"c": connection_id, "t": tool, "d": day, "a": actor},
            )
            queued.append(item)
    if queued:
        audit.record(
            conn,
            actor=actor,
            action="run.request",
            target_type="run_request",
            client_ip=client_ip,
            detail={"queued": queued},
        )
    return RunNowResult(queued, refused)


def pending_requests(conn: Connection, *, limit: int) -> list[dict[str, object]]:
    rows = conn.execute(
        text(f"""
        SELECT rr.id, rr.connection_id, c.name AS connection, rr.tool, rr.reason, rr.status,
               rr.attempt, rr.snapshot_date, rr.not_before, rr.claimed_at, rr.heartbeat_at
        FROM run_request rr JOIN ({DIRECTORY_SQL}) c ON c.id = rr.connection_id
        WHERE rr.status IN ('queued', 'claimed')
        -- Running first, so the first page always shows them; then claim order.
        ORDER BY rr.status = 'claimed' DESC, rr.not_before, rr.id LIMIT :l
    """),  # noqa: S608 - exported SQL constants only
        {"l": limit},
    )
    return [dict(r._mapping) for r in rows]


def pending_counts(conn: Connection) -> tuple[int, list[dict[str, object]]]:
    """Exact counts behind the queue's first page: every waiting or running request, and the
    backfill requests still left per connection."""
    rows = conn.execute(
        text(f"""
        SELECT rr.connection_id, c.name AS connection, count(*) AS waiting,
               count(*) FILTER (WHERE rr.reason = 'backfill') AS backfill_left
        FROM run_request rr JOIN ({DIRECTORY_SQL}) c ON c.id = rr.connection_id
        WHERE rr.status IN ('queued', 'claimed')
        GROUP BY rr.connection_id, c.name ORDER BY c.name
    """)  # noqa: S608 - exported SQL constants only
    ).all()
    total = sum(r.waiting for r in rows)
    backfills: list[dict[str, object]] = [
        {"connection_id": r.connection_id, "connection": r.connection, "left": r.backfill_left}
        for r in rows
        if r.backfill_left
    ]
    return total, backfills


@dataclass(frozen=True)
class RunTrigger:
    """Why a run happened: the request behind it, and the first attempt's reason when it is a
    retry. `schedule` is the schedule's name while it exists."""

    reason: str  # schedule | manual | retry | backfill
    origin: str  # the first attempt's reason
    schedule: str | None
    requested_by: str
    attempt: int


def run_triggers(conn: Connection, scan_run_ids: list[int]) -> dict[int, RunTrigger]:
    """The trigger of each run on a page of the Runs list, in one query. A run whose request
    is gone (deleted with its connection) has no entry."""
    if not scan_run_ids:
        return {}
    rows = conn.execute(
        text(f"""
        SELECT rr.scan_run_id, rr.reason, rr.requested_by, rr.attempt, s.name AS schedule,
               {ORIGIN_SQL} AS origin
        FROM run_request rr LEFT JOIN schedule s ON s.id = rr.schedule_id
        WHERE rr.scan_run_id = ANY (:ids)
    """),  # noqa: S608 - constant SQL only
        {"ids": scan_run_ids},
    ).all()
    return {
        r.scan_run_id: RunTrigger(r.reason, r.origin, r.schedule, r.requested_by, r.attempt)
        for r in rows
    }
