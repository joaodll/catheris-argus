"""Schedules -> run requests (design: "Schedules screen"; ADR-0019, ADR-0022).

tick() turns each enabled schedule's latest due occurrence into one request per connection and
tool, in tool order.
The database dedupes occurrences (run_request_one_per_occurrence), so any number of workers
may tick. Accounts start at a deterministic offset inside the stagger window, so a schedule
never sends every account to the cloud APIs at the same minute (throttling layer 1).

An occurrence earlier than the schedule's last change is skipped: a schedule edited at 10:05
to "every day at 10:00" runs tomorrow at 10:00, not immediately.
"""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise

from cronsim import CronSim, CronSimError
from sqlalchemy import Connection, text

from argus.collection import TOOL_ORDER
from argus.connections import DIRECTORY_SQL
from argus.settings import CollectionSettings

# A worker that was down longer than this does not replay the occurrences it missed.
CATCH_UP = timedelta(hours=24)


class InvalidScheduleError(ValueError):
    pass


@dataclass(frozen=True)
class CronCheck:
    expression: str
    explanation: str
    next_runs: list[datetime]


def check_cron(
    expression: str, *, min_interval_minutes: int, now: datetime | None = None
) -> CronCheck:
    """Validates a cron expression for a schedule and explains it in plain language. Refuses
    expressions that fire more often than the minimum interval (an administration setting)."""
    start = now or datetime.now(UTC)
    try:
        sim = CronSim(expression, start)
        runs = [next(sim) for _ in range(6)]
    except (CronSimError, StopIteration) as exc:
        raise InvalidScheduleError(f"invalid cron expression: {exc}") from None
    shortest = min(b - a for a, b in pairwise(runs))
    if shortest < timedelta(minutes=min_interval_minutes):
        raise InvalidScheduleError(
            f"runs every {int(shortest.total_seconds() // 60)} minutes; the minimum interval "
            f"is {min_interval_minutes} minutes"
        )
    return CronCheck(expression, CronSim(expression, start).explain(), runs[:3])


def stagger_offset(connection_id: int, schedule_id: int, window_minutes: int) -> timedelta:
    if window_minutes <= 0:
        return timedelta(0)
    digest = hashlib.sha256(f"{schedule_id}|{connection_id}".encode()).digest()
    return timedelta(minutes=int.from_bytes(digest[:4], "big") % window_minutes)


def _latest_occurrence(expression: str, now: datetime) -> datetime | None:
    try:
        return next(CronSim(expression, now, reverse=True))
    except (CronSimError, StopIteration):
        return None


def tick(conn: Connection, *, now: datetime, settings: CollectionSettings) -> int:
    """Queues each enabled schedule's latest due occurrence. Returns requests created."""
    created = 0
    schedules = conn.execute(
        text("SELECT id, tools, cron, all_connections, updated_at FROM schedule WHERE enabled")
    ).all()
    for schedule in schedules:
        occurrence = _latest_occurrence(schedule.cron, now)
        if occurrence is None or occurrence < schedule.updated_at or now - occurrence > CATCH_UP:
            continue
        targets = (
            conn.execute(
                text(f"""
            SELECT c.id FROM ({DIRECTORY_SQL}) c
            WHERE c.enabled AND (:all OR EXISTS (
              SELECT 1 FROM schedule_connection sc
              WHERE sc.schedule_id = :s AND sc.connection_id = c.id))
        """),  # noqa: S608 - exported SQL constants only
                {"all": schedule.all_connections, "s": schedule.id},
            )
            .scalars()
            .all()
        )
        requests = [
            (connection_id, tool)
            for connection_id in targets
            for tool in TOOL_ORDER
            if tool in schedule.tools
        ]
        for connection_id, tool in requests:
            not_before = occurrence + stagger_offset(
                connection_id, schedule.id, settings.stagger_window_minutes
            )
            created += conn.execute(
                text("""
                INSERT INTO run_request (connection_id, tool, reason, schedule_id, occurrence_at,
                                         snapshot_date, not_before, requested_by)
                VALUES (:c, :tool, 'schedule', :s, :o, :d, :nb, 'scheduler')
                ON CONFLICT (schedule_id, connection_id, tool, occurrence_at)
                  WHERE schedule_id IS NOT NULL AND occurrence_at IS NOT NULL
                DO NOTHING
            """),
                {
                    "c": connection_id,
                    "tool": tool,
                    "s": schedule.id,
                    "o": occurrence,
                    "d": occurrence.date(),
                    "nb": not_before,
                },
            ).rowcount
    return created
