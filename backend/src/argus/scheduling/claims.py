"""Claiming run requests: the throttling-aware heart of the worker (ADR-0022, layer 1).

- One claimed request per connection (the database's partial unique index). The three tools
  share an account's API limits, so they never run against it at the same time.
- At most max_parallel_runs claimed requests in total (an administration setting). Claims
  are serialised by a transaction-scoped advisory lock, so the cap is exact across workers.
- Oldest day first, then Steampipe, Prowler, CloudFox: history is built in date order, and a
  day's inventory exists before the findings and paths that refer to it.
- Heartbeats prove a claim is alive. release_stale() returns a dead worker's claim to the
  queue; without it, one killed worker would stop that account being collected, forever.
- Each claim has its own token in claimed_by, and heartbeat() and finish() match it (ADR-0039).
  A worker whose claim was released and claimed again elsewhere cannot finish or retry the
  other worker's run: its own result is discarded. A run lost MAX_LOST times is not run again.
"""

import random
from collections.abc import Collection
from dataclasses import dataclass
from datetime import date, timedelta
from uuid import uuid4

from sqlalchemy import Connection, text

from argus.connections import DIRECTORY_SQL
from argus.core.redaction import redact_text
from argus.settings import CollectionSettings

CLAIM_LOCK = "argus.run_request.claim"
MAX_ATTEMPTS = 3
# Claims released by the reaper before a run ends as failed: a run that kills its worker (out
# of memory, evicted, past its deadline) would otherwise be requeued forever.
MAX_LOST = 2


@dataclass(frozen=True)
class ClaimedRequest:
    id: int
    connection_id: int
    tool: str
    reason: str
    snapshot_date: date | None
    attempt: int
    # The schedule behind the first attempt (a retry keeps it), and that attempt's reason: a
    # retry of a scheduled run stops when its schedule is disabled or deleted.
    schedule_id: int | None = None
    origin: str | None = None
    # This claim's own claimed_by: heartbeat() and finish() match it.
    token: str = ""
    # How many earlier claims of this request the reaper released.
    lost: int = 0


# The reason of a request's first attempt: retries chain through retry_of, at most two hops
# (MAX_ATTEMPTS). Falls back to the request's own reason when the chain was cut.
ORIGIN_SQL = """COALESCE(
          (SELECT o.reason FROM run_request o
           WHERE o.id = (SELECT coalesce(p.retry_of, p.id) FROM run_request p
                         WHERE p.id = rr.retry_of)), rr.reason)"""
# A scheduled request (or a retry of one) runs only while its schedule exists and is enabled.
# A retry of a scheduled run from before retries kept the schedule has none: it is not live.
_SCHEDULE_LIVE = f"""(rr.schedule_id IS NULL AND {ORIGIN_SQL} <> 'schedule'
          OR EXISTS (SELECT 1 FROM schedule s WHERE s.id = rr.schedule_id AND s.enabled))"""  # noqa: S608


# A request that may be claimed now: queued and due, its connection enabled, its schedule live,
# and no other request of its connection claimed. `c` is the connection (with its kind).
_CLAIMABLE = f"""run_request rr JOIN ({DIRECTORY_SQL}) c ON c.id = rr.connection_id AND c.enabled
        WHERE rr.status = 'queued' AND rr.not_before <= now()
          AND {_SCHEDULE_LIVE}
          AND NOT EXISTS (SELECT 1 FROM run_request x
                          WHERE x.connection_id = rr.connection_id AND x.status = 'claimed')"""  # noqa: S608


def claim(
    conn: Connection,
    *,
    worker_id: str,
    settings: CollectionSettings,
    kinds: Collection[str] | None = None,
) -> ClaimedRequest | None:
    """Claims the next request, of a connection of one of `kinds` when given (a Kubernetes run
    Job claims only its kind's work, ADR-0039)."""
    conn.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": CLAIM_LOCK})
    if claimed_count(conn) >= settings.max_parallel_runs:
        return None
    row = conn.execute(
        text(f"""
        SELECT rr.id, rr.connection_id, rr.tool, rr.reason, rr.snapshot_date, rr.attempt,
               rr.schedule_id, rr.lost, {ORIGIN_SQL} AS origin
        FROM {_CLAIMABLE}
          AND (CAST(:kinds AS text[]) IS NULL OR c.kind = ANY (CAST(:kinds AS text[])))
        ORDER BY rr.snapshot_date NULLS LAST,
                 CASE rr.tool WHEN 'steampipe' THEN 1 WHEN 'prowler' THEN 2 ELSE 3 END,
                 rr.not_before, rr.id
        LIMIT 1
        FOR UPDATE OF rr SKIP LOCKED
    """),  # noqa: S608 - exported SQL constants only
        {"kinds": sorted(kinds) if kinds is not None else None},
    ).one_or_none()
    if row is None:
        return None
    # The worker's id (its host name, the pod's on Kubernetes) plus a token for this claim.
    token = f"{worker_id}:{uuid4().hex[:12]}"
    conn.execute(
        text("""
        UPDATE run_request SET status = 'claimed', claimed_by = :w, claimed_at = now(),
          heartbeat_at = now()
        WHERE id = :i
    """),
        {"w": token, "i": row.id},
    )
    return ClaimedRequest(
        row.id,
        row.connection_id,
        row.tool,
        row.reason,
        row.snapshot_date,
        row.attempt,
        row.schedule_id,
        row.origin,
        token,
        row.lost,
    )


def claimed_count(conn: Connection) -> int:
    """Requests claimed now, by any worker or Job: what the global cap counts."""
    count: int = conn.execute(
        text("SELECT count(*) FROM run_request WHERE status = 'claimed'")
    ).scalar_one()
    return count


def claimed_by_kind(conn: Connection) -> dict[str, int]:
    """Requests claimed now, per connection kind (the scheduler's in-flight count)."""
    rows = conn.execute(
        text(f"""
        SELECT c.kind, count(*) FROM run_request rr
        JOIN ({DIRECTORY_SQL}) c ON c.id = rr.connection_id
        WHERE rr.status = 'claimed' GROUP BY c.kind
    """)  # noqa: S608 - exported SQL constants only
    ).all()
    return {kind: int(n) for kind, n in rows}


def claimable_connections(conn: Connection) -> dict[str, int]:
    """Per connection kind, how many connections have a request that may be claimed now. Only
    one request per connection runs at a time, so this, not the number of requests, is how
    many runs could start: a backfill of hundreds of rows on one connection is one."""
    rows = conn.execute(
        text(f"SELECT c.kind, count(DISTINCT rr.connection_id) FROM {_CLAIMABLE} GROUP BY c.kind")  # noqa: S608
    ).all()
    return {kind: int(n) for kind, n in rows}


def heartbeat(conn: Connection, request: ClaimedRequest) -> bool:
    """Refreshes the claim. False when it is no longer this worker's: released by the reaper,
    and perhaps claimed again elsewhere."""
    return bool(
        conn.execute(
            text("""
        UPDATE run_request SET heartbeat_at = now()
        WHERE id = :i AND status = 'claimed' AND claimed_by = :t
    """),
            {"i": request.id, "t": request.token},
        ).rowcount
    )


def finish(
    conn: Connection,
    request: ClaimedRequest,
    *,
    scan_run_id: int | None,
    error: str | None = None,
) -> bool:
    """Ends the claim. False when it is no longer this worker's: nothing is written, and the
    caller must not retry the run either."""
    return bool(
        conn.execute(
            text("""
        UPDATE run_request SET status = 'finished', finished_at = now(), scan_run_id = :r,
          error = :e
        WHERE id = :i AND status = 'claimed' AND claimed_by = :t
    """),
            # Error text can quote tool output or exception messages: redacted before it is stored.
            {
                "i": request.id,
                "t": request.token,
                "r": scan_run_id,
                "e": redact_text(error) if error else None,
            },
        ).rowcount
    )


def release_stale(conn: Connection, *, older_than: timedelta) -> int:
    """Returns claims whose worker stopped heart-beating to the queue, counting the loss."""
    released: int = conn.execute(
        text("""
        UPDATE run_request SET status = 'queued', claimed_by = NULL, claimed_at = NULL,
          heartbeat_at = NULL, lost = lost + 1,
          error = right(coalesce(error || E'\\n', '') || 'worker lost; requeued at '
                        || now()::text, 2000)
        WHERE status = 'claimed' AND heartbeat_at < now() - CAST(:age AS interval)
    """),
        {"age": f"{int(older_than.total_seconds())} seconds"},
    ).rowcount
    return released


def retry(conn: Connection, request: ClaimedRequest, *, settings: CollectionSettings) -> int | None:
    """Queues another attempt after a failed run, with jittered backoff. Backfills
    never retry: synthetic history is deterministic and a retry would repeat it. A retry keeps
    the first attempt's schedule and who asked; a scheduled run whose schedule was disabled or
    deleted meanwhile is not retried."""
    if request.reason == "backfill" or request.attempt >= MAX_ATTEMPTS:
        return None
    base = settings.retry_delays_minutes[request.attempt - 1]
    delay = timedelta(minutes=base * random.uniform(1.0, 1.2))  # noqa: S311 - jitter, not crypto
    new_id: int | None = conn.execute(
        text(f"""
        INSERT INTO run_request (connection_id, tool, reason, schedule_id, snapshot_date,
                                 not_before, attempt, retry_of, requested_by)
        SELECT rr.connection_id, rr.tool, 'retry', rr.schedule_id, rr.snapshot_date,
               now() + CAST(:delay AS interval), :a, rr.id, rr.requested_by
        FROM run_request rr
        WHERE rr.id = :of AND {_SCHEDULE_LIVE}
        RETURNING id
    """),  # noqa: S608 - constant SQL only
        {
            "delay": f"{int(delay.total_seconds())} seconds",
            "a": request.attempt + 1,
            "of": request.id,
        },
    ).scalar_one_or_none()
    return new_id


# A schedule's queued request is still wanted while the schedule is enabled and still covers
# that tool and that connection.
_STILL_IN_SCHEDULE = """EXISTS (
          SELECT 1 FROM schedule s
          WHERE s.id = rr.schedule_id AND s.enabled AND rr.tool = ANY (s.tools)
            AND (s.all_connections OR EXISTS (
              SELECT 1 FROM schedule_connection sc
              WHERE sc.schedule_id = s.id AND sc.connection_id = rr.connection_id)))"""


def cancel_queued(
    conn: Connection, *, schedule_id: int | None = None, whole_schedule: bool = False
) -> list[int]:
    """Cancels queued requests that may no longer run, and returns their ids.

    With `schedule_id`: that schedule's requests it no longer covers, after an edit (disabled,
    a tool or a connection taken out), or all of them with `whole_schedule` (before a delete).
    Without: every queued request whose schedule is disabled or gone, the worker's backstop
    for a tick that raced an edit."""
    if schedule_id is None:
        where = f"NOT {_SCHEDULE_LIVE}"
    elif whole_schedule:
        where = "rr.schedule_id = :s"
    else:
        where = f"rr.schedule_id = :s AND NOT {_STILL_IN_SCHEDULE}"
    ids: list[int] = list(
        conn.execute(
            text(f"""
        UPDATE run_request rr SET status = 'cancelled', finished_at = now()
        WHERE rr.status = 'queued' AND {where}
        RETURNING rr.id
    """),  # noqa: S608 - constant SQL only
            {"s": schedule_id},
        )
        .scalars()
        .all()
    )
    return ids


def cancel(conn: Connection, request_id: int) -> bool:
    """Cancels one queued request. False when it is not queued (claimed, finished, gone): a
    running request is not stopped from here."""
    return bool(
        conn.execute(
            text("""
        UPDATE run_request SET status = 'cancelled', finished_at = now()
        WHERE id = :i AND status = 'queued'
    """),
            {"i": request_id},
        ).rowcount
    )


def recently_completed(
    conn: Connection, *, connection_id: int, tool: str, cooldown_minutes: int
) -> bool:
    """Run now cooldown: the same tool and account finished within the cooldown, or one is
    already queued or running. Backfill requests do not count: they rebuild history from the
    synthetic source and make no cloud API call, and the cooldown protects API limits."""
    return bool(
        conn.execute(
            text("""
        SELECT EXISTS (
          SELECT 1 FROM run_request WHERE connection_id = :c AND tool = :t
            AND reason <> 'backfill'
            AND (status IN ('queued', 'claimed')
                 OR (status = 'finished'
                     AND finished_at > now() - CAST(:cool AS interval))))
    """),
            {"c": connection_id, "t": tool, "cool": f"{cooldown_minutes} minutes"},
        ).scalar_one()
    )
