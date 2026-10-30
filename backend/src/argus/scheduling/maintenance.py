"""The queue's upkeep, shared by the Compose worker's main loop (ADR-0019) and, on Kubernetes,
the scheduler (ADR-0039): every minute, schedules become run requests, lost claims go back to
the queue, requests a disabled schedule queued are cancelled, and Test connection requests no
one answered fail. And retention, once a day.

maintain() needs only the scheduler's database role (migration 0030): it reads no secret and
writes no scanned data.
"""

import logging
from datetime import date, datetime, timedelta

from sqlalchemy import Engine, text

from argus.connections import checks
from argus.core.rawstore import FilesystemRawStore
from argus.retention import run_retention
from argus.scheduling import claims, schedules
from argus.settings import read_collection, read_retention

log = logging.getLogger("argus.scheduling")
STALE_AFTER = timedelta(minutes=10)
RETENTION_LOCK = "argus.retention"
# Retention holds its lock on one connection and runs its transactions on another.
RETENTION_CONNECTIONS = 2


def maintain(engine: Engine, *, now: datetime) -> None:
    with engine.begin() as conn:
        created = schedules.tick(conn, now=now, settings=read_collection(conn))
        released = claims.release_stale(conn, older_than=STALE_AFTER)
        cancelled = claims.cancel_queued(conn)  # a tick that raced a schedule's disable
        expired = checks.expire_tests(conn)
    if created or released or cancelled or expired:
        log.info(
            "scheduler tick",
            extra={
                "requests_created": created,
                "claims_released": released,
                "requests_cancelled": len(cancelled),
                "tests_expired": expired,
            },
        )


def daily_retention(
    engine: Engine, *, store: FilesystemRawStore | None, today: date, done_on: date | None
) -> date | None:
    """Runs retention unless it already ran today in this process, or another process is
    running it now. Returns the day it last ran here. `store` is the Demo volume to prune;
    None where demo runs keep nothing (a Kubernetes demo Job)."""
    if done_on == today:
        return done_on
    with engine.connect() as conn:
        if not conn.execute(
            text("SELECT pg_try_advisory_lock(hashtext(:k))"), {"k": RETENTION_LOCK}
        ).scalar_one():
            return done_on  # another process is running it
        try:
            retention = read_retention(conn)
            conn.commit()
            run_retention(
                engine,
                store=store,
                today=today,
                retention_days=retention.history_days,
                demo_raw_days=retention.demo_raw_days,
            )
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": RETENTION_LOCK})
            conn.commit()
    return today
