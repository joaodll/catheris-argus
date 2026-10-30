"""Executing a claimed run request, for the Compose worker (ADR-0019) and a Kubernetes run Job
(ADR-0039) alike. The queue's upkeep is maintenance.py; the loops are worker.py and job.py.

Every path that runs a collection goes through execute(): collect -> register the run ->
ingest -> finish the request -> retry if the run failed. An exception anywhere
still finishes the request with its error, so a request is never left claimed by a live worker,
and still records a failed run, so the Runs tab says why instead of showing nothing.

A claim the reaper released (its heartbeat stopped long enough) is no longer this worker's: the
run stops before registering anything, or its result is discarded at the finish, and another
worker runs the request again (ADR-0039). A request lost MAX_LOST times ends as a failed run.
"""

import logging
import threading
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import Engine
from sqlalchemy.exc import StatementError

from argus import connections
from argus.collection import (
    AwsAccess,
    CollectOptions,
    CollectTarget,
    access_for,
    collect,
    source_for,
    store_for,
)
from argus.connections import ConnectionRow
from argus.core.rawstore import FilesystemRawStore, RawStore
from argus.ingest import ingest_run, register_failed_run, register_run
from argus.scheduling import claims
from argus.settings import CollectionSettings, read_collection

log = logging.getLogger("argus.worker")
HEARTBEAT_EVERY = timedelta(seconds=30)
# A run holds at most three connections at once: ingest's re-derive lock, one transaction beside
# it, and the heartbeat (core.db.require_pool).
RUN_CONNECTIONS = 3


@dataclass
class _Attempt:
    """What one request's execution has learnt so far: enough to record a failed run for it
    whatever step went wrong."""

    request: claims.ClaimedRequest
    day: date
    store: RawStore
    run_uid: UUID = field(default_factory=uuid4)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    connection: ConnectionRow | None = None
    settings: CollectionSettings | None = None
    path: str | None = None  # where collect archived the run
    scan_run_id: int | None = None
    # Set by the heartbeat when the claim is no longer this worker's.
    lost: threading.Event = field(default_factory=threading.Event)


class _ClaimLost(Exception):
    """The claim was released while the run executed: another worker owns the request now."""


class _LostTooOften(Exception):
    """The request's earlier claims were lost MAX_LOST times: it is not run again."""


def execute(
    engine: Engine,
    *,
    store: FilesystemRawStore,
    rules_dir: Path,
    request: claims.ClaimedRequest,
    today: date,
) -> str:
    """Runs one claimed request to the end. Returns the run status, "lost" when the claim
    was released meanwhile, or "error"."""
    stop_heartbeat = threading.Event()
    attempt = _Attempt(request=request, day=request.snapshot_date or today, store=store)

    def beat() -> None:
        while not stop_heartbeat.wait(HEARTBEAT_EVERY.total_seconds()):
            try:
                with engine.begin() as conn:
                    alive = claims.heartbeat(conn, request)
            except Exception:  # one failed beat must not end them all; the next one retries
                log.exception("heartbeat failed", extra={"request_id": request.id})
                continue
            if not alive:
                log.warning("claim lost while running", extra={"request_id": request.id})
                attempt.lost.set()
                return

    beater = threading.Thread(target=beat, name=f"heartbeat-{request.id}", daemon=True)
    beater.start()
    try:
        status = _collect_and_ingest(engine, attempt, local=store, rules_dir=rules_dir)
    except _ClaimLost:
        log.warning("claim lost; result discarded", extra={"request_id": request.id})
        status = "lost"
    except _LostTooOften as exc:
        status = _end_with_error(engine, attempt, rules_dir=rules_dir, error=str(exc), retry=False)
    except Exception as exc:  # the request must end, whatever went wrong
        log.exception("run request failed", extra={"request_id": request.id})
        status = _end_with_error(engine, attempt, rules_dir=rules_dir, error=describe_error(exc))
    finally:
        if attempt.path is not None:
            attempt.store.release(attempt.path)  # the S3 staging copy; the archive keeps the run
        stop_heartbeat.set()
        beater.join(timeout=5)
    log.info(
        "run request finished",
        extra={
            "request_id": request.id,
            "tool": request.tool,
            "status": status,
            "scan_run_id": attempt.scan_run_id,
        },
    )
    return status


def _collect_and_ingest(
    engine: Engine, attempt: _Attempt, *, local: FilesystemRawStore, rules_dir: Path
) -> str:
    request = attempt.request
    with engine.connect() as conn:
        connection = attempt.connection = connections.get(conn, request.connection_id)
        settings = attempt.settings = read_collection(conn)
        aws_access: AwsAccess | None = None
        if connection is not None:
            attempt.store = store_for(conn, connection.kind, local=local)
            if connection.kind == "aws":
                aws_access = access_for(conn, connection)
    if connection is None:
        raise LookupError(f"connection {request.connection_id} no longer exists")
    if request.lost >= claims.MAX_LOST:
        raise _LostTooOften(
            f"lost {request.lost} times while running (killed, out of memory, evicted or past "
            "its deadline); not run again"
        )
    log.info(
        "run started",
        extra={
            "request_id": request.id,
            "connection_id": connection.id,
            "tool": request.tool,
            "attempt": request.attempt,
            "day": attempt.day.isoformat(),
        },
    )
    attempt.path, manifest = collect(
        source_for(connection.kind),
        attempt.store,
        target=CollectTarget(
            connection.id, connection.kind, connection.account_id, connection.demo_seed
        ),
        tool=request.tool,  # type: ignore[arg-type]
        day=attempt.day,
        run_uid=attempt.run_uid,
        options=CollectOptions(
            synthetic_throttle_share=settings.synthetic_throttle_share,
            attempt=request.attempt,
            aws_access=aws_access,
            aws_regions=tuple(settings.aws_regions),
            cloudfox_max_goroutines=settings.cloudfox_max_goroutines,
            steampipe_parallel_tables=settings.steampipe_parallel_tables,
        ),
    )
    if attempt.lost.is_set():
        raise _ClaimLost  # another worker collects it again: register nothing of this one
    with engine.begin() as conn:
        attempt.scan_run_id = register_run(
            conn, connection_id=connection.id, raw_path=attempt.path, manifest=manifest
        )
    outcome = ingest_run(
        engine, store=attempt.store, scan_run_id=attempt.scan_run_id, rules_dir=rules_dir
    )
    with engine.begin() as conn:
        if not claims.finish(conn, request, scan_run_id=attempt.scan_run_id, error=outcome.error):
            raise _ClaimLost
        # A partial run is not retried: its usual cause, actions the scanner role denies by
        # design, would make the retry partial again (decided 2026-10-08, argus_v8).
        if outcome.status == "failed":
            claims.retry(conn, request, settings=settings)
    return outcome.status


def _end_with_error(
    engine: Engine, attempt: _Attempt, *, rules_dir: Path, error: str, retry: bool = True
) -> str:
    """Finishes a request that raised. If no run was registered for it yet, a failed one is,
    so the Runs tab says why; that run is retried like any failed run, unless `retry` is
    False. A claim that was lost meanwhile is left to the worker that holds it now."""
    if attempt.lost.is_set():
        log.warning("claim lost; error discarded", extra={"request_id": attempt.request.id})
        return "lost"
    recorded = False
    if attempt.scan_run_id is None and attempt.connection is not None:
        attempt.scan_run_id = _record_failure(
            engine, attempt, attempt.connection, rules_dir=rules_dir, error=error
        )
        recorded = attempt.scan_run_id is not None
    with engine.begin() as conn:
        finished = claims.finish(
            conn, attempt.request, scan_run_id=attempt.scan_run_id, error=error
        )
        if finished and retry and recorded and attempt.settings is not None:
            claims.retry(conn, attempt.request, settings=attempt.settings)
    return "failed" if recorded else "error"


def describe_error(exc: BaseException) -> str:
    """The error a request ends with. A database error is reduced to the driver's message:
    SQLAlchemy's own text adds the statement and its parameters, which can be a whole log tail."""
    cause = exc.orig if isinstance(exc, StatementError) and exc.orig is not None else exc
    return f"{type(cause).__name__}: {cause}"[:2000]


def _record_failure(
    engine: Engine, attempt: _Attempt, connection: ConnectionRow, *, rules_dir: Path, error: str
) -> int | None:
    """A failed run for a request that ended before its run was registered, sent through ingest
    so the tool's metrics carry forward like any failed run. None if even that cannot be
    written (the database is down): the request still ends, with its error."""
    scan_run_id: int | None = None
    try:
        with engine.begin() as conn:
            scan_run_id = register_failed_run(
                conn,
                connection_id=connection.id,
                tool=attempt.request.tool,
                source=source_for(connection.kind).name,
                day=attempt.day,
                run_uid=attempt.run_uid,
                raw_path=attempt.path or "",
                started_at=attempt.started_at,
                error=error,
            )
        ingest_run(engine, store=attempt.store, scan_run_id=scan_run_id, rules_dir=rules_dir)
    except Exception:
        log.exception("failed run not recorded", extra={"request_id": attempt.request.id})
    return scan_run_id


def run_once(
    engine: Engine,
    *,
    store: FilesystemRawStore,
    rules_dir: Path,
    worker_id: str,
    today: date | None = None,
    kinds: Collection[str] | None = None,
    max_parallel: int | None = None,
) -> str | None:
    """Claims and executes one request, if one is due (of a connection of one of `kinds` when
    given, and while fewer than `max_parallel` run, when it is below the administration
    setting). Returns its status, or None."""
    with engine.begin() as conn:
        settings = read_collection(conn)
        if max_parallel is not None and max_parallel < settings.max_parallel_runs:
            settings = settings.model_copy(update={"max_parallel_runs": max_parallel})
        request = claims.claim(conn, worker_id=worker_id, settings=settings, kinds=kinds)
    if request is None:
        return None
    return execute(
        engine,
        store=store,
        rules_dir=rules_dir,
        request=request,
        today=today or datetime.now(UTC).date(),
    )
