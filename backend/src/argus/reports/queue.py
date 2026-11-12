"""The report queue (ADR-0047): an Operator or Admin asks, the worker (Docker Compose) or a report
Job (Kubernetes) builds, the API serves.

The API inserts the request's own columns only (migrations 0047, 0050), so it can never mark a
report ready or point it at a file; the builder writes the build's columns only.

A report building for longer than STALE_AFTER_SECONDS was abandoned (its builder stopped). Every
read here shows it Failed at once, with STALE_ERROR, and it no longer counts as open; the next
report Job writes that failure (fail_stale)."""

import json
from datetime import date
from typing import Any

from sqlalchemy import Connection, text

from argus.connections import DIRECTORY_SQL
from argus.core import audit
from argus.core.redaction import redact_text
from argus.findings import FindingFilters
from argus.reports.filters import to_json
from argus.reports.model import (
    EXPIRY_DAYS,
    LOCAL_STORE_KINDS,
    MAX_OPEN_PER_USER,
    STALE_AFTER_SECONDS,
    STALE_ERROR,
    ClaimedReport,
    ReportFormat,
    ReportKind,
    ReportRefusedError,
    ReportRow,
)

DEMO_ONLY = (
    "Reports on this install cover Demo connections only. Filter the list to Demo accounts, "
    "or choose them in New report."
)
if "'" in STALE_ERROR:  # it is written into SQL as a literal below
    raise ValueError("STALE_ERROR must hold no quote")
# Abandoned: still building long after it started. STALE_AFTER_SECONDS is an int constant.
STALE = f"(status = 'building' AND started_at < now() - interval '{STALE_AFTER_SECONDS} seconds')"
_COLUMNS = f"""
    id, kind, format, filters, connection_ids, requested_by_id, requested_by,
    CASE WHEN {STALE} THEN 'failed' ELSE status END AS status,
    requested_at, started_at, finished_at, expires_at,
    (expires_at IS NOT NULL AND expires_at <= now()) AS expired,
    file_deleted_at, storage_key, storage_bucket, storage_region, size_bytes, sha256, row_count,
    truncated, data_through,
    CASE WHEN {STALE} THEN '{STALE_ERROR}' ELSE error END AS error
"""


def resolve_scope(conn: Connection, connection_ids: tuple[int, ...]) -> list[tuple[int, str]]:
    """The connections a report covers, with their kind: those asked for that exist, or every
    connection when none is asked for (the list shows them all the same way)."""
    rows = conn.execute(
        text(f"""
        SELECT d.id, d.kind FROM ({DIRECTORY_SQL}) d
        WHERE CAST(:c AS bigint[]) IS NULL OR d.id = ANY(CAST(:c AS bigint[]))
        ORDER BY d.id
    """),  # noqa: S608 - exported SQL constants only
        {"c": list(connection_ids) or None},
    )
    return [(r.id, r.kind) for r in rows]


def check_scope(scope: list[tuple[int, str]], *, local: bool) -> None:
    """Refuses an empty scope, and on a local store any connection that is not Demo."""
    if not scope:
        raise ReportRefusedError("No account matches this report's filters.")
    if local and any(kind not in LOCAL_STORE_KINDS for _, kind in scope):
        raise ReportRefusedError(DEMO_ONLY)


def request_report(
    conn: Connection,
    *,
    kind: ReportKind,
    fmt: ReportFormat,
    filters: FindingFilters,
    user_id: int,
    username: str,
    client_ip: str | None,
    bucket: tuple[str, str] | None = None,
) -> int:
    """Queues a report over the filters' accounts, resolved now. `bucket` is the (bucket,
    region) an S3 report goes to, recorded with it; None is the local store. Refused
    (ReportRefusedError) when no account matches, when one is a real AWS connection on a local
    store, or when the user already has MAX_OPEN_PER_USER open. The caller commits."""
    scope = resolve_scope(conn, filters.connection_ids)
    check_scope(scope, local=bucket is None)
    # One user's requests in turn, so two at once cannot both pass the cap.
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtext('argus.reports.request'), CAST(:u AS int))"),
        {"u": user_id},
    )
    open_count = conn.execute(
        text(f"""
        SELECT count(*) FROM report_request
        WHERE requested_by_id = :u AND status IN ('queued', 'building') AND NOT {STALE}
    """),  # noqa: S608 - a constant predicate
        {"u": user_id},
    ).scalar_one()
    if open_count >= MAX_OPEN_PER_USER:
        raise ReportRefusedError(
            f"You have {MAX_OPEN_PER_USER} reports being built. Wait for one to finish."
        )
    report_id: int = conn.execute(
        text("""
        INSERT INTO report_request
          (kind, format, filters, connection_ids, requested_by_id, requested_by, storage_bucket,
           storage_region)
        VALUES (:k, :f, CAST(:filters AS jsonb), CAST(:c AS bigint[]), :u, :n, :b, :r)
        RETURNING id
    """),
        {
            "k": kind,
            "f": fmt,
            "filters": json.dumps(to_json(filters)),
            "c": [cid for cid, _ in scope],
            "u": user_id,
            "n": username,
            "b": bucket[0] if bucket else None,
            "r": bucket[1] if bucket else None,
        },
    ).scalar_one()
    audit.record(
        conn,
        actor=username,
        action="report.requested",
        target_type="report",
        target_id=str(report_id),
        detail={"kind": kind, "format": fmt, "connections": len(scope)},
        client_ip=client_ip,
    )
    return report_id


def _row(mapping: Any) -> ReportRow:
    values = dict(mapping)
    through = values["data_through"]
    if through is not None:
        values["data_through"] = {int(k): date.fromisoformat(v) for k, v in through.items()}
    return ReportRow(**values)


def list_reports(
    conn: Connection, *, user_id: int, all_users: bool, limit: int, offset: int
) -> tuple[list[ReportRow], int]:
    """Newest first: the user's own, or everyone's for an Admin."""
    params = {"u": user_id, "all": all_users}
    rows = conn.execute(
        text(f"""
        SELECT {_COLUMNS} FROM report_request
        WHERE :all OR requested_by_id = :u
        ORDER BY requested_at DESC, id DESC
        LIMIT :l OFFSET :o
    """),  # noqa: S608 - constant column list
        {**params, "l": limit, "o": offset},
    )
    total = conn.execute(
        text("SELECT count(*) FROM report_request WHERE :all OR requested_by_id = :u"), params
    ).scalar_one()
    return [_row(r._mapping) for r in rows], int(total)


def get_report(conn: Connection, report_id: int) -> ReportRow | None:
    row = conn.execute(
        text(f"SELECT {_COLUMNS} FROM report_request WHERE id = :i"),  # noqa: S608
        {"i": report_id},
    ).first()
    return _row(row._mapping) if row else None


def claim_report(conn: Connection) -> ClaimedReport | None:
    """The oldest queued report, now building; None when nothing is queued."""
    row = conn.execute(
        text("""
        UPDATE report_request SET status = 'building', started_at = now()
        WHERE id = (
          SELECT id FROM report_request WHERE status = 'queued'
          ORDER BY requested_at, id LIMIT 1 FOR UPDATE SKIP LOCKED
        )
        RETURNING id, kind, format, filters, connection_ids, requested_by, storage_bucket,
                  storage_region
    """)
    ).first()
    return ClaimedReport(**row._mapping) if row else None


def finish_report(
    conn: Connection,
    report_id: int,
    *,
    storage_key: str,
    size_bytes: int,
    sha256: str,
    row_count: int,
    truncated: bool,
    data_through: dict[int, Any],
) -> bool:
    """Ready, expiring EXPIRY_DAYS from now. False when the report is no longer building (it
    was failed meanwhile): the caller then removes the file."""
    updated = conn.execute(
        text(f"""
        UPDATE report_request
        SET status = 'ready', finished_at = now(),
            expires_at = now() + interval '{EXPIRY_DAYS} days',
            storage_key = :k, size_bytes = :s, sha256 = :h, row_count = :n, truncated = :t,
            data_through = CAST(:d AS jsonb)
        WHERE id = :i AND status = 'building'
    """),  # noqa: S608 - EXPIRY_DAYS is an int constant
        {
            "i": report_id,
            "k": storage_key,
            "s": size_bytes,
            "h": sha256,
            "n": row_count,
            "t": truncated,
            "d": json.dumps({str(k): v.isoformat() for k, v in data_through.items()}),
        },
    )
    return updated.rowcount == 1


def fail_report(conn: Connection, report_id: int, message: str) -> None:
    conn.execute(
        text("""
        UPDATE report_request SET status = 'failed', finished_at = now(), error = :e
        WHERE id = :i AND status = 'building'
    """),
        {"i": report_id, "e": redact_text(message)[:2000] or "failed"},
    )


def fail_abandoned(conn: Connection) -> int:
    """Fails every report left building: called when the worker's report thread starts, so a
    build a stopped worker held does not stay Building. One worker per Docker Compose install
    builds reports, so nothing else can be building at that moment."""
    return conn.execute(
        text("""
        UPDATE report_request
        SET status = 'failed', finished_at = now(),
            error = 'The worker stopped while building this report. Request it again.'
        WHERE status = 'building'
    """)
    ).rowcount


def fail_stale(conn: Connection) -> int:
    """Writes the failure of every abandoned report (see STALE): run by a report Job before it
    claims, since Kubernetes has no worker start to end them. Reads already show them Failed."""
    return conn.execute(
        text(f"""
        UPDATE report_request
        SET status = 'failed', finished_at = now(), error = :e
        WHERE {STALE}
    """),  # noqa: S608 - a constant predicate
        {"e": STALE_ERROR},
    ).rowcount


def queued_reports(conn: Connection) -> int:
    """How many reports wait for a builder: the Kubernetes scheduler starts report Jobs for
    them (it may read status and started_at only, migration 0050)."""
    queued = conn.execute(text("SELECT count(*) FROM report_request WHERE status = 'queued'"))
    return int(queued.scalar_one())


def kept_keys(conn: Connection) -> set[str]:
    """The keys of every file a report still names: ready, and not yet deleted by retention."""
    rows = conn.execute(
        text(
            "SELECT storage_key FROM report_request "
            "WHERE status = 'ready' AND file_deleted_at IS NULL"
        )
    )
    return {r.storage_key for r in rows}


def expired_files(conn: Connection) -> list[str]:
    """The keys of ready reports past their expiry whose file is still kept, marked deleted.
    The caller deletes the files after its transaction commits."""
    rows = conn.execute(
        text("""
        UPDATE report_request SET file_deleted_at = now()
        WHERE status = 'ready' AND file_deleted_at IS NULL AND expires_at <= now()
        RETURNING storage_key
    """)
    )
    return [r.storage_key for r in rows]
