"""Operate -> Reports (ADR-0047): exports of the Misconfigurations and Vulnerabilities lists.

The API queues a report and serves its file; the Compose worker or a Kubernetes report Job builds
it (the API has a 5 s statement timeout and a capped pool). Operator and Admin only: a report
carries the estate's weak points out of Argus. An Operator sees their own, an Admin everyone's.
Every request and download is audited, and so is every refused download.

Where files live is a deployment fact (core/config.py): a local volume on Docker Compose, the
reports/ folder of the raw-output bucket on Kubernetes with IRSA. On S3 the API reads with its
own IRSA role only (core.aws.web_identity_s3_client), from the bucket recorded on the report."""

import logging
from collections.abc import Iterator
from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from argus import reports
from argus.api import deps
from argus.api.deps import Db, OperatorUser, client_ip
from argus.api.routes.findings import FindingFilterQuery, finding_filters
from argus.api.routes.vulnerabilities import VulnerabilityFilterQuery, vulnerability_filters
from argus.auth import SessionUser
from argus.core import audit
from argus.core.aws import NoWebIdentityError, web_identity_available, web_identity_s3_client
from argus.core.config import get_settings
from argus.settings import read_raw_storage

log = logging.getLogger("argus.api.reports")
router = APIRouter(tags=["reports"])

# Why this install can't take a report now, as a sentence for the person asking (422).
UNAVAILABLE: dict[str, str] = {
    "off": (
        "This install keeps no reports. On Kubernetes they need IRSA roles for the API and the "
        "report Job."
    ),
    "no_identity": "Reports can't be stored: the API has no IRSA identity. See the install notes.",
    "no_bucket": (
        "Reports go to the raw-output bucket, and none is set. Set Raw output storage first."
    ),
}
MEDIA_TYPES: dict[str, str] = {"csv": "text/csv; charset=utf-8", "pdf": "application/pdf"}
# local: a local volume, Demo connections only (Docker Compose). s3: the reports/ folder of the
# raw-output bucket, every connection (Kubernetes with IRSA). The others: no report can be
# requested now, and UNAVAILABLE says why.
Storage = Literal["local", "s3", "off", "no_identity", "no_bucket"]


class MisconfigurationReportIn(BaseModel):
    kind: Literal["misconfigurations"]
    format: reports.ReportFormat = "csv"
    filters: FindingFilterQuery = Field(default_factory=FindingFilterQuery)


class VulnerabilityReportIn(BaseModel):
    kind: Literal["vulnerabilities"]
    format: reports.ReportFormat = "csv"
    filters: VulnerabilityFilterQuery = Field(default_factory=VulnerabilityFilterQuery)


ReportIn = Annotated[MisconfigurationReportIn | VulnerabilityReportIn, Field(discriminator="kind")]


class ReportQueued(BaseModel):
    id: int


class ReportOut(BaseModel):
    id: int
    kind: reports.ReportKind
    format: reports.ReportFormat
    # The list's filters as the report runs them (FindingFilters' fields); for "filters in
    # words" on the screen.
    filters: dict[str, Any]
    # The accounts the report covers, resolved when it was requested.
    connection_ids: list[int]
    requested_by: str
    # queued and building: the screen keeps polling; failed: `error` says why.
    status: reports.ReportStatus
    requested_at: datetime
    finished_at: datetime | None
    expires_at: datetime | None
    # Past expires_at: the file is refused whatever storage still holds.
    expired: bool
    # Ready, not expired and still kept: Download is offered.
    downloadable: bool
    size_bytes: int | None
    row_count: int | None
    # Cut at the row cap: the file holds the first `row_count` rows only.
    truncated: bool
    # Each account's newest scanned day the report reflects, by connection id.
    data_through: dict[str, date] | None
    error: str | None


class ReportPage(BaseModel):
    items: list[ReportOut]
    total: int
    # Where this install keeps reports, or why it can't now (see Storage).
    storage: Storage
    row_cap: int
    expiry_days: int
    max_open: int


def _storage(conn: Connection) -> tuple[Storage, tuple[str, str] | None]:
    """Where a report requested now would go: the storage kind, and for S3 the (bucket, region)
    to record on it."""
    settings = get_settings()
    if settings.reports_root is not None:
        return "local", None
    if settings.reports_store != "s3":
        return "off", None
    if not web_identity_available():
        return "no_identity", None
    raw = read_raw_storage(conn)
    if raw.bucket is None or raw.region is None:
        return "no_bucket", None
    return "s3", (raw.bucket, raw.region)


def _store_for(row: reports.ReportRow) -> reports.ReportStore | None:
    """The store holding this report's file: where it was built. None when this install can't
    read it (no store, or a report made for another kind of store)."""
    settings = get_settings()
    if settings.reports_root is not None:
        if row.storage_bucket is not None:
            return None
        return reports.LocalReportStore(settings.reports_root)
    if settings.reports_store != "s3" or row.storage_bucket is None or row.storage_region is None:
        return None
    try:
        client = web_identity_s3_client(row.storage_region)
    except NoWebIdentityError as exc:
        raise reports.ReportStoreUnavailableError(str(exc)) from exc
    return reports.S3ReportStore(client, row.storage_bucket)


def _out(row: reports.ReportRow) -> ReportOut:
    return ReportOut(
        id=row.id,
        kind=row.kind,
        format=row.format,
        filters=row.filters,
        connection_ids=row.connection_ids,
        requested_by=row.requested_by,
        status=row.status,
        requested_at=row.requested_at,
        finished_at=row.finished_at,
        expires_at=row.expires_at,
        expired=row.expired,
        downloadable=row.status == "ready" and not row.expired and row.file_deleted_at is None,
        size_bytes=row.size_bytes,
        row_count=row.row_count,
        truncated=row.truncated,
        data_through=(
            {str(k): v for k, v in row.data_through.items()} if row.data_through else None
        ),
        error=row.error,
    )


def _visible(row: reports.ReportRow | None, user: SessionUser) -> reports.ReportRow | None:
    if row is None or (user.role != "admin" and row.requested_by_id != user.id):
        return None
    return row


@router.get("/reports")
def list_reports(
    conn: Db,
    user: OperatorUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ReportPage:
    """Newest first: the user's own reports, or everyone's for an Admin."""
    rows, total = reports.list_reports(
        conn, user_id=user.id, all_users=user.role == "admin", limit=limit, offset=offset
    )
    return ReportPage(
        items=[_out(r) for r in rows],
        total=total,
        storage=_storage(conn)[0],
        row_cap=reports.ROW_CAP,
        expiry_days=reports.EXPIRY_DAYS,
        max_open=reports.MAX_OPEN_PER_USER,
    )


@router.post("/reports", status_code=status.HTTP_202_ACCEPTED)
def request_report(body: ReportIn, conn: Db, user: OperatorUser, request: Request) -> ReportQueued:
    """Queues a report over the list's filters. Refused (422, with a sentence) where this
    install can't keep a report now, when no account matches, when an account is a real AWS
    connection on a local store, or when the user has too many reports being built."""
    storage, bucket = _storage(conn)
    if storage not in ("local", "s3"):
        raise reports.ReportRefusedError(UNAVAILABLE[storage])
    filters = (
        finding_filters(body.filters)
        if isinstance(body, MisconfigurationReportIn)
        else vulnerability_filters(body.filters)
    )
    report_id = reports.request_report(
        conn,
        kind=body.kind,
        fmt=body.format,
        filters=filters,
        user_id=user.id,
        username=user.username,
        client_ip=client_ip(request),
        bucket=bucket,
    )
    conn.commit()
    return ReportQueued(id=report_id)


@router.get("/reports/{report_id}")
def get_report(report_id: int, conn: Db, user: OperatorUser) -> ReportOut:
    row = _visible(reports.get_report(conn, report_id), user)
    if row is None:
        raise LookupError(report_id)
    return _out(row)


def _refuse(
    conn: Connection, user: SessionUser, request: Request, report_id: int, reason: str, code: int
) -> HTTPException:
    audit.record(
        conn,
        actor=user.username,
        action="report.refused",
        target_type="report",
        target_id=str(report_id),
        detail={"reason": reason},
        client_ip=client_ip(request),
    )
    conn.commit()
    messages = {
        "not_found": "not found",
        "expired": "This report has expired. Request it again.",
        "file_missing": "This report's file is no longer kept. Request it again.",
        "file_changed": (
            "This report's file is not the one Argus built, so it is not served. Request it again."
        ),
        "store_unavailable": "Reports' storage can't be reached now. Try again in a minute.",
    }
    return HTTPException(code, messages[reason])


def _refuse_after(
    user: SessionUser, request: Request, report_id: int, reason: str, code: int
) -> HTTPException:
    """_refuse on a short connection of its own, once the request's has gone back to the pool."""
    with deps.short_connection() as conn:
        return _refuse(conn, user, request, report_id, reason, code)


@router.get(
    "/reports/{report_id}/download",
    response_class=StreamingResponse,
    responses={
        200: {
            "content": {"text/csv": {}, "application/pdf": {}},
            "description": "The report's file, as its format says.",
        }
    },
)
def download_report(
    report_id: int, conn: Db, user: OperatorUser, request: Request
) -> StreamingResponse:
    """The report's file, as an attachment. The key comes from the row only, and must have a
    report key's shape. The file is served only when it is the one the build recorded (its size,
    and on S3 its SHA-256), checked before the first byte. The database connection is released
    before the file streams, so a slow download never holds a slot of the API's capped pool."""
    row = reports.get_report(conn, report_id)
    if row is None:
        raise LookupError(report_id)
    if _visible(row, user) is None:
        raise _refuse(conn, user, request, report_id, "not_found", status.HTTP_404_NOT_FOUND)
    if row.status != "ready":
        raise HTTPException(status.HTTP_409_CONFLICT, "This report is not ready.")
    if row.expired:
        raise _refuse(conn, user, request, report_id, "expired", status.HTTP_410_GONE)
    key, size, digest = row.storage_key, row.size_bytes, row.sha256
    if key is None or size is None or digest is None or row.file_deleted_at is not None:
        raise _refuse(conn, user, request, report_id, "file_missing", status.HTTP_410_GONE)
    # Back to the pool before the store is asked: on S3 that is a network call, with retries,
    # that must never hold a slot of the API's capped pool. The outcome is audited afterwards on a
    # short connection of its own. (The dependency's own close runs only after the response.)
    conn.commit()
    conn.close()
    try:
        store = _store_for(row)
        if store is None:
            raise reports.ReportStoreError("not readable on this install")
        chunks = store.open(key, size_bytes=size, sha256=digest)
    except reports.ReportFileChangedError:
        log.warning("report file changed since it was built", extra={"report_id": report_id})
        raise _refuse_after(
            user, request, report_id, "file_changed", status.HTTP_410_GONE
        ) from None
    except reports.ReportStoreError:
        raise _refuse_after(
            user, request, report_id, "file_missing", status.HTTP_410_GONE
        ) from None
    except reports.ReportStoreUnavailableError as exc:
        log.warning("report store unavailable", extra={"report_id": report_id, "why": str(exc)})
        raise _refuse_after(
            user, request, report_id, "store_unavailable", status.HTTP_503_SERVICE_UNAVAILABLE
        ) from None
    try:
        with deps.short_connection() as audit_conn:
            audit.record(
                audit_conn,
                actor=user.username,
                action="report.downloaded",
                target_type="report",
                target_id=str(report_id),
                detail={"kind": row.kind, "format": row.format, "bytes": size},
                client_ip=client_ip(request),
            )
            audit_conn.commit()
    except Exception:
        _close(chunks)
        raise
    return StreamingResponse(
        chunks,
        media_type=MEDIA_TYPES[row.format],
        headers={
            "Content-Disposition": f'attachment; filename="argus-{row.kind}-{row.id}.{row.format}"',
            "Content-Length": str(size),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


def _close(chunks: Iterator[bytes]) -> None:
    close = getattr(chunks, "close", None)
    if close is not None:
        close()
