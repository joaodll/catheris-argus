"""Operate -> Reports (ADR-0047): exports of the Misconfigurations and Vulnerabilities lists.

The API queues a report and serves its file; the worker builds it (the API has a 5 s statement
timeout and a capped pool). Operator and Admin only: a report carries the estate's weak points
out of Argus. An Operator sees their own, an Admin everyone's. Every request and download is
audited, and so is every refused download."""

from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from argus import reports
from argus.api.deps import Db, OperatorUser, client_ip
from argus.api.routes.findings import FindingFilterQuery, finding_filters
from argus.api.routes.vulnerabilities import VulnerabilityFilterQuery, vulnerability_filters
from argus.auth import SessionUser
from argus.core import audit
from argus.core.config import get_settings

router = APIRouter(tags=["reports"])

NOT_AVAILABLE = "Reports are not available on this install yet."


class MisconfigurationReportIn(BaseModel):
    kind: Literal["misconfigurations"]
    format: Literal["csv"] = "csv"
    filters: FindingFilterQuery = Field(default_factory=FindingFilterQuery)


class VulnerabilityReportIn(BaseModel):
    kind: Literal["vulnerabilities"]
    format: Literal["csv"] = "csv"
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
    # local: this install keeps reports on a local volume, for Demo connections only (Docker
    # Compose); off: it keeps none, and requests are refused (Kubernetes, until S3).
    storage: Literal["local", "off"]
    row_cap: int
    expiry_days: int
    max_open: int


def _store() -> reports.LocalReportStore | None:
    root = get_settings().reports_root
    return reports.LocalReportStore(root) if root else None


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
        storage="local" if _store() else "off",
        row_cap=reports.ROW_CAP,
        expiry_days=reports.EXPIRY_DAYS,
        max_open=reports.MAX_OPEN_PER_USER,
    )


@router.post("/reports", status_code=status.HTTP_202_ACCEPTED)
def request_report(body: ReportIn, conn: Db, user: OperatorUser, request: Request) -> ReportQueued:
    """Queues a report over the list's filters. Refused (422, with a sentence) where this
    install keeps no reports, when no account matches, when an account is a real AWS
    connection on a local store, or when the user has too many reports being built."""
    if _store() is None:
        raise reports.ReportRefusedError(NOT_AVAILABLE)
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
    conn: Db, user: SessionUser, request: Request, report_id: int, reason: str, code: int
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
    }
    return HTTPException(code, messages[reason])


@router.get(
    "/reports/{report_id}/download",
    response_class=FileResponse,
    responses={200: {"content": {"text/csv": {}}, "description": "The report's file."}},
)
def download_report(report_id: int, conn: Db, user: OperatorUser, request: Request) -> FileResponse:
    """The report's file, as an attachment. The key comes from the row only, and resolves
    inside the reports folder or is refused. The database connection is released before the
    file streams, so a slow download never holds a slot of the API's capped pool."""
    store = _store()
    row = reports.get_report(conn, report_id)
    if row is None:
        raise LookupError(report_id)
    if _visible(row, user) is None:
        raise _refuse(conn, user, request, report_id, "not_found", status.HTTP_404_NOT_FOUND)
    if row.status != "ready":
        raise HTTPException(status.HTTP_409_CONFLICT, "This report is not ready.")
    if row.expired:
        raise _refuse(conn, user, request, report_id, "expired", status.HTTP_410_GONE)
    if store is None or row.storage_key is None or row.file_deleted_at is not None:
        raise _refuse(conn, user, request, report_id, "file_missing", status.HTTP_410_GONE)
    try:
        path = store.path(row.storage_key)
    except reports.ReportStoreError:
        raise _refuse(
            conn, user, request, report_id, "file_missing", status.HTTP_410_GONE
        ) from None
    if not path.is_file():
        raise _refuse(conn, user, request, report_id, "file_missing", status.HTTP_410_GONE)
    audit.record(
        conn,
        actor=user.username,
        action="report.downloaded",
        target_type="report",
        target_id=str(report_id),
        detail={"kind": row.kind, "format": row.format, "bytes": row.size_bytes},
        client_ip=client_ip(request),
    )
    conn.commit()
    # Back to the pool now: the dependency's own close runs only after the response is sent.
    conn.close()
    return FileResponse(
        path,
        media_type="text/csv; charset=utf-8",
        filename=f"argus-{row.kind}-{row.id}.csv",
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )
