"""Builds one queued report (ADR-0047), in three steps that never share a transaction:

1. claim the oldest queued report;
2. read its rows in ONE read-only REPEATABLE READ transaction (findings are the current state,
   not a day's snapshot, so a scan loading meanwhile cannot mix two states into one file),
   re-checking the scope first, and write them to a hidden file beside the final one. A CSV is
   written while reading; a PDF is read first, and drawn by the renderer after the transaction
   closes (pdf.py);
3. record the result. A failure of any kind fails the report with a redacted reason and
   removes what was written."""

import hashlib
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from sqlalchemy import Connection, Engine

from argus import findings, ingest, inventory
from argus.core.process import IsolatedRunError
from argus.findings import FindingFilters
from argus.reports import filters as report_filters
from argus.reports import pdf, queue
from argus.reports.csv_report import CsvReport
from argus.reports.model import (
    MAX_BUILD_SECONDS,
    MAX_REPORT_BYTES,
    ROW_CAP,
    ClaimedReport,
    ReportRefusedError,
)
from argus.reports.store import (
    ReportStore,
    ReportStoreError,
    ReportStoreUnavailableError,
    StoreFor,
    new_key,
)

log = logging.getLogger("argus.reports")
BATCH = 1000


class _TooLongError(Exception):
    pass


class _TooLargeError(Exception):
    pass


@dataclass(frozen=True)
class _Built:
    row_count: int
    truncated: bool
    data_through: dict[int, object]


def _scope(
    conn: Connection, report: ClaimedReport, *, local: bool
) -> tuple[FindingFilters, dict[int, date]]:
    """The report's filters over its scope, re-checked inside the build's transaction, and each
    account's data-through day."""
    scope = queue.resolve_scope(conn, tuple(report.connection_ids))
    queue.check_scope(scope, local=local)
    ids = [cid for cid, _ in scope]
    filters = report_filters.from_json(report.kind, report.filters, connection_ids=ids)
    through = ingest.data_through_by_connection(conn, connection_ids=ids, tools=filters.tools)
    return filters, through


@contextmanager
def _snapshot(engine: Engine) -> Iterator[Connection]:
    """One read-only REPEATABLE READ transaction: every read in it sees one state."""
    with (
        engine.connect().execution_options(
            isolation_level="REPEATABLE READ", postgresql_readonly=True
        ) as conn,
        conn.begin(),
    ):
        yield conn


def _write_csv(
    engine: Engine,
    report: ClaimedReport,
    out_path: Path,
    *,
    local: bool,
    row_cap: int,
    deadline: float,
) -> _Built:
    with _snapshot(engine) as conn:
        filters, through = _scope(conn, report, local=local)
        written = 0
        truncated = False
        with out_path.open("w", encoding="utf-8", newline="") as out:
            csv = CsvReport(out, report.kind)
            for batch in findings.iter_findings(conn, filters, batch=BATCH):
                if time.monotonic() > deadline:
                    raise _TooLongError
                names = inventory.resource_names(
                    conn, [r["resource_id"] for r in batch if r["resource_id"] is not None]
                )
                facts = (
                    findings.vulnerability_facts(conn, [r["id"] for r in batch])
                    if report.kind == "vulnerabilities"
                    else {}
                )
                for row in batch:
                    if written == row_cap:
                        truncated = True
                        break
                    row["resource_name"] = (
                        names.get(row["resource_id"]) or row["reported_resource_name"]
                    )
                    row["vulnerability"] = facts.get(row["id"])
                    csv.write(row)
                    written += 1
                if truncated:
                    break
    return _Built(row_count=written, truncated=truncated, data_through=dict(through))


def _write_pdf(engine: Engine, report: ClaimedReport, out_path: Path, *, local: bool) -> _Built:
    """Reads inside the transaction, then closes it before rendering: a render can outlast the
    worker role's 5-minute limit on an idle transaction."""
    with _snapshot(engine) as conn:
        filters, through = _scope(conn, report, local=local)
        collected = pdf.collect(conn, report.kind, filters)
    context = pdf.build_context(
        collected,
        report_id=report.id,
        kind=report.kind,
        requested_by=report.requested_by,
        generated_at=datetime.now(UTC),
        scope_words=pdf.describe(filters, accounts=len(report.connection_ids)),
        severities_in_scope=list(filters.severities) or list(pdf.SEVERITIES),
        data_through=through,
    )
    out_path.write_bytes(pdf.render(context))
    return _Built(
        row_count=collected.total, truncated=collected.truncated, data_through=dict(through)
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _failure_reason(exc: Exception, report_id: int) -> str:
    """The sentence a failed report shows, logged with the cause where the sentence hides it."""
    if isinstance(exc, ReportRefusedError):
        return str(exc)
    if isinstance(exc, _TooLongError):
        return "The report took longer than an hour to build. Narrow its filters."
    if isinstance(exc, _TooLargeError):
        return "The report's file is too large. Narrow its filters."
    if isinstance(exc, ReportStoreUnavailableError):
        log.warning("report store unavailable", extra={"report_id": report_id, "why": str(exc)})
        return "The report could not be stored. See the report builder's log."
    if isinstance(exc, ReportStoreError):
        log.warning("report store refused", extra={"report_id": report_id, "why": str(exc)})
        return "The report could not be stored. See the report builder's log."
    if isinstance(exc, IsolatedRunError):
        log.warning("report render failed", extra={"report_id": report_id, "why": str(exc)})
        return "The PDF could not be drawn. Try the CSV, or narrow the filters."
    log.exception("report build failed", extra={"report_id": report_id})
    return "The report could not be built. See the report builder's log."


def _one(store: ReportStore) -> StoreFor:
    return lambda _report: store


def build_pending(
    engine: Engine,
    *,
    store: ReportStore | None = None,
    store_for: StoreFor | None = None,
    row_cap: int = ROW_CAP,
    max_seconds: float = MAX_BUILD_SECONDS,
) -> bool:
    """Builds the oldest queued report into `store` (Compose's one store), or the store
    `store_for` gives for it (Kubernetes: the bucket recorded on the report). False when nothing
    was queued."""
    if store_for is None:
        if store is None:
            raise TypeError("build_pending takes store or store_for")
        store_for = _one(store)
    elif store is not None:
        raise TypeError("build_pending takes store or store_for, not both")
    with engine.begin() as conn:
        report = queue.claim_report(conn)
    if report is None:
        return False
    key = new_key(report.id, report.format)
    temp: Path | None = None
    started = time.monotonic()
    try:
        target = store_for(report)
        temp = target.temp_path(key)
        if report.format == "pdf":
            built = _write_pdf(engine, report, temp, local=target.local)
        else:
            built = _write_csv(
                engine,
                report,
                temp,
                local=target.local,
                row_cap=row_cap,
                deadline=started + max_seconds,
            )
        size = temp.stat().st_size
        if size > MAX_REPORT_BYTES:
            raise _TooLargeError
        digest = _sha256(temp)
        target.publish(temp, key, sha256=digest)
    except Exception as exc:
        if temp is not None:
            temp.unlink(missing_ok=True)
        reason = _failure_reason(exc, report.id)
        with engine.begin() as conn:
            queue.fail_report(conn, report.id, reason)
        return True
    try:
        with engine.begin() as conn:
            done = queue.finish_report(
                conn,
                report.id,
                storage_key=key,
                size_bytes=size,
                sha256=digest,
                row_count=built.row_count,
                truncated=built.truncated,
                data_through=built.data_through,
            )
    except Exception:
        # Not recorded, so no row would ever name the file: remove it where Argus may (on S3 the
        # lifecycle rule does), and let fail_abandoned or fail_stale end the row if failing it
        # here fails too.
        target.delete(key)
        log.exception("report not recorded", extra={"report_id": report.id})
        with engine.begin() as conn:
            queue.fail_report(
                conn, report.id, "The report could not be recorded. Request it again."
            )
        return True
    if not done:
        target.delete(key)
    log.info(
        "report built",
        extra={
            "report_id": report.id,
            "kind": report.kind,
            "format": report.format,
            "rows": built.row_count,
            "truncated": built.truncated,
            "bytes": size,
            "seconds": round(time.monotonic() - started, 1),
        },
    )
    return True
