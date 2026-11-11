"""Builds one queued report (ADR-0047), in three steps that never share a transaction:

1. claim the oldest queued report;
2. read its rows in ONE read-only REPEATABLE READ transaction (findings are the current state,
   not a day's snapshot, so a scan loading meanwhile cannot mix two states into one file),
   re-checking the scope first, and write them to a hidden file beside the final one;
3. record the result. A failure of any kind fails the report with a redacted reason and
   removes what was written."""

import hashlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Connection, Engine

from argus import findings, ingest, inventory
from argus.reports import filters as report_filters
from argus.reports import queue
from argus.reports.csv_report import CsvReport
from argus.reports.model import MAX_BUILD_SECONDS, ROW_CAP, ClaimedReport, ReportRefusedError
from argus.reports.store import LocalReportStore

log = logging.getLogger("argus.reports")
BATCH = 1000


class _TooLongError(Exception):
    pass


@dataclass(frozen=True)
class _Built:
    row_count: int
    truncated: bool
    data_through: dict[int, object]


def _write_rows(
    conn: Connection, report: ClaimedReport, out_path: Path, *, row_cap: int, deadline: float
) -> _Built:
    scope = queue.resolve_scope(conn, tuple(report.connection_ids))
    queue.check_scope(scope)
    ids = [cid for cid, _ in scope]
    filters = report_filters.from_json(report.kind, report.filters, connection_ids=ids)
    through = ingest.data_through_by_connection(conn, connection_ids=ids, tools=filters.tools)
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_pending(
    engine: Engine,
    *,
    store: LocalReportStore,
    row_cap: int = ROW_CAP,
    max_seconds: float = MAX_BUILD_SECONDS,
) -> bool:
    """Builds the oldest queued report. False when nothing was queued."""
    with engine.begin() as conn:
        report = queue.claim_report(conn)
    if report is None:
        return False
    key = store.new_key(report.id)
    temp: Path | None = None
    started = time.monotonic()
    try:
        temp = store.temp_path(key)
        with (
            engine.connect().execution_options(
                isolation_level="REPEATABLE READ", postgresql_readonly=True
            ) as conn,
            conn.begin(),
        ):
            built = _write_rows(conn, report, temp, row_cap=row_cap, deadline=started + max_seconds)
        size = temp.stat().st_size
        digest = _sha256(temp)
        store.publish(temp, key)
    except Exception as exc:
        if temp is not None:
            temp.unlink(missing_ok=True)
        if isinstance(exc, ReportRefusedError):
            reason = str(exc)
        elif isinstance(exc, _TooLongError):
            reason = "The report took longer than an hour to build. Narrow its filters."
        else:
            log.exception("report build failed", extra={"report_id": report.id})
            reason = "The report could not be built. See the worker's log."
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
        # Not recorded, so no row would ever name the file: remove it, and let the next start's
        # sweep (fail_abandoned) end the row if failing it here fails too.
        store.delete(key)
        log.exception("report not recorded", extra={"report_id": report.id})
        with engine.begin() as conn:
            queue.fail_report(
                conn, report.id, "The report could not be recorded. Request it again."
            )
        return True
    if not done:
        store.delete(key)
    log.info(
        "report built",
        extra={
            "report_id": report.id,
            "kind": report.kind,
            "rows": built.row_count,
            "truncated": built.truncated,
            "bytes": size,
            "seconds": round(time.monotonic() - started, 1),
        },
    )
    return True
