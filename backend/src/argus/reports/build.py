"""Builds one queued report (ADR-0047), in three steps that never share a transaction:

1. claim the oldest queued report;
2. read its rows in ONE read-only REPEATABLE READ transaction (findings are the current state,
   not a day's snapshot, so a scan loading meanwhile cannot mix two states into one file),
   re-checking the scope first, and write them to a hidden file beside the final one. A CSV is
   written while reading; a PDF is read first, and drawn by the renderer after the transaction
   closes (pdf.py);
3. record the result. A failure of any kind fails the report with a redacted reason and
   removes what was written.

A Resources report's JSON Lines file (ADR-0047 3c) is written while reading, as a CSV is: each
batch of the list with its configurations and links, then the linked resources the filters left
out, in the report's accounts, each once."""

import hashlib
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, Engine

from argus import findings, ingest, inventory, relationships
from argus.core.process import IsolatedRunError
from argus.findings import FindingFilters, ResourceListFilters
from argus.reports import filters as report_filters
from argus.reports import pdf, problems, queue
from argus.reports.csv_report import CsvReport
from argus.reports.jsonl_report import JsonlReport, link
from argus.reports.model import (
    KIND_FORMATS,
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
) -> tuple[report_filters.ReportFilters, dict[int, date]]:
    """The report's filters over its scope, re-checked inside the build's transaction, and each
    account's data-through day."""
    scope = queue.resolve_scope(conn, tuple(report.connection_ids))
    queue.check_scope(scope, local=local)
    ids = [cid for cid, _ in scope]
    filters = report_filters.from_json(report.kind, report.filters, connection_ids=ids)
    tools = (
        filters.tools
        if isinstance(filters, FindingFilters)
        else report_filters.KIND_TOOLS[report.kind]
    )
    through = ingest.data_through_by_connection(conn, connection_ids=ids, tools=tools)
    return filters, through


def _finding_rows(
    conn: Connection, report: ClaimedReport, filters: FindingFilters
) -> Iterator[list[dict[str, Any]]]:
    """A Misconfigurations or Vulnerabilities report's rows, batch by batch."""
    for batch in findings.iter_findings(conn, filters, batch=BATCH):
        names = inventory.resource_names(
            conn, [r["resource_id"] for r in batch if r["resource_id"] is not None]
        )
        facts = (
            findings.vulnerability_facts(conn, [r["id"] for r in batch])
            if report.kind == "vulnerabilities"
            else {}
        )
        for row in batch:
            row["resource_name"] = names.get(row["resource_id"]) or row["reported_resource_name"]
            row["vulnerability"] = facts.get(row["id"])
        yield batch


@dataclass
class _ResourceScope:
    """What every batch of a Resources report reads against: its accounts, the accounts the
    CVE scanner covers, and the other accounts' names met on links."""

    accounts: dict[int, tuple[str, str]]
    collected: set[int]

    @classmethod
    def of(cls, conn: Connection, filters: ResourceListFilters) -> "_ResourceScope":
        ids = list(filters.connection_ids)
        collected = ingest.data_through_by_connection(
            conn, connection_ids=ids, tools=[findings.VULNERABILITY_TOOL]
        )
        return cls(queue.scope_accounts(conn, ids), set(collected))

    def account_ids(self, conn: Connection, connection_ids: set[int]) -> dict[int, str]:
        missing = [c for c in connection_ids if c not in self.accounts]
        if missing:
            self.accounts.update(queue.scope_accounts(conn, missing))
        return {c: self.accounts[c][1] for c in connection_ids if c in self.accounts}


def _columns(conn: Connection, batch: list[dict[str, Any]], scope: _ResourceScope) -> None:
    """A batch's list columns, each read from its owning module for the batch (the list reads
    them per page): one definition for the CSV and the JSON Lines file."""
    resource_ids = [r["id"] for r in batch]
    counts = findings.open_finding_counts(conn, resource_ids)
    cells = findings.vulnerability_summaries(conn, batch, collected=scope.collected)
    roles = [r["id"] for r in batch if r["type"] == inventory.ROLE_TYPE]
    used = inventory.role_last_used(conn, roles)
    workloads = relationships.role_workloads(conn, roles)
    for row in batch:
        rid = row["id"]
        row["connection"], row["account_id"] = scope.accounts.get(row["connection_id"], ("", ""))
        row["open_misconfigurations"], row["worst_severity"] = counts.get(rid, (0, None))
        row["vulnerabilities"] = cells.get(rid)
        row["role_last_used"] = used.get(rid)
        row["workloads"] = workloads.get(rid)


def _resource_rows(
    conn: Connection, filters: ResourceListFilters
) -> Iterator[list[dict[str, Any]]]:
    """A Resources report's rows, batch by batch: the list's rows with the columns it shows."""
    scope = _ResourceScope.of(conn, filters)
    for batch in inventory.iter_resources(conn, filters.inventory_filters(), batch=BATCH):
        _columns(conn, batch, scope)
        yield batch


def _links(
    conn: Connection, batch: list[dict[str, Any]], scope: _ResourceScope, day: date
) -> tuple[dict[int, list[dict[str, Any]]], dict[int, int]]:
    """A batch's links as its panels list them, and each other end in the inventory with its
    connection (the linked resources to export are among them)."""
    by_connection: dict[int, list[int]] = {}
    for row in batch:
        by_connection.setdefault(row["connection_id"], []).append(row["id"])
    edges: dict[int, list[dict[str, Any]]] = {}
    for connection_id, ids in by_connection.items():
        edges.update(
            relationships.edges_of_resources(conn, ids, connection_id=connection_id, day=day)
        )
    others = {
        end
        for rid, found in edges.items()
        for e in found
        for end in (e["source_resource_id"], e["target_resource_id"])
        if end is not None and end != rid
    }
    heads = inventory.resource_heads(conn, sorted(others))
    accounts = scope.account_ids(conn, {h["connection_id"] for h in heads.values()})
    ends = {
        rid: {**head, "account_id": accounts.get(head["connection_id"])}
        for rid, head in heads.items()
    }
    links = {rid: [link(e, rid, ends) for e in found] for rid, found in edges.items()}
    return links, {rid: head["connection_id"] for rid, head in heads.items()}


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
        batches = (
            _finding_rows(conn, report, filters)
            if isinstance(filters, FindingFilters)
            else problems.iter_rows(conn, filters)
            if isinstance(filters, report_filters.ResourceProblemFilters)
            else _resource_rows(conn, filters)
        )
        with out_path.open("w", encoding="utf-8", newline="") as out:
            csv = CsvReport(out, report.kind)
            for batch in batches:
                if time.monotonic() > deadline:
                    raise _TooLongError
                for row in batch:
                    if written == row_cap:
                        truncated = True
                        break
                    csv.write(row)
                    written += 1
                if truncated:
                    break
    return _Built(row_count=written, truncated=truncated, data_through=dict(through))


class _Lines:
    """A JSON Lines file being written: its count against the cap, and the resources in it."""

    def __init__(self, out: JsonlReport, cap: int, deadline: float) -> None:
        self.out, self.cap, self.deadline = out, cap, deadline
        self.written = 0
        self.truncated = False
        self.exported: set[int] = set()

    def write_batch(
        self,
        conn: Connection,
        batch: list[dict[str, Any]],
        scope: _ResourceScope,
        *,
        included: str,
        day: date,
    ) -> dict[int, int]:
        """Writes a batch, up to the cap (then `truncated`); returns its links' other ends in
        the inventory, each with its connection."""
        if time.monotonic() > self.deadline:
            raise _TooLongError
        _columns(conn, batch, scope)
        configs = inventory.configs_at(conn, batch, day=day)
        links, ends = _links(conn, batch, scope, day)
        for row in batch:
            if self.written == self.cap:
                self.truncated = True
                break
            self.out.write(
                row,
                included=included,
                links=links.get(row["id"], []),
                config=configs.get(row["id"]),
            )
            self.exported.add(row["id"])
            self.written += 1
        return ends


def _write_jsonl(
    engine: Engine,
    report: ClaimedReport,
    out_path: Path,
    *,
    local: bool,
    row_cap: int,
    deadline: float,
) -> _Built:
    """A Resources report with each resource's links and configuration (ADR-0047 3c): the
    matched resources, then each resource one link away that the filters left out, in the
    report's accounts only (another account's resource is named in the link, never exported)."""
    day = datetime.now(UTC).date()
    with _snapshot(engine) as conn:
        filters, through = _scope(conn, report, local=local)
        if not isinstance(filters, ResourceListFilters):
            raise ReportRefusedError(queue.FORMAT_REFUSED[report.kind])
        scope = _ResourceScope.of(conn, filters)
        in_scope = set(filters.connection_ids)
        candidates: set[int] = set()
        with out_path.open("wb") as raw:
            out = JsonlReport(raw)
            try:
                lines = _Lines(out, row_cap, deadline)
                for batch in inventory.iter_resources(
                    conn, filters.inventory_filters(), batch=BATCH
                ):
                    ends = lines.write_batch(conn, batch, scope, included="matched", day=day)
                    candidates.update(r for r, c in ends.items() if c in in_scope)
                    if lines.truncated:
                        break
                pending = sorted(candidates - lines.exported)
                for start in range(0, len(pending), BATCH):
                    if lines.truncated:
                        break
                    batch = inventory.resources_by_ids(conn, pending[start : start + BATCH])
                    lines.write_batch(conn, batch, scope, included="linked", day=day)
            finally:
                out.close()
    return _Built(row_count=lines.written, truncated=lines.truncated, data_through=dict(through))


def _write_pdf(engine: Engine, report: ClaimedReport, out_path: Path, *, local: bool) -> _Built:
    """Reads inside the transaction, then closes it before rendering: a render can outlast the
    worker role's 5-minute limit on an idle transaction."""
    if "pdf" not in KIND_FORMATS[report.kind]:
        raise ReportRefusedError(queue.FORMAT_REFUSED[report.kind])
    with _snapshot(engine) as conn:
        filters, through = _scope(conn, report, local=local)
        if isinstance(filters, report_filters.ResourceProblemFilters):
            by_resource = problems.collect(conn, filters)
        elif not isinstance(filters, FindingFilters):
            raise ReportRefusedError(queue.FORMAT_REFUSED[report.kind])
        else:
            collected = pdf.collect(conn, report.kind, filters)
    if isinstance(filters, report_filters.ResourceProblemFilters):
        context = problems.build_context(
            by_resource,
            report_id=report.id,
            requested_by=report.requested_by,
            generated_at=datetime.now(UTC),
            scope_words=problems.describe(filters, accounts=len(report.connection_ids)),
            severities_in_scope=list(filters.severities) or list(pdf.SEVERITIES),
            data_through=through,
        )
        out_path.write_bytes(pdf.render(context))
        return _Built(
            row_count=by_resource.total,
            truncated=by_resource.truncated,
            data_through=dict(through),
        )
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
        elif report.format == "jsonl":
            built = _write_jsonl(
                engine,
                report,
                temp,
                local=target.local,
                row_cap=row_cap,
                deadline=started + max_seconds,
            )
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
