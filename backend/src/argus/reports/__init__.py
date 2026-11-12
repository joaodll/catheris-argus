"""Reports: exports of the Misconfigurations and Vulnerabilities lists (ADR-0047).

Owns report_request.
Public interface:
    request_report()     an Operator or Admin asks (the API); the scope is resolved now
    list_reports(), get_report()   the read side (Operate -> Reports)
    build_pending()      a builder builds the oldest queued report into its store
    fail_abandoned()     at the Compose worker's start: reports a stopped worker left building
    fail_stale()         before a Kubernetes report Job claims: reports building far too long
    queued_reports()     the scheduler's count of reports waiting for a report Job
    kept_keys()          the files reports still name (the local store's sweep keeps only these)
    expired_files()      retention: keys of expired files, marked deleted
    LocalReportStore     the Docker Compose store (a local volume)
    S3ReportStore, s3_store_for()   the Kubernetes store (the bucket's reports/ folder)
"""

from argus.reports.build import build_pending
from argus.reports.model import (
    EXPIRY_DAYS,
    MAX_OPEN_PER_USER,
    MAX_REPORT_BYTES,
    ROW_CAP,
    ReportFormat,
    ReportKind,
    ReportRefusedError,
    ReportRow,
    ReportStatus,
)
from argus.reports.queue import (
    expired_files,
    fail_abandoned,
    fail_stale,
    get_report,
    kept_keys,
    list_reports,
    queued_reports,
    request_report,
)
from argus.reports.s3 import renderer_present, s3_store_for
from argus.reports.store import (
    LocalReportStore,
    ReportFileChangedError,
    ReportStore,
    ReportStoreError,
    ReportStoreUnavailableError,
    S3ReportStore,
)

__all__ = [
    "EXPIRY_DAYS",
    "MAX_OPEN_PER_USER",
    "MAX_REPORT_BYTES",
    "ROW_CAP",
    "LocalReportStore",
    "ReportFileChangedError",
    "ReportFormat",
    "ReportKind",
    "ReportRefusedError",
    "ReportRow",
    "ReportStatus",
    "ReportStore",
    "ReportStoreError",
    "ReportStoreUnavailableError",
    "S3ReportStore",
    "build_pending",
    "expired_files",
    "fail_abandoned",
    "fail_stale",
    "get_report",
    "kept_keys",
    "list_reports",
    "queued_reports",
    "renderer_present",
    "request_report",
    "s3_store_for",
]
