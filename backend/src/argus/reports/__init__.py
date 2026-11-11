"""Reports: exports of the Misconfigurations and Vulnerabilities lists (ADR-0047).

Owns report_request.
Public interface:
    request_report()     an Operator or Admin asks (the API); the scope is resolved now
    list_reports(), get_report()   the read side (Operate -> Reports)
    build_pending()      the worker builds the oldest queued report into the store
    fail_abandoned()     at the worker's start: reports a stopped worker left building
    kept_keys()          the files reports still name (the store's sweep keeps only these)
    expired_files()      retention: keys of expired files, marked deleted
    LocalReportStore     the Docker Compose store (a local volume)
"""

from argus.reports.build import build_pending
from argus.reports.model import (
    EXPIRY_DAYS,
    MAX_OPEN_PER_USER,
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
    get_report,
    kept_keys,
    list_reports,
    request_report,
)
from argus.reports.store import LocalReportStore, ReportStoreError

__all__ = [
    "EXPIRY_DAYS",
    "MAX_OPEN_PER_USER",
    "ROW_CAP",
    "LocalReportStore",
    "ReportFormat",
    "ReportKind",
    "ReportRefusedError",
    "ReportRow",
    "ReportStatus",
    "ReportStoreError",
    "build_pending",
    "expired_files",
    "fail_abandoned",
    "get_report",
    "kept_keys",
    "list_reports",
    "request_report",
]
