"""What a report is (ADR-0047): its kinds, formats, limits and the row the queue holds."""

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Literal

ReportKind = Literal["misconfigurations", "vulnerabilities"]
ReportFormat = Literal["csv", "pdf"]
ReportStatus = Literal["queued", "building", "ready", "failed"]

# A file is kept this long after it is ready; the API refuses it afterwards, whatever storage
# still holds (ADR-0047). Fixed, not a setting.
EXPIRY_DAYS = 7
# Open reports (queued or building) one user may have at once.
MAX_OPEN_PER_USER = 3
# Rows in one CSV. Past it the file is cut and the report says so.
ROW_CAP = 500_000
# A PDF is a hand-off to read, not the whole list (the CSV is): at most this many resources per
# check or CVE, this many in all, and this many checks or CVEs in full; the rest of them are named
# in one table, up to PDF_NAMED_CAP, and the rest are counted.
PDF_RESOURCES_PER_BLOCK = 25
PDF_RESOURCE_CAP = 5_000
PDF_DETAILED_BLOCKS = 300
# Past the detailed blocks, at most this many more are named in one table; the CSV has the rest.
# 10,000 names took the renderer past its 2 GiB limit (2026-11-11).
PDF_NAMED_CAP = 1_000
# A build that runs longer gives up and fails: the worker's one report thread is then free.
MAX_BUILD_SECONDS = 3600
# On this install's store (a local volume, Docker Compose), only Demo connections: real tool
# output never stays on a local disk (ADR-0032).
LOCAL_STORE_KINDS = frozenset({"demo"})


class ReportRefusedError(ValueError):
    """A request the rules refuse; the message is a sentence for the person who asked (422)."""


@dataclass(frozen=True)
class ReportRow:
    id: int
    kind: ReportKind
    format: ReportFormat
    filters: dict[str, Any]
    connection_ids: list[int]
    requested_by_id: int | None
    requested_by: str
    status: ReportStatus
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    expires_at: datetime | None
    expired: bool
    file_deleted_at: datetime | None
    storage_key: str | None
    size_bytes: int | None
    row_count: int | None
    truncated: bool
    data_through: dict[int, date] | None
    error: str | None


@dataclass(frozen=True)
class ClaimedReport:
    id: int
    kind: ReportKind
    format: ReportFormat
    filters: dict[str, Any]
    connection_ids: list[int]
    requested_by: str
