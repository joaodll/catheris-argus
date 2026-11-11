"""Value types more than one router shares, so routers never import each other."""

from datetime import date
from typing import Literal

from pydantic import BaseModel

# The clouds Argus knows. Only AWS is covered yet; GCP and OCI are accepted so a filter reads
# the same once they are (frontend/src/providers.ts).
Provider = Literal["aws", "gcp", "oci"]


class MonthRow(BaseModel):
    """One month of a month-over-month table (metrics.series.month_table): each severity's open
    count at the month's end, the total, and the change from the column before. Null values: no
    data that month, never 0. Null changes: no column before to compare with."""

    month: str  # YYYY-MM
    values: dict[str, float | None]
    total: float | None
    change: dict[str, float | None] | None
    total_change: float | None


class VulnerabilityTypeMonths(BaseModel):
    type: str  # the scanner's own resource type, the list's resource_type filter; "" for none
    months: list[MonthRow]


class VulnerabilityMonths(BaseModel):
    """Open vulnerabilities (not suppressed in the scanner) at each of the last six calendar
    months' ends, oldest first: each account's latest count on or before the month end, however
    old. `data_through`: the newest count shown."""

    data_through: date
    all: list[MonthRow]
    by_type: list[VulnerabilityTypeMonths] | None  # the summary only; the Overview: null
