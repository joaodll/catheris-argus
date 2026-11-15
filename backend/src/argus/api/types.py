"""Value types more than one router shares, so routers never import each other."""

import json
from datetime import date
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field

# The clouds Argus knows. Only AWS is covered yet; GCP and OCI are accepted so a filter reads
# the same once they are (frontend/src/providers.ts).
Provider = Literal["aws", "gcp", "oci"]

# A tag's name and value as AWS bounds them (128 and 256 characters).
TAG_KEY_MAX = 128
TAG_VALUE_MAX = 256


def _tag_pair(raw: str) -> str:
    """A Tag filter value: the JSON array [name, value]. Names and values may hold any
    character (AWS allows "=", ":" and "/" in both), so no separator would do."""
    try:
        pair = json.loads(raw)
    except ValueError:
        raise ValueError('a tag is a JSON array ["name", "value"]') from None
    if not (isinstance(pair, list) and len(pair) == 2 and all(isinstance(p, str) for p in pair)):
        raise ValueError('a tag is a JSON array ["name", "value"]')
    key, value = pair
    if not 1 <= len(key) <= TAG_KEY_MAX or len(value) > TAG_VALUE_MAX:
        raise ValueError(
            f"a tag name has 1 to {TAG_KEY_MAX} characters, a value at most {TAG_VALUE_MAX}"
        )
    return raw


# One tag a list matches: ["Team", "payments"]. Several values of one name match any of them;
# several names must all match.
TagFilter = Annotated[str, Field(min_length=7, max_length=2400), AfterValidator(_tag_pair)]


def tag_pairs(raw: list[str]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Validated TagFilter values -> findings.FindingFilters.tags: each name once, in order, with
    its values."""
    grouped: dict[str, list[str]] = {}
    for item in raw:
        key, value = json.loads(item)
        values = grouped.setdefault(key, [])
        if value not in values:
            values.append(value)
    return tuple((k, tuple(v)) for k, v in grouped.items())


class TagKeyOut(BaseModel):
    key: str
    # Every value is offered (GET .../tag-values); false: too many, the value is typed and
    # matched exactly.
    listed: bool


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
