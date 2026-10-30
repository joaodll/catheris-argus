"""Which days a chart shows: month-ends and the 6M / 3M / 1M samples, from the days that have
data. One definition for every history read (the Overview, Compliance)."""

from collections.abc import Collection
from datetime import date, timedelta
from typing import Literal

Range = Literal["6M", "3M", "1M"]
MONTHS = 6
# Six months of month-ends plus the current month: what every history read loads.
HISTORY_DAYS = 183
_STEPS: dict[str, tuple[int, int]] = {"3M": (7, 13), "1M": (1, 30)}  # (days apart, how many)


def latest_on_or_before(days: Collection[date], day: date) -> date | None:
    found = [d for d in days if d <= day]
    return max(found) if found else None


def calendar_month_ends(
    days: Collection[date], ref: date, months: int = MONTHS
) -> list[tuple[str, date | None]]:
    """(YYYY-MM, last day with data in that month or None), for the `months` calendar months
    ending with ref's, oldest first; the current month is to date."""
    out: list[tuple[str, date | None]] = []
    year, month = ref.year, ref.month
    for _ in range(months):
        last = date(year, month, 1) + timedelta(days=32)
        last = date(last.year, last.month, 1) - timedelta(days=1)
        day = latest_on_or_before(days, min(last, ref))
        in_month = day is not None and (day.year, day.month) == (year, month)
        out.append((f"{year:04d}-{month:02d}", day if in_month else None))
        year, month = (year, month - 1) if month > 1 else (year - 1, 12)
    return list(reversed(out))


def month_ends(days: Collection[date], ref: date, months: int = MONTHS) -> list[tuple[str, date]]:
    """The months of calendar_month_ends that have data."""
    return [(m, d) for m, d in calendar_month_ends(days, ref, months) if d is not None]


def sample(days: Collection[date], ref: date, step: int, count: int) -> list[date]:
    """The latest day with data on or before each of `count` days `step` apart, ending at ref;
    each day once, oldest first, and none before the window: a 1M chart never shows a scan
    from two months ago."""
    start = ref - timedelta(days=step * (count - 1))
    return sorted(
        {
            d
            for back in range(0, step * count, step)
            if (d := latest_on_or_before(days, ref - timedelta(days=back))) and d >= start
        }
    )


def range_days(days: Collection[date], ref: date, rng: Range) -> list[date]:
    """6M: month-ends; 3M: weekly; 1M: daily."""
    if rng == "6M":
        return [d for _, d in month_ends(days, ref)]
    step, count = _STEPS[rng]
    return sample(days, ref, step, count)
