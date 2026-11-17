"""Each IAM role's last use, as AWS records it (role_last_used, migration 0053): the read side.

The value is IAM's RoleLastUsed, as Steampipe exports it with aws_iam_role, kept apart from the
configuration so a role used every day does not get a new configuration every day. It is the
latest reading only. A null date is AWS saying no use in its tracking window (the trailing 400
days), never "never". A role with no row has not been read since migration 0053 ("not covered").
load.py writes it, only from a run in which the role table was complete.
"""

from dataclasses import dataclass
from datetime import date, datetime
from typing import Literal

from sqlalchemy import Connection, text

ROLE_TYPE = "aws_iam_role"
# AWS's tracking window for RoleLastUsed (IAM API reference, checked 2026-11-17).
TRACKING_DAYS = 400

# Exported SQL: one connection's roles that are not marked deleted (relationships' workload
# counts, bound to :c).
CURRENT_ROLES_SQL = (
    f"SELECT id FROM resource WHERE connection_id = :c AND type = '{ROLE_TYPE}' "  # noqa: S608
    "AND deleted_on IS NULL"
)

# The URL's values, as text: "90" days and so on.
RoleUnused = Literal["90", "180", "365"]
# Exported SQL for ResourceFilters.within: the roles AWS records no use of in the last N days,
# counted back from the day the value was read (scans run every 15 or 30 days, so counting from
# today would make a role used since the last scan look idle). A null date is included.
UNUSED_ROLES_SQL: dict[str, str] = {
    days: (
        "SELECT rl.resource_id FROM role_last_used rl "  # noqa: S608 - constants only
        f"WHERE rl.last_used_at IS NULL OR rl.last_used_at < rl.observed_on - {days}"
    )
    for days in ("90", "180", "365")
}


@dataclass(frozen=True)
class RoleLastUsed:
    last_used_at: datetime | None  # null: no use in AWS's tracking window
    last_used_region: str | None
    observed_on: date  # the inventory day it was read
    # When the role was created (IAM CreateDate, migration 0055); null: not read yet. With no
    # last use and a creation inside the tracking window, the role was never used.
    created_at: datetime | None = None


def role_last_used(conn: Connection, resource_ids: list[int]) -> dict[int, RoleLastUsed]:
    """The last use of each of these roles; a role never read since migration 0053 is absent.
    For one page of ids."""
    if not resource_ids:
        return {}
    rows = conn.execute(
        text(
            "SELECT resource_id, last_used_at, last_used_region, observed_on, created_at "
            "FROM role_last_used WHERE resource_id = ANY(CAST(:ids AS bigint[]))"
        ),
        {"ids": resource_ids},
    )
    return {
        r.resource_id: RoleLastUsed(r.last_used_at, r.last_used_region, r.observed_on, r.created_at)
        for r in rows
    }
