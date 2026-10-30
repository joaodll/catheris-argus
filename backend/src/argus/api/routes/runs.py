"""Administration -> Runs: status, duration, exit code, throttle events, log tail, and what a
run left out: actions the scanning identity was denied, and raw output stored without KMS."""

from datetime import date, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import BaseModel

from argus import ingest, scheduling
from argus.api.deps import Db, Viewer

router = APIRouter(tags=["runs"])
Limit = Annotated[int, Query(ge=1, le=200)]


class RunTrigger(BaseModel):
    """What started the run. `origin` is the first attempt's reason when this is a retry;
    `schedule` the schedule's name while it exists; `requested_by` who asked (the scheduler,
    or the administrator who used Run now)."""

    reason: Literal["schedule", "manual", "retry", "backfill"]
    origin: Literal["schedule", "manual", "retry", "backfill"]
    schedule: str | None
    requested_by: str
    attempt: int


class RunOut(BaseModel):
    id: int
    # The run's folder name in the raw archive: <prefix>/aws/<account>/<YYYY>/<MM>/<DD>/<run_uid>.
    run_uid: UUID
    # Where the raw output was archived (an s3:// location, or a path in the local volume);
    # "" when the run ended before anything was archived.
    raw_path: str
    connection_id: int
    connection: str
    tool: str
    tool_version: str
    source: str
    snapshot_date: date
    status: str
    started_at: datetime
    finished_at: datetime | None
    duration_seconds: int | None
    exit_code: int | None
    throttle_events: int
    api_regions: int | None
    region_scope: list[str]
    ingested_at: datetime | None
    log_tail: str
    denied_actions: list[str]
    # S3's server-side encryption for the raw output (the weakest seen); None on the local
    # volume. Anything but aws:kms / aws:kms:dsse is flagged in the UI (ADR-0031).
    raw_encryption: str | None
    # The tool's command line as the worker ran it; "" for synthetic runs and for runs from
    # before it was recorded.
    command: str
    # Steampipe: the tables this run left out of its scope (failed, denied, throttled, not
    # applicable or refused); their resources were carried forward, every other table is
    # complete.
    incomplete_tables: list[str] = []
    # Refused by the resource's own policy: not fixable in the role (ADR-0012, 2026-10-21).
    refused_actions: list[str] = []
    # Steampipe: of incomplete_tables, those whose service is not used in the account, and
    # those a resource refused. Neither makes the run partial.
    not_applicable_tables: list[str] = []
    refused_tables: list[str] = []
    # None when the request behind the run is gone (runs from before requests were kept).
    trigger: RunTrigger | None = None


class RunPage(BaseModel):
    items: list[RunOut]
    total: int  # runs matching the filters, for the page count


@router.get("/runs")
def list_runs(
    conn: Db,
    _user: Viewer,
    *,
    limit: Limit = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    connection_id: int | None = None,
    tool: Literal["steampipe", "prowler", "cloudfox"] | None = None,
    status: Literal["complete", "partial", "failed", "running"] | None = None,
    missing_permissions: bool = False,
    order: Literal["started_desc", "started_asc"] = "started_desc",
) -> RunPage:
    rows, total = ingest.list_runs(
        conn,
        limit=limit,
        offset=offset,
        connection_id=connection_id,
        tool=tool,
        status=status,
        missing_permissions=missing_permissions,
        order=order,
    )
    triggers = scheduling.run_triggers(conn, [int(r["id"]) for r in rows])
    return RunPage(
        items=[
            RunOut.model_validate(
                {**r, "trigger": vars(t) if (t := triggers.get(int(r["id"]))) else None}
            )
            for r in rows
        ],
        total=total,
    )
