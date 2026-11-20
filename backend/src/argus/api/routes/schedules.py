"""Administration -> Schedules, and Run now."""

from datetime import date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from argus import scheduling
from argus.api.deps import Db, Operator, Viewer, client_ip
from argus.collection import aws_regions as aws_region_names
from argus.scheduling import check_cron
from argus.settings import read_collection

router = APIRouter(tags=["schedules"])
Tool = Literal["steampipe", "prowler", "cloudfox", "vulnerabilities"]
# A region's shape only; scheduling refuses a name the pinned tools don't know (422).
Region = Annotated[str, Field(pattern=r"^[a-z]{2}(-[a-z]+)+-[0-9]$", max_length=30)]
# Regions a run scans: Prowler, Steampipe and the vulnerability scanner read only these;
# CloudFox scans every region whatever is chosen. Empty: every region enabled in the account.
Regions = Annotated[list[Region], Field(max_length=40)]


class ScheduleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    # Each run is still one tool on one account; the schedule queues them in tool order.
    tools: list[Tool] = Field(min_length=1, max_length=4)
    cron: str = Field(min_length=9, max_length=100)
    connection_ids: list[int] | None = None  # None or empty: every connection
    enabled: bool = True
    aws_regions: Regions = Field(default_factory=list)


class ScheduleOut(BaseModel):
    id: int
    name: str
    tools: list[str]
    cron: str
    explanation: str
    next_runs: list[datetime]
    all_connections: bool
    connection_ids: list[int]
    enabled: bool
    updated_at: datetime
    updated_by: str
    aws_regions: list[str]


class CronIn(BaseModel):
    cron: str = Field(min_length=9, max_length=100)


class CronOut(BaseModel):
    cron: str
    explanation: str
    next_runs: list[datetime]


class RunNowIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connection_ids: list[int] = Field(min_length=1, max_length=200)
    tools: list[Tool] | None = None  # None: every tool, in order
    aws_regions: Regions = Field(default_factory=list)


class RunNowItem(BaseModel):
    connection_id: int
    tool: str
    reason: str | None = None


class RunNowOut(BaseModel):
    queued: list[RunNowItem]
    refused: list[RunNowItem]


class PendingRequest(BaseModel):
    id: int
    connection_id: int
    connection: str
    tool: str
    reason: str
    status: str
    attempt: int
    snapshot_date: date | None
    not_before: datetime
    claimed_at: datetime | None
    heartbeat_at: datetime | None
    # A running request that was asked to stop and has not stopped yet.
    cancel_requested: bool = False
    # The regions it scans; empty: every region.
    aws_regions: list[str] = Field(default_factory=list)


class BackfillLeft(BaseModel):
    connection_id: int
    connection: str
    left: int


class Queue(BaseModel):
    # The first page, in claim order. `total` and `backfills` count everything waiting.
    items: list[PendingRequest]
    total: int
    backfills: list[BackfillLeft]


QUEUE_PAGE = 50


def _out(conn: Db, schedule_id: int) -> ScheduleOut:
    view = scheduling.get_schedule(conn, schedule_id)
    if view is None:
        raise LookupError(schedule_id)
    return ScheduleOut.model_validate(view, from_attributes=True)


class SchedulePage(BaseModel):
    items: list[ScheduleOut]
    total: int  # schedules matching the search, for the page count


@router.get("/schedules")
def list_schedules(
    conn: Db,
    _user: Viewer,
    *,
    q: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> SchedulePage:
    """Schedules by name; `q` keeps those whose name contains it, in any case."""
    views, total = scheduling.list_schedules(conn, q=q or None, limit=limit, offset=offset)
    return SchedulePage(
        items=[ScheduleOut.model_validate(v, from_attributes=True) for v in views], total=total
    )


class AwsRegions(BaseModel):
    regions: list[str]


@router.get("/schedules/aws-regions")
def aws_regions(_user: Viewer) -> AwsRegions:
    """The AWS regions a schedule or a Run now may choose: the commercial partition of the
    pinned tools, in name order."""
    return AwsRegions(regions=sorted(aws_region_names()))


@router.post("/schedules/preview")
def preview(body: CronIn, conn: Db, _user: Operator) -> CronOut:
    """Plain-language preview and next runs, before saving."""
    check = check_cron(
        body.cron, min_interval_minutes=read_collection(conn).schedule_min_interval_minutes
    )
    return CronOut(cron=check.expression, explanation=check.explanation, next_runs=check.next_runs)


def _spec(body: ScheduleIn) -> scheduling.ScheduleSpec:
    return scheduling.ScheduleSpec(
        name=body.name,
        tools=list(body.tools),
        cron=body.cron,
        connection_ids=body.connection_ids,
        enabled=body.enabled,
        aws_regions=body.aws_regions,
    )


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
def create(body: ScheduleIn, conn: Db, user: Operator, request: Request) -> ScheduleOut:
    schedule_id = scheduling.create_schedule(
        conn, _spec(body), actor=user, client_ip=client_ip(request)
    )
    conn.commit()
    return _out(conn, schedule_id)


@router.put("/schedules/{schedule_id}")
def update(
    schedule_id: int, body: ScheduleIn, conn: Db, user: Operator, request: Request
) -> ScheduleOut:
    scheduling.update_schedule(
        conn, _spec(body), schedule_id=schedule_id, actor=user, client_ip=client_ip(request)
    )
    conn.commit()
    return _out(conn, schedule_id)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete(schedule_id: int, conn: Db, user: Operator, request: Request) -> None:
    scheduling.delete_schedule(
        conn, schedule_id=schedule_id, actor=user, client_ip=client_ip(request)
    )
    conn.commit()


@router.post("/run-requests", status_code=status.HTTP_202_ACCEPTED)
def run_now(
    body: RunNowIn, conn: Db, user: Operator, request: Request, response: Response
) -> RunNowOut:
    result = scheduling.run_now(
        conn,
        connection_ids=body.connection_ids,
        tools=body.tools,
        actor=user,
        aws_regions=body.aws_regions,
        client_ip=client_ip(request),
    )
    conn.commit()
    if not result.queued and result.refused:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"message": "nothing queued: cooldown", "refused": result.refused},
        )
    response.status_code = status.HTTP_202_ACCEPTED
    return RunNowOut.model_validate(result, from_attributes=True)


class CancelOut(BaseModel):
    # cancelled: it was waiting and is gone. stopping: it was running and was asked to stop.
    state: Literal["cancelled", "stopping"]


@router.post("/run-requests/{request_id}/cancel")
def cancel(request_id: int, conn: Db, user: Operator, request: Request) -> CancelOut:
    """Cancels a run request, never to be retried. A queued one (a waiting retry, a staggered
    scheduled run, a Run now) is cancelled at once. A running one is asked to stop: its tool is
    killed within about half a minute and the run is recorded as cancelled; if its results are
    already loading, it finishes instead. 404 when the request is neither queued nor running, or
    was already asked to stop."""
    state = scheduling.cancel_request(
        conn, request_id=request_id, actor=user, client_ip=client_ip(request)
    )
    conn.commit()
    return CancelOut(state=state)


@router.get("/run-requests")
def pending(conn: Db, _user: Viewer) -> Queue:
    total, backfills = scheduling.pending_counts(conn)
    return Queue(
        items=[
            PendingRequest.model_validate(r)
            for r in scheduling.pending_requests(conn, limit=QUEUE_PAGE)
        ],
        total=total,
        backfills=[BackfillLeft.model_validate(b) for b in backfills],
    )
