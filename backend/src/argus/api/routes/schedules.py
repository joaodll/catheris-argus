"""Administration -> Schedules, and Run now."""

from datetime import date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from argus import scheduling
from argus.api.deps import Db, Operator, Viewer, client_ip
from argus.scheduling import check_cron
from argus.settings import read_collection

router = APIRouter(tags=["schedules"])
Tool = Literal["steampipe", "prowler", "cloudfox", "vulnerabilities"]


class ScheduleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    # Each run is still one tool on one account; the schedule queues them in tool order.
    tools: list[Tool] = Field(min_length=1, max_length=4)
    cron: str = Field(min_length=9, max_length=100)
    connection_ids: list[int] | None = None  # None or empty: every connection
    enabled: bool = True


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


@router.post("/schedules/preview")
def preview(body: CronIn, conn: Db, _user: Operator) -> CronOut:
    """Plain-language preview and next runs, before saving."""
    check = check_cron(
        body.cron, min_interval_minutes=read_collection(conn).schedule_min_interval_minutes
    )
    return CronOut(cron=check.expression, explanation=check.explanation, next_runs=check.next_runs)


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
def create(body: ScheduleIn, conn: Db, user: Operator, request: Request) -> ScheduleOut:
    schedule_id = scheduling.create_schedule(
        conn,
        name=body.name,
        tools=body.tools,
        cron=body.cron,
        connection_ids=body.connection_ids,
        enabled=body.enabled,
        actor=user,
        client_ip=client_ip(request),
    )
    conn.commit()
    return _out(conn, schedule_id)


@router.put("/schedules/{schedule_id}")
def update(
    schedule_id: int, body: ScheduleIn, conn: Db, user: Operator, request: Request
) -> ScheduleOut:
    scheduling.update_schedule(
        conn,
        schedule_id=schedule_id,
        name=body.name,
        tools=body.tools,
        cron=body.cron,
        connection_ids=body.connection_ids,
        enabled=body.enabled,
        actor=user,
        client_ip=client_ip(request),
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


@router.post("/run-requests/{request_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
def cancel(request_id: int, conn: Db, user: Operator, request: Request) -> None:
    """Cancels a queued run request (a waiting retry, a staggered scheduled run, a Run now). A
    cancelled request is never retried. 404 when it is not queued: running runs are not
    stopped from here."""
    scheduling.cancel_request(conn, request_id=request_id, actor=user, client_ip=client_ip(request))
    conn.commit()


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
