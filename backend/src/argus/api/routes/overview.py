"""The Overview: every block from metric_daily, for one connection or all (0), as of the latest
scan (or the latest on or before `as_of`). Values that do not exist are null, so the UI says
"no data" instead of drawing 0."""

from datetime import UTC, date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel

from argus import connections, ingest, metrics
from argus.api.deps import Db, Viewer

router = APIRouter(tags=["overview"])


class Kpi(BaseModel):
    value: float | None


class ThreatScoreKpi(Kpi):
    target: float


class Kpis(BaseModel):
    assets: Kpi
    threatscore: ThreatScoreKpi
    open_critical: Kpi
    exploitable_paths: Kpi


class StripPoint(BaseModel):
    month: str
    score: float | None
    change: float | None


class Pillar(BaseModel):
    pillar: str
    score: float | None


class ThreatScore(BaseModel):
    strip: list[StripPoint]
    change_since_first: float | None
    pillars: list[Pillar]


class MonthlyPassRate(BaseModel):
    month: str
    pass_rate: float | None


class CheckResults(BaseModel):
    passed: float | None
    failed: float | None
    muted: float | None
    manual: float | None
    pass_rate: float | None
    monthly_pass_rate: list[MonthlyPassRate]


class SeverityCount(BaseModel):
    severity: str
    value: float | None


class SeverityPoint(BaseModel):
    date: date
    critical: float | None
    high: float | None
    medium: float | None
    low: float | None
    informational: float | None


class MonthRow(BaseModel):
    month: str
    values: dict[str, float | None]
    total: float
    change: dict[str, float | None] | None


class SeverityOverTime(BaseModel):
    range: str
    points: list[SeverityPoint]
    month_table: list[MonthRow]


class CategoryCount(BaseModel):
    category: str
    count: float


class TypeCount(BaseModel):
    type: str
    count: float


class Inventory(BaseModel):
    by_type: list[TypeCount]


class Overview(BaseModel):
    as_of: date
    data_through: date | None
    kpis: Kpis
    threatscore: ThreatScore
    check_results: CheckResults
    failed_by_severity: list[SeverityCount]
    severity_over_time: SeverityOverTime
    attack_paths_by_category: list[CategoryCount]
    inventory: Inventory
    coverage: dict[str, str]


class ConnectionOption(BaseModel):
    id: int
    name: str
    kind: str
    account_id: str
    enabled: bool


class LastRun(BaseModel):
    connection_id: int
    connection: str
    tool: str
    status: str
    snapshot_date: date
    finished_at: datetime | None


class Context(BaseModel):
    connections: list[ConnectionOption]
    last_runs: list[LastRun]
    providers: dict[str, str]


@router.get("/overview")
def overview(
    conn: Db,
    _user: Viewer,
    connection_id: Annotated[int, Query(ge=0)] = 0,
    as_of: date | None = None,
    severity_range: Annotated[Literal["6M", "3M", "1M"], Query(alias="range")] = "6M",
) -> Overview:
    data = metrics.build_overview(
        conn,
        connection_id=connection_id,
        as_of=as_of or datetime.now(UTC).date(),
        severity_range=severity_range,
    )
    return Overview.model_validate(data)


@router.get("/context")
def context(conn: Db, _user: Viewer, connection_id: Annotated[int, Query(ge=0)] = 0) -> Context:
    """The context bar: which accounts exist, and each tool's last run."""
    return Context(
        connections=[
            ConnectionOption(
                id=c.id, name=c.name, kind=c.kind, account_id=c.account_id, enabled=c.enabled
            )
            for c in connections.list_views(conn)
        ],
        last_runs=[
            LastRun.model_validate(r) for r in ingest.last_runs(conn, connection_id=connection_id)
        ],
        providers={"aws": "covered", "gcp": "not covered", "oci": "not covered"},
    )
