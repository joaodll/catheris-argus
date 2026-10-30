"""Posture -> Compliance: every Prowler framework's score and history, one framework's accounts
month by month, and its requirements (docs/ui/screens.md E9, E10). Read-only. Scores come from
metric_daily; requirements from one day of compliance_snapshot (one connection) or
compliance_rollup (all connections). A value that does not exist is null, never 0."""

from datetime import UTC, date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

from argus import connections, findings, metrics
from argus.api.deps import Db, Viewer
from argus.api.types import Provider

router = APIRouter(tags=["compliance"])

# Prowler's framework keys: cis_6.0_aws, nist_800_53_revision_5_aws, ...
FrameworkKey = Annotated[str, Path(pattern=r"^[A-Za-z0-9_.-]{1,200}$")]
ComplianceOrder = Literal["score_asc", "score_desc", "name_asc", "name_desc"]


class ScorePoint(BaseModel):
    date: date
    score: float


class RequirementCounts(BaseModel):
    pass_: int = Field(alias="pass")
    fail: int
    manual: int


class MonthScore(BaseModel):
    month: str  # YYYY-MM; the current month is to date
    score: float | None  # month-end score; null when the month had no scan
    change: float | None  # from the month before; null when either has no score


class FrameworkSummary(BaseModel):
    framework: str  # the key: cis_6.0_aws
    name: str | None  # as Prowler names it; null until a Prowler run since migration 0013
    family: str | None
    version: str
    provider: str
    score: float | None  # requirements passed / assessed x 100, manual excluded
    change: float | None  # points since the first month-end of the last six months
    change_since: str | None  # that month, YYYY-MM
    requirements: RequirementCounts | None  # on the latest day; null with no results
    latest_day: date | None


class FrameworkListItem(FrameworkSummary):
    trend: list[ScorePoint]  # weekly, up to 26 points


class ComplianceList(BaseModel):
    data_through: date | None  # the latest day any framework has results
    items: list[FrameworkListItem]
    total: int


class FrameworkDetail(FrameworkSummary):
    data_through: date | None  # = latest_day: the day the KPIs and requirements show
    range: Literal["6M", "3M", "1M"]
    series: list[ScorePoint]  # 6M month-ends, 3M weekly, 1M daily
    month_table: list[MonthScore]  # six calendar months, oldest first


class AccountMonths(BaseModel):
    connection_id: int
    connection: str
    account_id: str
    score: float | None
    latest_day: date | None
    months: list[MonthScore]


class AccountList(BaseModel):
    data_through: date | None
    items: list[AccountMonths]
    total: int


class RequirementOut(BaseModel):
    section: str | None
    requirement_id: str
    title: str | None
    description: str
    status: Literal["FAIL", "MANUAL", "PASS"]
    passed_checks: int
    failed_checks: int
    # All connections only: how many fail it, of the connections that assessed it.
    fail_connections: int | None
    assessed_connections: int | None


class RequirementList(BaseModel):
    data_through: date | None  # the day listed: the framework's latest day
    items: list[RequirementOut]
    total: int


def _framework(conn: Db, key: str) -> findings.Framework:
    framework = findings.framework_catalog(conn).get(key)
    if framework is None:
        raise HTTPException(404, "No results for this framework.")
    return framework


def _catalog_fields(framework: findings.Framework) -> dict[str, object]:
    return {
        "framework": framework.framework,
        "name": framework.name,
        "family": framework.family,
        "version": framework.version,
        "provider": framework.provider,
    }


def _today() -> date:
    return datetime.now(UTC).date()


def _sort(items: list[FrameworkListItem], order: ComplianceOrder) -> None:
    """By name, or by score with the frameworks that have none last either way."""

    def name(i: FrameworkListItem) -> str:
        return (i.name or i.framework).casefold()

    if order in ("name_asc", "name_desc"):
        items.sort(key=name, reverse=order == "name_desc")
    else:
        sign = 1 if order == "score_asc" else -1
        items.sort(key=lambda i: (i.score is None, sign * (i.score or 0.0), name(i)))


@router.get("/compliance")
def compliance(
    *,
    conn: Db,
    _user: Viewer,
    connection_id: Annotated[int, Query(ge=0)] = 0,
    q: Annotated[str | None, Query(max_length=200)] = None,
    provider: Annotated[list[Provider] | None, Query(max_length=3)] = None,
    order: ComplianceOrder = "score_asc",
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ComplianceList:
    """Every framework with results in the last six months: score, change, requirement counts
    and a weekly trend, for one connection or all (0). `provider` repeats and matches the
    framework's own provider."""
    catalog = findings.framework_catalog(conn)
    items = []
    for row in metrics.compliance_scores(conn, connection_id=connection_id, as_of=_today()):
        framework = catalog.get(row["framework"])
        if framework is None:  # results whose catalog row is gone: nothing to name them by
            continue
        items.append(FrameworkListItem.model_validate({**row, **_catalog_fields(framework)}))
    days = [i.latest_day for i in items if i.latest_day]
    if q:
        needle = q.casefold()
        items = [i for i in items if needle in f"{i.name or ''}\n{i.framework}".casefold()]
    if provider:
        items = [i for i in items if i.provider in provider]
    _sort(items, order)
    return ComplianceList(
        data_through=max(days) if days else None,
        items=items[offset : offset + limit],
        total=len(items),
    )


@router.get("/compliance/{framework}")
def framework_detail(
    conn: Db,
    _user: Viewer,
    framework: FrameworkKey,
    connection_id: Annotated[int, Query(ge=0)] = 0,
    score_range: Annotated[Literal["6M", "3M", "1M"], Query(alias="range")] = "6M",
) -> FrameworkDetail:
    """One framework for one connection or all (0): its score, the history for the range, and
    the six month-ends."""
    found = _framework(conn, framework)
    history = metrics.compliance_history(
        conn, framework=framework, connection_id=connection_id, as_of=_today(), rng=score_range
    )
    return FrameworkDetail.model_validate(
        {**history, **_catalog_fields(found), "data_through": history["latest_day"]}
    )


@router.get("/compliance/{framework}/accounts")
def framework_accounts(
    conn: Db,
    _user: Viewer,
    framework: FrameworkKey,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AccountList:
    """Each connection's month-end score for the framework, lowest latest score first. No
    average row: the overall average across accounts was set aside (2026-10-07)."""
    _framework(conn, framework)
    by_account = metrics.compliance_by_account(conn, framework=framework, as_of=_today())
    names = {c.id: c for c in connections.list_views(conn)}
    items = [
        AccountMonths(
            connection_id=cid,
            connection=names[cid].name,
            account_id=names[cid].account_id,
            score=row["score"],
            latest_day=row["latest_day"],
            months=[MonthScore.model_validate(m) for m in row["months"]],
        )
        for cid, row in by_account.items()
        if cid in names
    ]
    items.sort(key=lambda a: (a.score is None, a.score or 0.0, a.connection.casefold()))
    days = [a.latest_day for a in items if a.latest_day]
    return AccountList(
        data_through=max(days) if days else None,
        items=items[offset : offset + limit],
        total=len(items),
    )


@router.get("/compliance/{framework}/requirements")
def framework_requirements(
    *,
    conn: Db,
    _user: Viewer,
    framework: FrameworkKey,
    connection_id: Annotated[int, Query(ge=0)] = 0,
    status: Literal["FAIL", "MANUAL", "PASS"] | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> RequirementList:
    """The framework's requirements on its latest day for the connection (or all, 0), by
    section and requirement id."""
    _framework(conn, framework)
    day = metrics.compliance_history(
        conn, framework=framework, connection_id=connection_id, as_of=_today()
    )["latest_day"]
    if day is None:
        return RequirementList(data_through=None, items=[], total=0)
    page = findings.list_requirements(
        conn,
        framework=framework,
        connection_id=connection_id,
        day=day,
        status=status,
        q=q,
        limit=limit,
        offset=offset,
    )
    return RequirementList(
        data_through=day,
        items=[RequirementOut.model_validate(r) for r in page.items],
        total=page.total,
    )
