"""Risk: the resources where facts from different tools add up, worst first (ADR-0049).

Every number here is read from stored rows: the list from resource_risk, the tiles from
metric_daily (risk.resources). Neither counts findings or edges at request time.
"""

from datetime import UTC, date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from argus import inventory, metrics, risk
from argus.api.deps import Db, Viewer
from argus.api.types import Provider

router = APIRouter(tags=["risk"])

Tier = Literal["critical", "high", "medium"]
# The combinations' ids: the contract lists them so the client can name each one.
CombinationId = Literal[
    "reachable-exploitable",
    "admin-user-long-lived-credential",
    "reachable-critical-cve",
    "reachable-misconfigured",
    "reachable-secret",
    "exploitable-fixable",
]
_Facet = Annotated[str, Field(min_length=1, max_length=200)]


def _many(n: int = 50) -> Any:
    return Field(default_factory=list, max_length=n)


class CombinationOut(BaseModel):
    id: CombinationId
    tier: Tier
    title: str
    description: str


class RiskRow(BaseModel):
    """One resource at risk. The facts are what made its combinations, each one a link on the
    screen to the list it comes from."""

    resource_id: int
    name: str | None  # its name, or its native id when it has none
    connection_id: int
    provider: Provider
    resource_type: str
    tier: Tier
    combinations: list[CombinationId]  # in the set's order
    first_seen: date  # when it first became at risk in any combination
    # Set while its internet door turned "unknown" (data the verdict needs is missing): the row
    # is held, not dropped, and the door has not been re-checked since this day.
    door_held_since: date | None
    door: bool  # Argus's rules confirm traffic from the internet can reach it (or held)
    admin: bool  # an administrator, or can make itself one
    env_secret: bool  # CloudFox found a secret in its environment variables
    # The credentials that work from anywhere an IAM user holds: access_key,
    # console_password_no_mfa.
    credential_kinds: list[str]
    exploitable_cves: int  # open CVEs with a public exploit
    high_cves: int  # open critical or high CVEs
    max_epss: float | None  # the highest EPSS among its open CVEs
    # Open critical or high misconfigurations, as the Misconfigurations list filtered to the
    # resource shows them, and the worst open misconfiguration's severity.
    high_misconfigurations: int
    worst_misconfiguration: str | None


class RiskPage(BaseModel):
    items: list[RiskRow]
    total: int
    # False while no enabled connection in scope was ever computed: "not computed yet", which
    # the screen tells apart from "nothing at risk".
    computed: bool
    data_through: date | None  # the newest day a refresh in scope reflects


class RiskQuery(BaseModel):
    """A list parameter repeats and matches any of its values; absent, it does not filter."""

    limit: int = Field(20, ge=1, le=200)
    offset: int = Field(0, ge=0)
    connection_id: list[int] = _many()
    provider: list[Provider] = _many(3)
    tier: list[Tier] = _many(3)
    combination: list[CombinationId] = _many(10)
    type: list[_Facet] = _many(200)


@router.get("/risk/combinations")
def list_combinations(_user: Viewer) -> list[CombinationOut]:
    return [
        CombinationOut.model_validate(
            {"id": c.id, "tier": c.tier, "title": c.title, "description": c.description}
        )
        for c in risk.COMBINATIONS
    ]


@router.get("/risk")
def list_risk(conn: Db, _user: Viewer, query: Annotated[RiskQuery, Query()]) -> RiskPage:
    rows, total = risk.list_risk(
        conn,
        filters=risk.RiskFilters(
            connection_ids=tuple(query.connection_id),
            providers=tuple(query.provider),
            tiers=tuple(query.tier),
            combinations=tuple(query.combination),
            resource_types=tuple(query.type),
        ),
        limit=query.limit,
        offset=query.offset,
    )
    names = inventory.resource_names(conn, [r["resource_id"] for r in rows])
    scope = risk.risk_scope(conn, connection_ids=tuple(query.connection_id))
    return RiskPage(
        items=[RiskRow.model_validate({**r, "name": names.get(r["resource_id"])}) for r in rows],
        total=total,
        computed=scope.computed,
        data_through=scope.data_through,
    )


class RiskFacets(BaseModel):
    types: list[str]  # the resource types at risk in scope, for the Type filter


@router.get("/risk/facets")
def risk_facets(
    conn: Db,
    _user: Viewer,
    connection_id: Annotated[list[int], Query(max_length=50)] = [],  # noqa: B006 - FastAPI copies
) -> RiskFacets:
    return RiskFacets(types=risk.risk_types(conn, connection_ids=tuple(connection_id)))


class RiskSummary(BaseModel):
    """The tiles: resources at risk on the scope's latest count, by tier and by combination.
    `computed` false (and every count null): Risk was never computed for the scope."""

    computed: bool
    as_of: date | None  # the day the counts were written
    data_through: date | None
    total: int | None
    tiers: dict[Tier, int] | None
    combinations: dict[CombinationId, int] | None


@router.get("/risk/summary")
def risk_summary(
    conn: Db,
    _user: Viewer,
    connection_id: Annotated[int, Query(ge=0)] = metrics.ALL_CONNECTIONS,
) -> RiskSummary:
    today = datetime.now(UTC).date()
    scope = risk.risk_scope(conn, connection_ids=(connection_id,) if connection_id else ())
    counted = metrics.risk_counts(conn, connection_id=connection_id, today=today)
    if counted is None or not scope.computed:
        return RiskSummary(
            computed=False,
            as_of=None,
            data_through=scope.data_through,
            total=None,
            tiers=None,
            combinations=None,
        )
    day, dims = counted
    return RiskSummary.model_validate(
        {
            "computed": True,
            "as_of": day,
            "data_through": scope.data_through,
            "total": dims.get("total", 0),
            "tiers": {t: dims.get(f"tier:{t}", 0) for t in risk.TIERS},
            "combinations": {c.id: dims.get(f"combination:{c.id}", 0) for c in risk.COMBINATIONS},
        }
    )
