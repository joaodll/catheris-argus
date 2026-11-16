"""Investigate -> Attack paths (ADR-0052): stored routes, read by index. Nothing is walked here:
the worker or the `paths` Job works routes out after ingests, and this reads what it stored.

A route is one way in and one kind (kind, entry), with its worst targets listed. Every role
reads them (owner, 2026-11-15). A step shows only the attributes ROUTE_STEP_ATTRIBUTES allows for
its edge type (§9 M4); a step the walk made shows its reason and reference only. No route is
exported (§9 L2).
"""

from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from argus import attackpaths, ingest, inventory, relationships
from argus.api.deps import Db, Viewer
from argus.api.routes.resource_map import NodeFacts, resource_facts
from argus.core.config import get_settings

router = APIRouter(tags=["attack-paths"])

# The tools whose scans a route's edges come from: a route is as current as their data.
TOOLS = ("steampipe", "cloudfox")
Severity = Literal["critical", "high", "medium", "low", "informational"]
RouteClass = Literal["confirmed", "conditional", "potential", "unknown", "blocked"]
KindId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]


class NodeRef(BaseModel):
    """A resource on a route, or a pseudo-node (internet, an account's administrator, an
    external host, every store of a service)."""

    uid: str
    kind: Literal["resource", "internet", "admin", "external", "any"]
    resource_id: int | None
    type: str | None
    name: str | None
    connection_id: int | None
    deleted_on: date | None


class StepNode(NodeRef):
    # The Security Map's facts on the resource (open misconfigurations, vulnerabilities, a
    # confirmed reach), as the Security Map shows them; null for a pseudo-node.
    facts: NodeFacts | None


class _Route(BaseModel):
    """What a route's list row and its page share."""

    id: int
    kind: str
    kind_name: str | None  # null when this release has no file for the kind
    entry: NodeRef
    connection_id: int
    # Every connection a target found crosses, the entry's first.
    crossed_connection_ids: list[int]
    severity: Severity
    # The class of its worst listed target.
    worst_class: RouteClass
    target_count: int
    listed_count: int
    worst_target: NodeRef
    first_seen: date
    last_seen: date
    resolved_on: date | None
    state: Literal["open", "reopened", "resolved"]


class RouteOut(_Route):
    # With `through`: the first listed target whose steps touch that resource, and the first
    # such step, where the Map's Attack Path view opens. Null without `through`.
    through_target: int | None = None
    through_step: int | None = None


class EvaluationOut(BaseModel):
    """When routes were last worked out, and whether they are behind the scans (§9 M2)."""

    # The last evaluation that finished, and the newest ingest it covered: null when never.
    evaluated_at: datetime | None
    covered_through: datetime | None
    # The last evaluation failed: when (the routes shown are the previous ones).
    failed_at: datetime | None
    # A scan was ingested after the routes shown were worked out.
    behind: bool


class EvaluationDetail(EvaluationOut):
    # The last evaluation's error when it failed, redacted when it was recorded.
    error: str | None


class RoutePage(BaseModel):
    items: list[RouteOut]
    total: int
    # The scan time the routes reflect (the newest Steampipe or CloudFox day ingested).
    data_through: date | None
    evaluation: EvaluationOut


class StepOut(BaseModel):
    n: int
    # An edge type, or a step the walk made: FOOTHOLD (takes control of a resource) or
    # AUTHENTICATES (logs in to a database).
    type: str
    source: StepNode
    target: StepNode
    edge_id: int | None
    origin: str
    connection_id: int | None
    day: date | None
    level: Literal["blocked", "unknown", "candidate", "supported", "confirmed"]
    reason: str
    # An evidence reference, never a value: a CVE id, or the edges a walk-made step joins.
    ref: str
    # The edge's attributes the step's words read, allow-listed per type (never all of them).
    attributes: dict[str, Any]


class TargetOut(BaseModel):
    seq: int
    target: NodeRef
    severity: Severity
    cls: RouteClass
    likelihood: Literal["higher", "lower", "unknown"]
    steps: int


class RouteDetail(_Route):
    category: str | None
    technique: str | None
    description: str | None
    remediation: str | None
    targets: list[TargetOut]
    target: int  # the target whose steps are listed
    steps: list[StepOut]


class RouteFacets(BaseModel):
    kind: dict[str, int]
    kind_names: dict[str, str]
    severity: dict[str, int]
    cls: dict[str, int]


class RouteFilterQuery(BaseModel):
    state: Literal["open", "resolved"] = "open"
    connection_id: int | None = None
    # With a connection: also the routes that cross it.
    crossing: bool = False
    # A resource on a listed target's steps.
    through: int | None = None


class RouteQuery(RouteFilterQuery):
    severity: list[Severity] = Field(default_factory=list, max_length=5)
    kind: list[KindId] = Field(default_factory=list, max_length=50)
    # Empty: every class but Latent (blocked), shown only when asked for.
    cls: list[RouteClass] = Field(default_factory=list, max_length=5)
    limit: int = Field(50, ge=1, le=200)
    offset: int = Field(0, ge=0)
    order: attackpaths.RouteOrder = "severity"


def _kinds() -> dict[str, attackpaths.RouteKind]:
    """The kind files this release ships (the image's rules folder), read once."""
    return attackpaths.kinds_by_id(get_settings().rules_dir)


def _filters(q: RouteFilterQuery, **extra: Any) -> attackpaths.RouteFilters:
    return attackpaths.RouteFilters(
        state=q.state,
        connection_id=q.connection_id,
        crossing=q.crossing and q.connection_id is not None,
        through=q.through,
        **extra,
    )


def _nodes(conn: Connection, uids: set[str]) -> dict[str, dict[str, Any]]:
    return inventory.resource_nodes(
        conn, sorted(u for u in uids if relationships.kind_of(u) == "resource")
    )


def _ref(uid: str, nodes: dict[str, dict[str, Any]]) -> NodeRef:
    n = nodes.get(uid, {})
    return NodeRef(
        uid=uid,
        kind=relationships.kind_of(uid),
        resource_id=n.get("id"),
        type=n.get("type"),
        name=n.get("name"),
        connection_id=n.get("connection_id"),
        deleted_on=n.get("deleted_on"),
    )


def _route(row: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    kind = _kinds().get(row["kind"])
    return {
        "id": row["id"],
        "kind": row["kind"],
        "kind_name": kind.name if kind else None,
        "entry": _ref(row["entry_uid"], nodes),
        "connection_id": row["connection_id"],
        "crossed_connection_ids": list(row["crossed"]),
        "severity": row["severity"],
        "worst_class": row["worst_class"],
        "target_count": row["target_count"],
        "listed_count": row["listed_count"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "resolved_on": row["resolved_on"],
        "state": row["state"],
        "through_target": row.get("through_target"),
        "through_step": row.get("through_step"),
    }


def evaluation(conn: Connection) -> EvaluationDetail:
    state = attackpaths.evaluation_state(conn)
    last, done = state.get("last"), state.get("complete")
    newest = max((r.ingested_at for r in ingest.newest_runs(conn).values()), default=None)
    covered = done["newest_load_at"] if done else None
    failed = last is not None and last["status"] == "failed"
    return EvaluationDetail(
        evaluated_at=done["finished_at"] if done else None,
        covered_through=covered,
        failed_at=last["finished_at"] if last and failed else None,
        behind=done is not None and newest is not None and (covered is None or newest > covered),
        error=last["error"] if last and failed else None,
    )


def _step_node(ref: NodeRef, facts: dict[int, NodeFacts]) -> StepNode:
    found = facts.get(ref.resource_id) if ref.resource_id is not None else None
    return StepNode(**ref.model_dump(), facts=found)


@router.get("/attack-paths")
def list_attack_paths(conn: Db, _user: Viewer, query: Annotated[RouteQuery, Query()]) -> RoutePage:
    """One page of routes, worst first."""
    items, total = attackpaths.list_routes(
        conn,
        _filters(
            query, severity=tuple(query.severity), kind=tuple(query.kind), cls=tuple(query.cls)
        ),
        order=query.order,
        limit=query.limit,
        offset=query.offset,
    )
    nodes = _nodes(conn, {i["entry_uid"] for i in items} | {i["target_uid"] for i in items})
    return RoutePage(
        items=[
            RouteOut(**_route(i, nodes), worst_target=_ref(i["target_uid"], nodes)) for i in items
        ],
        total=total,
        # Over the chosen connection, so the screen can say it is not covered.
        data_through=ingest.data_through(conn, connection_id=query.connection_id, tools=TOOLS),
        evaluation=EvaluationOut(**evaluation(conn).model_dump(exclude={"error"})),
    )


@router.get("/attack-paths/evaluation")
def attack_path_evaluation(conn: Db, _user: Viewer) -> EvaluationDetail:
    """When routes were last worked out, and the last evaluation's redacted error when it
    failed (the Runs line, §9 M2)."""
    return evaluation(conn)


@router.get("/attack-paths/facets")
def attack_path_facets(
    conn: Db, _user: Viewer, query: Annotated[RouteFilterQuery, Query()]
) -> RouteFacets:
    """How many routes of each kind, severity and class, for the pickers."""
    counts = attackpaths.route_facets(conn, _filters(query))
    kinds = _kinds()
    return RouteFacets(
        kind=counts["kind"],
        kind_names={k: kinds[k].name for k in counts["kind"] if k in kinds},
        severity=counts["severity"],
        cls=counts["cls"],
    )


@router.get("/attack-paths/{route_id}")
def get_attack_path(
    conn: Db,
    _user: Viewer,
    route_id: int,
    target: Annotated[int, Query(ge=1, le=100)] = 1,
) -> RouteDetail:
    """A route, its listed targets, and one target's steps (the worst by default)."""
    found = attackpaths.get_route(conn, route_id, target=target)
    if found is None or target > len(found["targets"]):
        raise LookupError("attack path not found")
    steps = found["steps"]
    uids = {found["entry_uid"]} | {t["target_uid"] for t in found["targets"]}
    uids |= {s["source_uid"] for s in steps} | {s["target_uid"] for s in steps}
    nodes = _nodes(conn, uids)
    on_steps = {s["source_uid"] for s in steps} | {s["target_uid"] for s in steps}
    facts = resource_facts(conn, [nodes[u] for u in sorted(on_steps) if u in nodes])
    kind = _kinds().get(found["kind"])
    worst = found["targets"][0]["target_uid"] if found["targets"] else found["entry_uid"]
    return RouteDetail(
        **_route(found, nodes),
        worst_target=_ref(worst, nodes),
        category=kind.category if kind else None,
        technique=kind.technique if kind else None,
        description=kind.description if kind else None,
        remediation=kind.remediation if kind else None,
        targets=[
            TargetOut(
                seq=t["seq"],
                target=_ref(t["target_uid"], nodes),
                severity=t["severity"],
                cls=t["cls"],
                likelihood=t["likelihood"],
                steps=t["steps"],
            )
            for t in found["targets"]
        ],
        target=found["target"],
        steps=[
            StepOut(
                n=s["n"],
                type=s["type"],
                source=_step_node(_ref(s["source_uid"], nodes), facts),
                target=_step_node(_ref(s["target_uid"], nodes), facts),
                edge_id=s["edge_id"],
                origin=s["origin"],
                connection_id=s["connection_id"],
                day=s["day"],
                level=s["level"],
                reason=s["reason"],
                ref=s["ref"],
                attributes=s["attributes"],
            )
            for s in steps
        ],
    )
