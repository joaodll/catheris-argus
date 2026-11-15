"""Attack paths: stored (kind, entry) routes and how they are worked out (ADR-0052).

Owns route, route_target, route_node and route_evaluation. Public interface:
    evaluate()          one evaluation in the caller's REPEATABLE READ transaction: every
                        enabled connection's standing edges, the kinds' targets and the findings
                        the steps read -> the walk -> the routes written (only what changed)
    loads_digest(), last_evaluation(), due()   whether an evaluation should start
    start(), finish(), fail()   the evaluation's own record (route_evaluation)
    purge_resolved(), purge_evaluations()   retention (ADR-0052 §9 L1)
    load_kinds(), kinds_by_id(), RouteKind   the kind files, <rules dir>/attack_paths/*.toml
    list_routes(), route_facets(), get_route(), evaluation_state()   the read side (API)
    ROUTE_STEP_ATTRIBUTES   the only edge attributes a route's step shows (§9 M4)

The walk runs in the worker (Docker Compose) or the `paths` Job (Kubernetes), never in the API.
"""

from argus.attackpaths.evaluate import (
    LastEvaluation,
    due,
    evaluate,
    fail,
    finish,
    last_evaluation,
    loads_digest,
    purge_evaluations,
    start,
)
from argus.attackpaths.kinds import RouteKind, kinds_by_id, load_kinds
from argus.attackpaths.queries import (
    ROUTE_STEP_ATTRIBUTES,
    RouteFilters,
    RouteOrder,
    RouteState,
    evaluation_state,
    get_route,
    list_routes,
    route_facets,
    step_attributes,
)
from argus.attackpaths.store import Runs, Written, purge_resolved

__all__ = [
    "ROUTE_STEP_ATTRIBUTES",
    "LastEvaluation",
    "RouteFilters",
    "RouteKind",
    "RouteOrder",
    "RouteState",
    "Runs",
    "Written",
    "due",
    "evaluate",
    "evaluation_state",
    "fail",
    "finish",
    "get_route",
    "kinds_by_id",
    "last_evaluation",
    "list_routes",
    "load_kinds",
    "loads_digest",
    "purge_evaluations",
    "purge_resolved",
    "route_facets",
    "start",
    "step_attributes",
]
