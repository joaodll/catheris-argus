"""Read side of attack routes (the Attack paths screen): stored rows by index, nothing walked.

A step shows only the attributes ROUTE_STEP_ATTRIBUTES allows for its edge type, read from the
edge (already redacted) at display time (ADR-0052 §5, §9 M4). A step the walk made has no edge
and shows its stored reason and reference only.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import Connection, text

from argus import relationships
from argus.attackpaths.levels import CLASSES

RouteState = Literal["open", "resolved"]
RouteOrder = Literal["severity", "last_seen"]
# What a step shows of its edge's attributes, per edge type: the door's ports and verdict, and
# the evidence keys the step words read. Never a whole attributes object (§9 M4).
ROUTE_STEP_ATTRIBUTES: Mapping[str, tuple[str, ...]] = {
    "ROUTES_TO": ("open", "network", "via", "checked", "missing", "imds", "waf", "state",
                  "port", "protocol", "routes"),
    "PUBLIC_RESTRICTED": ("reason", "open_ports", "network", "via", "checked", "missing"),
    "PUBLIC_UNVERIFIED": ("missing", "checked", "network", "via", "dns"),
    "INTERNET_REACHABLE": ("port", "ports", "protocol"),
    "OUTSIDER": ("kind", "account"),
    "HAS_CREDENTIAL": ("credentials",),
    "CAN_CONNECT_TO": ("ports", "services", "engine"),
    "ACCESSES": ("level", "via_policy"),
    "CAN_RUN_ON": ("via", "unevaluated"),
    "IS_ADMIN": ("via_policy", "unevaluated"),
    "CAN_ESCALATE_TO": ("methods", "unevaluated"),
    "TRIGGERS": ("protocol",),
}  # fmt: skip
_SEVERITY_RANK = (
    "CASE r.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 "
    "WHEN 'low' THEN 2 ELSE 1 END"
)
_CLASS_RANK = "array_position(CAST(:classes_order AS text[]), r.worst_class)"


def step_attributes(type_: str, attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    allowed = ROUTE_STEP_ATTRIBUTES.get(type_, ())
    return {k: v for k, v in (attributes or {}).items() if k in allowed}


@dataclass(frozen=True)
class RouteFilters:
    state: RouteState = "open"
    connection_id: int | None = None
    crossing: bool = False  # with a connection: also the routes that cross it
    severity: tuple[str, ...] = ()
    kind: tuple[str, ...] = ()
    # Empty: every class but Latent (blocked), which is shown only when asked for.
    cls: tuple[str, ...] = ()
    through: int | None = None  # a resource id on a listed target's steps


def _where(f: RouteFilters) -> tuple[str, dict[str, Any]]:
    parts = [
        "r.state = 'resolved'" if f.state == "resolved" else "r.state <> 'resolved'",
        "r.worst_class = ANY(CAST(:cls AS text[]))",
    ]
    params: dict[str, Any] = {
        "cls": list(f.cls) or [c for c in CLASSES if c != "blocked"],
        "classes_order": list(CLASSES),
    }
    if f.connection_id is not None:
        params["c"] = f.connection_id
        parts.append(
            "(r.connection_id = :c OR r.crossed_connection_ids @> ARRAY[CAST(:c AS bigint)])"
            if f.crossing
            else "r.connection_id = :c"
        )
    if f.severity:
        parts.append("r.severity = ANY(CAST(:sev AS text[]))")
        params["sev"] = list(f.severity)
    if f.kind:
        parts.append("r.kind = ANY(CAST(:kind AS text[]))")
        params["kind"] = list(f.kind)
    if f.through is not None:
        parts.append(
            "EXISTS (SELECT 1 FROM route_node n WHERE n.route_id = r.id AND n.resource_id = :t)"
        )
        params["t"] = f.through
    return " AND ".join(parts), params


def list_routes(
    conn: Connection, f: RouteFilters, *, order: RouteOrder, limit: int, offset: int
) -> tuple[list[dict[str, Any]], int]:
    """One page of routes, worst first (severity, then the most sure, then the latest), with
    each route's worst target, and how many match."""
    where, params = _where(f)
    by = (
        f"{_SEVERITY_RANK} DESC, {_CLASS_RANK} DESC, r.last_seen DESC, r.id"
        if order == "severity"
        else f"COALESCE(r.resolved_on, r.last_seen) DESC, {_SEVERITY_RANK} DESC, r.id"
    )
    rows = conn.execute(
        text(f"""
        SELECT r.id, r.kind, r.entry_uid, r.entry_resource_id, r.connection_id,
               r.crossed_connection_ids AS crossed, r.severity, r.worst_class, r.target_count,
               r.listed_count, r.first_seen, r.last_seen, r.resolved_on, r.state,
               t.target_uid, t.target_resource_id,
               t.step_connection_id[cardinality(t.step_connection_id)] AS target_connection_id
        FROM route r JOIN route_target t ON t.route_id = r.id AND t.seq = 1
        WHERE {where}
        ORDER BY {by} LIMIT :limit OFFSET :offset
    """),  # noqa: S608 - fixed fragments, parameters only
        {**params, "limit": limit, "offset": offset},
    )
    items = [dict(r._mapping) for r in rows]
    total = conn.execute(
        text(f"SELECT count(*) FROM route r WHERE {where}"),  # noqa: S608 - fixed fragments
        params,
    ).scalar_one()
    return items, int(total)


def route_facets(conn: Connection, f: RouteFilters) -> dict[str, dict[str, int]]:
    """How many routes of each kind, severity and class under the state, connection and
    through filters (the pickers' counts)."""
    where, params = _where(RouteFilters(f.state, f.connection_id, f.crossing, through=f.through,
                                        cls=tuple(CLASSES)))  # fmt: skip
    out: dict[str, dict[str, int]] = {}
    for name, column in (("kind", "r.kind"), ("severity", "r.severity"), ("cls", "r.worst_class")):
        rows = conn.execute(
            text(f"SELECT {column} AS v, count(*) AS n FROM route r WHERE {where} GROUP BY 1"),  # noqa: S608
            params,
        )
        out[name] = {r.v: int(r.n) for r in rows}
    return out


_STEPS = text("""
    SELECT s.n, s.type, s.source_uid, s.target_uid, s.source_id, s.target_id, s.edge_id,
           s.origin, s.connection_id, s.day, s.level, s.reason, s.ref
    FROM route_target t,
         unnest(t.step_type, t.step_source_uid, t.step_target_uid, t.step_source_id,
                t.step_target_id, t.step_edge_id, t.step_origin, t.step_connection_id,
                t.step_day, t.step_level, t.step_reason, t.step_ref)
           WITH ORDINALITY AS s(type, source_uid, target_uid, source_id, target_id, edge_id,
                                origin, connection_id, day, level, reason, ref, n)
    WHERE t.route_id = :r AND t.seq = :q
    ORDER BY s.n
""")


def get_route(conn: Connection, route_id: int, *, target: int = 1) -> dict[str, Any] | None:
    """A route, its listed targets, and the chosen target's steps with their allowed
    attributes."""
    head = conn.execute(
        text("""
        SELECT id, kind, entry_uid, entry_resource_id, connection_id,
               crossed_connection_ids AS crossed, severity, worst_class, target_count,
               listed_count, first_seen, last_seen, resolved_on, state
        FROM route WHERE id = :r
    """),
        {"r": route_id},
    ).first()
    if head is None:
        return None
    targets = [
        dict(t._mapping)
        for t in conn.execute(
            text("""
            SELECT seq, target_uid, target_resource_id, severity, class AS cls, likelihood,
                   cardinality(step_type) AS steps,
                   step_connection_id[cardinality(step_connection_id)] AS connection_id
            FROM route_target WHERE route_id = :r ORDER BY seq
        """),
            {"r": route_id},
        )
    ]
    steps = [dict(s._mapping) for s in conn.execute(_STEPS, {"r": route_id, "q": target})]
    attributes = relationships.edge_attributes(
        conn, [s["edge_id"] for s in steps if s["edge_id"] is not None]
    )
    for s in steps:
        s["attributes"] = step_attributes(s["type"], attributes.get(s["edge_id"]))
    return {**dict(head._mapping), "targets": targets, "target": target, "steps": steps}


def evaluation_state(conn: Connection) -> dict[str, Any]:
    """The last evaluation that finished, and the last one, for the screen's banners."""
    rows = conn.execute(
        text("""
        (SELECT 'last' AS which, started_at, finished_at, status, newest_load_at
         FROM route_evaluation ORDER BY started_at DESC, id DESC LIMIT 1)
        UNION ALL
        (SELECT 'complete', started_at, finished_at, status, newest_load_at
         FROM route_evaluation WHERE status = 'complete' ORDER BY started_at DESC, id DESC LIMIT 1)
    """)
    )
    return {r.which: dict(r._mapping) for r in rows}
