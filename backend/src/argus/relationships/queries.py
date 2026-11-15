"""Read side of relationships: which edges stood on a given day."""

from dataclasses import dataclass
from datetime import date
from typing import Any, NamedTuple

from sqlalchemy import Connection, text

MAX_EDGES = 500  # how many of a resource's edges its panel lists

# Exported SQL: the view the attack-path kinds read as `e` (ADR-0052). One connection's
# effective edges: each family's snapshot that stands (bind :rule_day and :cloudfox_day to its
# latest loads), plus every manual edge.
EFFECTIVE_EDGES_SQL = """
  SELECT ed.id, ed.source_uid, ed.target_uid, ed.type, ed.origin, ed.attributes
  FROM edge ed JOIN edge_snapshot es ON es.edge_id = ed.id
  WHERE ed.connection_id = :connection_id
    AND ((starts_with(ed.origin, 'rule:') AND es.snapshot_date = :rule_day)
      OR (ed.origin = 'cloudfox' AND es.snapshot_date = :cloudfox_day))
  UNION ALL
  SELECT id, source_uid, target_uid, type, origin, attributes FROM edge WHERE origin = 'manual'
"""


@dataclass(frozen=True)
class EdgeLoad:
    """A connection's latest load of one edge family: its day and, for rules, the rule set."""

    connection_id: int
    family: str
    day: date
    ruleset: str | None


def latest_loads(conn: Connection) -> list[EdgeLoad]:
    """Every connection's latest load of each edge family, however old: the edges that stand
    now, and what an attack-path evaluation is computed from (its loads digest)."""
    rows = conn.execute(
        text("""
        SELECT DISTINCT ON (connection_id, family) connection_id, family, snapshot_date, ruleset
        FROM edge_load ORDER BY connection_id, family, snapshot_date DESC
    """)
    )
    return [EdgeLoad(r.connection_id, r.family, r.snapshot_date, r.ruleset) for r in rows]


def standing_edges(
    conn: Connection,
    *,
    loads: list[EdgeLoad],
    types: tuple[str, ...],
    attributes_of: tuple[str, ...],
) -> list[dict[str, Any]]:
    """The standing edges of these types in every connection with a load, plus the manual ones,
    each with its connection and the day of its family's load. Attributes are read only for the
    types in `attributes_of` (the others come back empty), so a walk over every account holds
    what it judges and no more. In edge id order, so a walk over the same edges finds the same
    routes in the same order (an unchanged estate writes nothing)."""
    days = [(ld.connection_id, ld.family, ld.day) for ld in loads]
    rows = conn.execute(
        text("""
        WITH d AS (
          SELECT * FROM unnest(CAST(:c AS bigint[]), CAST(:f AS text[]), CAST(:d AS date[]))
            AS d(connection_id, family, day)
        )
        SELECT e.id, e.source_uid, e.target_uid, e.source_resource_id, e.target_resource_id,
               e.type, e.origin, e.connection_id, d.day,
               CASE WHEN e.type = ANY(CAST(:a AS text[])) THEN e.attributes END AS attributes
        FROM d
        JOIN edge_snapshot s ON s.snapshot_date = d.day
        JOIN edge e ON e.id = s.edge_id AND e.connection_id = d.connection_id
         AND (CASE WHEN e.origin = 'cloudfox' THEN 'cloudfox' ELSE 'rule' END) = d.family
        WHERE e.type = ANY(CAST(:t AS text[]))
        UNION ALL
        SELECT e.id, e.source_uid, e.target_uid, e.source_resource_id, e.target_resource_id,
               e.type, e.origin, e.connection_id, NULL,
               CASE WHEN e.type = ANY(CAST(:a AS text[])) THEN e.attributes END
        FROM edge e WHERE e.origin = 'manual' AND e.type = ANY(CAST(:t AS text[]))
        ORDER BY 1
    """),
        {
            "c": [x[0] for x in days],
            "f": [x[1] for x in days],
            "d": [x[2] for x in days],
            "t": list(types),
            "a": list(attributes_of),
        },
    )
    return [dict(r._mapping) for r in rows]


def effective_days(conn: Connection, *, connection_id: int, day: date) -> dict[str, date | None]:
    """Each edge family's latest load on or before `day`, however old (owner's decision,
    2026-11-01: every screen shows each account's latest scan). A family (our relationship
    rules, CloudFox) is replaced whole by its next load, so a family whose tool did not run that
    day still stands, and a failed run does not erase edges."""
    return all_effective_days(conn, day=day, connection_ids=[connection_id]).get(
        connection_id, {"rule_day": None, "cloudfox_day": None}
    )


def all_effective_days(
    conn: Connection, *, day: date, connection_ids: list[int] | None = None
) -> dict[int, dict[str, date | None]]:
    """effective_days() for several connections (None: every one) in one read of edge_load,
    a small table keyed by connection, family and day."""
    rows = conn.execute(
        text("""
        SELECT connection_id, family, max(snapshot_date) AS day FROM edge_load
        WHERE snapshot_date <= :d
          AND (CAST(:c AS bigint[]) IS NULL OR connection_id = ANY(CAST(:c AS bigint[])))
        GROUP BY connection_id, family
    """),
        {"d": day, "c": connection_ids},
    )
    days: dict[int, dict[str, date | None]] = {}
    for r in rows:
        entry = days.setdefault(r.connection_id, {"rule_day": None, "cloudfox_day": None})
        entry["rule_day" if r.family == "rule" else "cloudfox_day"] = r.day
    return days


def latest_rule_loads(conn: Connection, *, day: date) -> dict[int, tuple[date, str | None]]:
    """Each connection's latest rule edge load standing on `day`, however old: its day and the
    rule set it was derived with (None: before migration 0026)."""
    rows = conn.execute(
        text("""
        SELECT DISTINCT ON (connection_id) connection_id, snapshot_date, ruleset
        FROM edge_load
        WHERE family = 'rule' AND snapshot_date <= :d
        ORDER BY connection_id, snapshot_date DESC
    """),
        {"d": day},
    )
    return {r.connection_id: (r.snapshot_date, r.ruleset) for r in rows}


class Door(NamedTuple):
    """What the internet rules say about one resource: its reach and why (ADR-0035)."""

    reach: str
    reason: str | None


@dataclass(frozen=True)
class InternetReach:
    """The internet rules' verdicts in one account on a day: `day` is the inventory day they
    judged (None: no rule load stands), `doors` each resource facing the internet."""

    day: date | None
    doors: dict[str, Door]


def internet_reach(conn: Connection, *, connection_id: int, day: date) -> InternetReach:
    """What Argus's internet rules say about each resource facing the internet in one account
    on a day (ADR-0035): "confirmed" (internet-entry: traffic can arrive), "restricted"
    (internet-restricted) or "unknown" (internet-unverified: data the verdict needs is missing),
    and the reason: a restricted door's own (not_running, nacl_blocks, ...), for an unknown one
    inspection_route (its default route goes to a firewall endpoint) or missing_data. CloudFox's
    public endpoints and Prowler's exposure checks are checked against it."""
    days = effective_days(conn, connection_id=connection_id, day=day)
    if days["rule_day"] is None:
        return InternetReach(None, {})
    rows = conn.execute(
        text("""
        SELECT e.target_uid,
               CASE WHEN bool_or(e.type = 'ROUTES_TO') THEN 'confirmed'
                    WHEN bool_or(e.type = 'PUBLIC_RESTRICTED') THEN 'restricted'
                    ELSE 'unknown' END AS reach,
               CASE WHEN bool_or(e.type = 'ROUTES_TO') THEN NULL
                    WHEN bool_or(e.type = 'PUBLIC_RESTRICTED')
                      THEN min(e.attributes ->> 'reason')
                             FILTER (WHERE e.type = 'PUBLIC_RESTRICTED')
                    WHEN bool_or(EXISTS (
                      SELECT 1 FROM jsonb_array_elements_text(
                        CASE jsonb_typeof(e.attributes -> 'missing')
                          WHEN 'array' THEN e.attributes -> 'missing' ELSE '[]' END) m
                      WHERE starts_with(m, 'inspection_route:'))) THEN 'inspection_route'
                    ELSE 'missing_data' END AS reason
        FROM edge e JOIN edge_snapshot s ON s.edge_id = e.id AND s.snapshot_date = :rd
        WHERE e.connection_id = :c AND e.source_uid = 'internet'
          AND e.type IN ('ROUTES_TO', 'PUBLIC_RESTRICTED', 'PUBLIC_UNVERIFIED')
          AND starts_with(e.origin, 'rule:')
        GROUP BY e.target_uid
    """),
        {"c": connection_id, "rd": days["rule_day"]},
    )
    return InternetReach(days["rule_day"], {r.target_uid: Door(r.reach, r.reason) for r in rows})


def edge_attributes(conn: Connection, edge_ids: list[int]) -> dict[int, dict[str, Any]]:
    """These edges' attributes, by id (an attack route's steps; the caller filters them to an
    allow-list before showing any)."""
    if not edge_ids:
        return {}
    rows = conn.execute(
        text("SELECT id, attributes FROM edge WHERE id = ANY(CAST(:ids AS bigint[]))"),
        {"ids": edge_ids},
    )
    return {r.id: r.attributes or {} for r in rows}


def delete_loads_before(conn: Connection, *, cutoff: date) -> int:
    """Retention: edge_load rows older than the history kept (their snapshots are gone)."""
    deleted: int = conn.execute(
        text("DELETE FROM edge_load WHERE snapshot_date < :c"), {"c": cutoff}
    ).rowcount
    return deleted


def edges_at(
    conn: Connection, *, resource_id: int, connection_id: int, day: date
) -> list[dict[str, Any]]:
    """Edges into and out of one resource as they stood on `day`, plus manual edges."""
    days = effective_days(conn, connection_id=connection_id, day=day)
    rows = conn.execute(
        text("""
        SELECT e.id, e.source_uid, e.target_uid, e.source_resource_id, e.target_resource_id,
               e.type, e.origin, e.attributes, e.first_seen, e.last_seen
        FROM edge e
        WHERE (e.source_resource_id = :r OR e.target_resource_id = :r)
          AND (e.origin = 'manual'
               OR EXISTS (SELECT 1 FROM edge_snapshot s WHERE s.edge_id = e.id
                          AND s.snapshot_date = CASE WHEN e.origin = 'cloudfox'
                                                     THEN CAST(:cf AS date)
                                                     ELSE CAST(:rd AS date) END))
        ORDER BY e.type, e.id LIMIT :l
    """),
        {"r": resource_id, "cf": days["cloudfox_day"], "rd": days["rule_day"], "l": MAX_EDGES},
    )
    return [dict(r._mapping) for r in rows]
