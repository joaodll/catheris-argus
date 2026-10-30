"""Read side of relationships: which edges stood on a given day."""

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, NamedTuple

from sqlalchemy import Connection, text

CARRY_FORWARD_DAYS = 31
MAX_EDGES = 500  # the map's neighbourhood cap (design: "Queries")

# Exported SQL: the view attack-path rules read as `e`. One connection's effective edges:
# each family's snapshot that stands for the day (bind :rule_day and :cloudfox_day to
# effective_days()), plus every manual edge.
EFFECTIVE_EDGES_SQL = """
  SELECT ed.id, ed.source_uid, ed.target_uid, ed.type, ed.origin, ed.attributes
  FROM edge ed JOIN edge_snapshot es ON es.edge_id = ed.id
  WHERE ed.connection_id = :connection_id
    AND ((starts_with(ed.origin, 'rule:') AND es.snapshot_date = :rule_day)
      OR (ed.origin = 'cloudfox' AND es.snapshot_date = :cloudfox_day))
  UNION ALL
  SELECT id, source_uid, target_uid, type, origin, attributes FROM edge WHERE origin = 'manual'
"""


def effective_days(conn: Connection, *, connection_id: int, day: date) -> dict[str, date | None]:
    """Each edge family's latest snapshot on or before `day`, within the window. A family
    (our relationship rules, CloudFox) is replaced whole by its next snapshot, so a family whose
    tool did not run that day still stands, and a failed run does not erase edges."""
    return all_effective_days(conn, day=day, connection_ids=[connection_id]).get(
        connection_id, {"rule_day": None, "cloudfox_day": None}
    )


def all_effective_days(
    conn: Connection, *, day: date, connection_ids: list[int] | None = None
) -> dict[int, dict[str, date | None]]:
    """effective_days() for several connections (None: every one) in one read of edge_load."""
    rows = conn.execute(
        text("""
        SELECT connection_id, family, max(snapshot_date) AS day FROM edge_load
        WHERE snapshot_date BETWEEN :start AND :d
          AND (CAST(:c AS bigint[]) IS NULL OR connection_id = ANY(CAST(:c AS bigint[])))
        GROUP BY connection_id, family
    """),
        {"d": day, "start": day - timedelta(days=CARRY_FORWARD_DAYS), "c": connection_ids},
    )
    days: dict[int, dict[str, date | None]] = {}
    for r in rows:
        entry = days.setdefault(r.connection_id, {"rule_day": None, "cloudfox_day": None})
        entry["rule_day" if r.family == "rule" else "cloudfox_day"] = r.day
    return days


def latest_load_day(conn: Connection, *, connection_id: int) -> date | None:
    """The latest day either edge family (rules, CloudFox) has a load for, in one account."""
    value: date | None = conn.execute(
        text("SELECT max(snapshot_date) FROM edge_load WHERE connection_id = :c"),
        {"c": connection_id},
    ).scalar()
    return value


def latest_rule_loads(conn: Connection, *, day: date) -> dict[int, tuple[date, str | None]]:
    """Each connection's latest rule edge load still standing on `day` (within the window): its
    day and the rule set it was derived with (None: before migration 0026)."""
    rows = conn.execute(
        text("""
        SELECT DISTINCT ON (connection_id) connection_id, snapshot_date, ruleset
        FROM edge_load
        WHERE family = 'rule' AND snapshot_date BETWEEN :start AND :d
        ORDER BY connection_id, snapshot_date DESC
    """),
        {"d": day, "start": day - timedelta(days=CARRY_FORWARD_DAYS)},
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
