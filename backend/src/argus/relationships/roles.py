"""How many workloads run as each IAM role (role_workload, migration 0053), for the Resources
list's role use: written with each rule load, read by resource id or as a filter's set.

A workload is a resource on a RUNS_AS line of the rules (instance-role, function-role,
container-role): an EC2 instance, a Lambda function, an ECS service or an EKS node group. A role
used by people, CI, other accounts or other AWS services has none; its last use
(inventory.role_last_used) says whether it is used at all. The rules read the day's inventory with
the tables a run could not read carried forward, so a failed Lambda table does not drop a count.
"""

from datetime import date

from sqlalchemy import Connection, text

from argus.inventory import CURRENT_ROLES_SQL

WORKLOAD_EDGE = "RUNS_AS"

# Exported SQL for inventory.ResourceFilters.within: the roles no workload runs as, by their
# connection's latest rule load. A role with no row (no rule load yet) is not in it.
NO_WORKLOAD_ROLES_SQL = "SELECT rw.resource_id FROM role_workload rw WHERE rw.workloads = 0"


def put_role_workloads(conn: Connection, *, connection_id: int, day: date) -> int:
    """Rewrites the connection's counts from its rule load of `day`, inside the load's own
    transaction; nothing when a later rule load exists (a re-run of an older day). Counts only
    the connection's own lines: a role runs as itself in its own account. Returns the rows
    written."""
    latest = conn.execute(
        text(
            "SELECT max(snapshot_date) FROM edge_load WHERE connection_id = :c AND family = 'rule'"
        ),
        {"c": connection_id},
    ).scalar_one()
    if latest is not None and latest > day:
        return 0
    conn.execute(text("DELETE FROM role_workload WHERE connection_id = :c"), {"c": connection_id})
    written: int = conn.execute(
        text(f"""
            INSERT INTO role_workload (resource_id, connection_id, workloads, rule_day)
            SELECT r.id, :c, count(DISTINCT e.source_uid), :d
            FROM ({CURRENT_ROLES_SQL}) r
            LEFT JOIN edge e
              ON e.target_resource_id = r.id AND e.connection_id = :c AND e.type = :t
             AND starts_with(e.origin, 'rule:')
             AND EXISTS (SELECT 1 FROM edge_snapshot es
                         WHERE es.edge_id = e.id AND es.snapshot_date = :d)
            GROUP BY r.id
        """),  # noqa: S608 - exported SQL constant only
        {"c": connection_id, "d": day, "t": WORKLOAD_EDGE},
    ).rowcount
    return written


def role_workloads(conn: Connection, resource_ids: list[int]) -> dict[int, int]:
    """How many workloads run as each of these roles; a role with no row is absent (no rule
    load yet: "not covered", never a zero). For one page of ids."""
    if not resource_ids:
        return {}
    rows = conn.execute(
        text(
            "SELECT resource_id, workloads FROM role_workload "
            "WHERE resource_id = ANY(CAST(:ids AS bigint[]))"
        ),
        {"ids": resource_ids},
    )
    return {r.resource_id: r.workloads for r in rows}
