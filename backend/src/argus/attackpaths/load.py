"""Loading a CloudFox batch: edges with origin "cloudfox", then attacker-view findings."""

from dataclasses import replace
from datetime import date

from sqlalchemy import Connection

from argus.attackpaths.cloudfox import CloudFoxBatch
from argus.core.resolver import record_unresolved
from argus.findings import ResolvedCommand, load_commands, load_tool_findings
from argus.inventory import uid_by_native_id
from argus.relationships import DerivedEdge, load_edges, owners_of_hosts


def load_cloudfox(
    conn: Connection,
    *,
    batch: CloudFoxBatch,
    connection_id: int,
    day: date,
    account_id: str,
    scan_run_id: int,
) -> dict[str, int]:
    edges: list[DerivedEdge] = []
    unresolved = [(ref, "endpoint not found in inventory") for ref in batch.unresolved]
    owners = owners_of_hosts(
        conn,
        connection_id=connection_id,
        day=day,
        hosts=sorted({e.target_host for e in batch.edges if e.target_host}),
    )
    for e in batch.edges:
        if e.target_host:
            target = owners.get(e.target_host)
        elif e.target_name:
            target = uid_by_native_id(
                conn, connection_id=connection_id, native_id=e.target_name, types=e.target_types
            )
        else:
            target = e.target_uid
        if target is None:
            if e.target_host:
                ref = f"{e.type}:{e.attributes.get('service')}:{e.target_host}"
                unresolved.append((ref, "address held by no resource in the inventory"))
            else:
                unresolved.append((f"{e.type}:{e.target_name}", "endpoint not found in inventory"))
            continue
        edges.append(DerivedEdge(e.source_uid, target, e.type, "cloudfox", e.attributes))
    for ref, reason in unresolved:
        record_unresolved(
            conn,
            tool="cloudfox",
            connection_id=connection_id,
            raw_ref=ref,
            reason=reason,
            day=day,
            scan_run_id=scan_run_id,
        )
    snapshot = load_edges(
        conn,
        edges=edges,
        connection_id=connection_id,
        day=day,
        origin_prefix="cloudfox",
        carry_forward=not batch.complete,
    )
    # A finding on a load balancer names it, like its edge: look it up in the inventory. Its
    # finding_uid keeps the name, so it is stable whether or not the lookup succeeds.
    found = []
    for f in batch.findings:
        name_and_types = batch.finding_targets.get(f.finding_uid)
        uid = (
            uid_by_native_id(
                conn,
                connection_id=connection_id,
                native_id=name_and_types[0],
                types=name_and_types[1],
            )
            if name_and_types
            else None
        )
        found.append(replace(f, resource_uid=uid) if uid else f)
    loaded = load_tool_findings(
        conn,
        tool="cloudfox",
        findings=found,
        executed=batch.executed,
        complete=batch.complete,
        connection_id=connection_id,
        day=day,
        account_id=account_id,
        scan_run_id=scan_run_id,
    )
    commands = _resolve_commands(conn, batch, connection_id=connection_id, day=day)
    command_rows = 0
    if batch.complete:
        # Current state: a complete run replaces the connection's commands; a partial one leaves
        # them (ADR-0038). A command whose built uid has no inventory row is kept (it shows once
        # the inventory has the resource) and recorded as unresolved, never dropped silently.
        not_inventoried = load_commands(
            conn, connection_id=connection_id, scan_run_id=scan_run_id, commands=commands
        )
        command_rows = len(commands)
        for uid in not_inventoried:
            record_unresolved(
                conn,
                tool="cloudfox",
                connection_id=connection_id,
                raw_ref=f"loot:{uid}",
                reason="loot command names a resource not in the inventory",
                day=day,
            )
    return {
        "edges": len(edges),
        "edge_snapshot_rows": snapshot,
        "unresolved": len(unresolved),
        "commands": command_rows,
        **{f"findings_{k}": v for k, v in loaded.items()},
    }


def _resolve_commands(
    conn: Connection, batch: CloudFoxBatch, *, connection_id: int, day: date
) -> list[ResolvedCommand]:
    """Each loot command's resource to a uid, as edges resolve (a built uid, a host's owner, or a
    name looked up by type). A host or name the inventory does not hold has no uid: it is
    recorded in unresolved_ref and left out. A built uid is kept; load_commands reports it when
    the inventory has no row for it."""
    hosts = sorted({c.resource_host for c in batch.commands if c.resource_host})
    owners = owners_of_hosts(conn, connection_id=connection_id, day=day, hosts=hosts)
    resolved: list[ResolvedCommand] = []
    for c in batch.commands:
        if c.resource_uid is not None:
            uid: str | None = c.resource_uid
        elif c.resource_host is not None:
            uid = owners.get(c.resource_host)
        elif c.resource_name is not None:
            uid = uid_by_native_id(
                conn, connection_id=connection_id, native_id=c.resource_name, types=c.resource_types
            )
        else:
            uid = None
        if uid is None:
            ref = c.resource_uid or c.resource_host or c.resource_name or c.source
            record_unresolved(
                conn,
                tool="cloudfox",
                connection_id=connection_id,
                raw_ref=f"loot:{c.source}:{ref}",
                reason="loot command names a resource not in the inventory",
                day=day,
            )
            continue
        resolved.append(
            ResolvedCommand(
                resource_uid=uid,
                label=c.label,
                command=c.command,
                note=c.note,
                source=c.source,
                ordinal=c.ordinal,
            )
        )
    return resolved
