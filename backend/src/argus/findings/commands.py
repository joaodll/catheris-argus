"""CloudFox's loot commands (ADR-0038): store and read. The adapter parses and the loader
resolves them to a resource; this module writes them and reads them back for a resource.

Current state, not history: a complete CloudFox run replaces its connection's rows in one
transaction, and a failed or partial run never calls the writer. Each row is already cleaned
(redact_text in the adapter); nothing here touches the command text."""

from dataclasses import dataclass

from sqlalchemy import Connection, text

from argus.inventory import resource_id_sql


@dataclass(frozen=True)
class ResolvedCommand:
    """A loot command whose resource resolved to an inventory uid, ready to store."""

    resource_uid: str
    label: str
    command: str
    note: str | None
    source: str
    ordinal: int


@dataclass(frozen=True)
class ResourceCommand:
    """A command shown on a resource (the finding detail, the resource sheet)."""

    label: str
    command: str
    note: str | None
    source: str


def load_commands(
    conn: Connection, *, connection_id: int, scan_run_id: int, commands: list[ResolvedCommand]
) -> list[str]:
    """Replace a connection's loot commands with this set (a complete run only). resource_id is
    the inventory row for the uid, or NULL when the resource is not inventoried. Returns those
    uids with no inventory row, for the loader to record as unresolved."""
    conn.execute(text("DELETE FROM finding_command WHERE connection_id = :c"), {"c": connection_id})
    if commands:
        conn.execute(
            text(f"""
                INSERT INTO finding_command (connection_id, resource_uid, resource_id, label,
                                             command, note, source, ordinal, scan_run_id)
                VALUES (:c, :ruid, {resource_id_sql("ruid")}, :label, :command, :note, :source,
                        :ordinal, :run)
            """),  # noqa: S608 - resource_id_sql is a constant subquery, :ruid is a bind param
            [
                {
                    "c": connection_id,
                    "ruid": r.resource_uid,
                    "label": r.label,
                    "command": r.command,
                    "note": r.note,
                    "source": r.source,
                    "ordinal": r.ordinal,
                    "run": scan_run_id,
                }
                for r in commands
            ],
        )
    rows = conn.execute(
        text("""
            SELECT DISTINCT resource_uid FROM finding_command
            WHERE connection_id = :c AND resource_id IS NULL ORDER BY resource_uid
        """),
        {"c": connection_id},
    )
    return list(rows.scalars())


def commands_for_resource(
    conn: Connection, *, connection_id: int, resource_uid: str
) -> list[ResourceCommand]:
    """A resource's loot commands from its connection's CloudFox (ADR-0034: data is keyed per
    connection), read-only checks first, then by file order."""
    rows = conn.execute(
        text("""
            SELECT label, command, note, source FROM finding_command
            WHERE connection_id = :c AND resource_uid = :uid
            ORDER BY CASE label WHEN 'check' THEN 0 WHEN 'reads_data' THEN 1 ELSE 2 END,
                     source, ordinal
        """),
        {"c": connection_id, "uid": resource_uid},
    ).all()
    return [
        ResourceCommand(label=r.label, command=r.command, note=r.note, source=r.source)
        for r in rows
    ]
