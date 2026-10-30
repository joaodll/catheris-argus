"""Writing an inventory batch for one connection and day.

Re-running a day replaces that day's snapshot rows, so history never duplicates. A partial
run updates what it saw and carries the previous snapshot forward for the tables it did not
complete, so throttling does not look like resources disappearing. Only a table that was
complete marks resources of its type deleted (per-table completeness, argus_v8).

A resource uid has one owning connection, the first to load it (ADR-0034). Another connection
that reports the same uid never updates its row or writes its snapshot rows; the uid is kept as
an unresolved reference instead, so it is never dropped silently.
"""

import json
from datetime import date

from sqlalchemy import Connection, text

from argus.core.resolver import record_unresolved
from argus.inventory.steampipe import InventoryBatch

OWNED_ELSEWHERE = "resource owned by another connection (ADR-0034)"


def load_inventory(
    conn: Connection, *, batch: InventoryBatch, connection_id: int, day: date
) -> dict[str, int]:
    owned_elsewhere: list[str] = []
    # Configurations: one row per hash, ever.
    if batch.resources:
        owned_elsewhere = list(
            conn.execute(
                text(
                    "SELECT resource_uid FROM resource "
                    "WHERE resource_uid = ANY(CAST(:uids AS text[])) AND connection_id <> :c "
                    "ORDER BY resource_uid"
                ),
                {"uids": [r.uid for r in batch.resources], "c": connection_id},
            ).scalars()
        )
        conn.execute(
            text(
                "INSERT INTO resource_config (config_hash, config, created_on) "
                "VALUES (:h, CAST(:c AS jsonb), :d) ON CONFLICT (config_hash) DO NOTHING"
            ),
            [
                {"h": r.config_hash, "c": json.dumps(r.config, default=str), "d": day}
                for r in batch.resources
            ],
        )
        conn.execute(
            text("""
                INSERT INTO resource (resource_uid, connection_id, region, type, native_id, name,
                                      vpc_id, tags, config_id, first_seen, last_seen)
                SELECT :uid, :c, :region, :type, :native, :name, :vpc, CAST(:tags AS jsonb),
                       rc.id, :d, :d
                FROM resource_config rc WHERE rc.config_hash = :h
                ON CONFLICT (resource_uid) DO UPDATE SET
                  region = EXCLUDED.region, type = EXCLUDED.type, name = EXCLUDED.name,
                  vpc_id = EXCLUDED.vpc_id, tags = EXCLUDED.tags,
                  config_id = CASE WHEN resource.last_seen <= EXCLUDED.last_seen
                                   THEN EXCLUDED.config_id ELSE resource.config_id END,
                  first_seen = LEAST(resource.first_seen, EXCLUDED.first_seen),
                  last_seen = GREATEST(resource.last_seen, EXCLUDED.last_seen),
                  deleted_on = CASE WHEN resource.deleted_on <= EXCLUDED.last_seen
                                    THEN NULL ELSE resource.deleted_on END
                WHERE resource.connection_id = EXCLUDED.connection_id
            """),
            [
                {
                    "uid": r.uid,
                    "c": connection_id,
                    "region": r.region,
                    "type": r.type,
                    "native": r.native_id,
                    "name": r.name,
                    "vpc": r.vpc_id,
                    "tags": json.dumps(r.tags),
                    "h": r.config_hash,
                    "d": day,
                }
                for r in batch.resources
            ],
        )

    conn.execute(
        text(
            "DELETE FROM resource_snapshot rs USING resource r "
            "WHERE rs.resource_id = r.id AND rs.snapshot_date = :d AND r.connection_id = :c"
        ),
        {"d": day, "c": connection_id},
    )
    inserted = conn.execute(
        text("""
            INSERT INTO resource_snapshot (snapshot_date, resource_id, config_id)
            SELECT :d, r.id, rc.id
            FROM unnest(CAST(:uids AS text[]), CAST(:hashes AS bytea[])) AS b(uid, hash)
            JOIN resource r ON r.resource_uid = b.uid AND r.connection_id = :c
            JOIN resource_config rc ON rc.config_hash = b.hash
        """),
        {
            "d": day,
            "c": connection_id,
            "uids": [r.uid for r in batch.resources],
            "hashes": [r.config_hash for r in batch.resources],
        },
    ).rowcount

    carried = 0
    if batch.carry_types is None or batch.carry_types:
        # Throttled, denied or cut short: keep the previous view of what this run did not see,
        # for every type, or only for the incomplete tables' types.
        carried = conn.execute(
            text("""
                INSERT INTO resource_snapshot (snapshot_date, resource_id, config_id)
                SELECT :d, prev.resource_id, prev.config_id
                FROM resource_snapshot prev
                JOIN resource r ON r.id = prev.resource_id
                WHERE prev.snapshot_date = (
                        SELECT max(s.snapshot_date) FROM resource_snapshot s
                        JOIN resource r2 ON r2.id = s.resource_id
                        WHERE r2.connection_id = :c AND s.snapshot_date < :d
                          AND s.snapshot_date >= :d - 31)
                  AND r.connection_id = :c AND r.deleted_on IS NULL
                  AND (CAST(:types AS text[]) IS NULL OR r.type = ANY(CAST(:types AS text[])))
                ON CONFLICT DO NOTHING
            """),
            {
                "d": day,
                "c": connection_id,
                "types": None if batch.carry_types is None else sorted(batch.carry_types),
            },
        ).rowcount

    for uid in owned_elsewhere:
        record_unresolved(
            conn,
            tool="steampipe",
            connection_id=connection_id,
            raw_ref=uid,
            reason=OWNED_ELSEWHERE,
            day=day,
        )

    deleted = 0
    if batch.complete_types:
        deleted = conn.execute(
            text("""
                UPDATE resource SET deleted_on = :d
                WHERE connection_id = :c AND deleted_on IS NULL AND last_seen < :d
                  AND type = ANY(CAST(:types AS text[]))
            """),
            {"d": day, "c": connection_id, "types": sorted(batch.complete_types)},
        ).rowcount
    return {
        "resources": len(batch.resources),
        "snapshot_rows": inserted,
        "carried_forward": carried,
        "deleted": deleted,
        "owned_elsewhere": len(owned_elsewhere),
    }


def delete_orphan_configs(conn: Connection) -> int:
    """Deletes configurations no resource or remaining snapshot points to (retention runs this
    after dropping old partitions). Returns how many went."""
    deleted: int = conn.execute(
        text("""
        DELETE FROM resource_config rc
        WHERE NOT EXISTS (SELECT 1 FROM resource r WHERE r.config_id = rc.id)
          AND NOT EXISTS (SELECT 1 FROM resource_snapshot s WHERE s.config_id = rc.id)
    """)
    ).rowcount
    return deleted
