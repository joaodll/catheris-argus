"""Migration 0036 (owner's decision, 2026-11-01): resource_load is backfilled from the snapshots
with their counts, plus an ingested Steampipe day with no resource as 0, so an account whose
resources all went away reads empty; a downgrade drops it."""

from datetime import date

import pytest
from alembic import command
from sqlalchemy import Engine, text
from tests.conftest import alembic_config
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import FilesystemRawStore

pytestmark = pytest.mark.db
DAY = date(2026, 10, 30)


def test_loads_are_backfilled_and_a_downgrade_drops_them(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    try:
        command.downgrade(alembic_config(), "0035")
        with owner.begin() as conn:
            present = conn.execute(
                text(
                    "SELECT count(*) FROM resource_snapshot s JOIN resource r "
                    "ON r.id = s.resource_id WHERE r.connection_id = :c AND s.snapshot_date = :d"
                ),
                {"c": target.connection_id, "d": DAY},
            ).scalar_one()
            # A later ingested Steampipe run that found nothing.
            conn.execute(
                text("""
                INSERT INTO scan_run (run_uid, connection_id, tool, tool_version, source,
                                      snapshot_date, status, started_at, raw_path, ingested_at)
                VALUES (gen_random_uuid(), :c, 'steampipe', '1.34.0', 'synthetic', :d,
                        'complete', now(), 'raw/x', now())
            """),
                {"c": target.connection_id, "d": date(2026, 10, 31)},
            )
        command.upgrade(alembic_config(), "0036")
        with owner.connect() as conn:
            loads = conn.execute(
                text(
                    "SELECT snapshot_date, resources FROM resource_load WHERE connection_id = :c "
                    "ORDER BY 1"
                ),
                {"c": target.connection_id},
            ).all()
        assert [tuple(r) for r in loads] == [(DAY, present), (date(2026, 10, 31), 0)]
        assert present > 0
        command.downgrade(alembic_config(), "0035")
        with owner.connect() as conn:
            assert conn.execute(text("SELECT to_regclass('resource_load') IS NULL")).scalar_one()
    finally:
        command.upgrade(alembic_config(), "head")
        # test_schema, next in order, starts from an empty connection table.
        with owner.begin() as conn:
            conn.execute(text("TRUNCATE connection, scan_run, resource RESTART IDENTITY CASCADE"))
