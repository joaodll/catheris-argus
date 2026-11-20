"""Migration 0057: the Settings region list moves into every schedule and every request still to
run, and leaves the stored settings (owner, 2026-11-19)."""

import json

import pytest
from alembic import command
from sqlalchemy import Engine, text
from tests.conftest import alembic_config
from tests.ingest.conftest import make_demo

from argus.settings import read_collection

pytestmark = pytest.mark.db


def test_the_setting_moves_into_schedules_and_requests_still_to_run(migrated: Engine) -> None:
    try:
        _moves(migrated)
    finally:
        # The session shares this database: leave it as it was found.
        with migrated.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM run_request WHERE connection_id IN "
                    "(SELECT id FROM connection WHERE name = 'demo-57')"
                )
            )
            conn.execute(text("DELETE FROM schedule WHERE name = 'regions-0057'"))
            conn.execute(text("DELETE FROM connection WHERE name = 'demo-57'"))
            conn.execute(text("DELETE FROM platform_setting WHERE topic = 'collection'"))


def _moves(migrated: Engine) -> None:
    command.downgrade(alembic_config(), "0056")
    try:
        # The session's database holds other tests' rows: this test reads only its own.
        target = make_demo(migrated, seed=57)
        with migrated.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO platform_setting (topic, value, updated_by) VALUES "
                    "('collection', CAST(:v AS jsonb), 't') "
                    "ON CONFLICT (topic) DO UPDATE SET value = EXCLUDED.value"
                ),
                {
                    "v": json.dumps(
                        {"max_parallel_runs": 3, "aws_regions": ["us-east-1", "eu-west-1"]}
                    )
                },
            )
            conn.execute(
                text(
                    "INSERT INTO schedule (name, tools, cron, all_connections, updated_by) "
                    "VALUES ('regions-0057', '{prowler}', '0 2 * * *', true, 't')"
                )
            )
            for status in ("queued", "claimed", "finished"):
                conn.execute(
                    text(
                        "INSERT INTO run_request (connection_id, tool, reason, status, "
                        "claimed_at, heartbeat_at, finished_at, requested_by) "
                        "VALUES (:c, 'prowler', 'manual', :s, "
                        "CASE WHEN :s = 'queued' THEN NULL ELSE now() END, "
                        "CASE WHEN :s = 'queued' THEN NULL ELSE now() END, "
                        "CASE WHEN :s = 'finished' THEN now() END, 't')"
                    ),
                    {"c": target.connection_id, "s": status},
                )
    finally:
        command.upgrade(alembic_config(), "head")

    with migrated.connect() as conn:
        schedules = (
            conn.execute(text("SELECT aws_regions FROM schedule WHERE name = 'regions-0057'"))
            .scalars()
            .all()
        )
        requests = dict(
            conn.execute(
                text("SELECT status, aws_regions FROM run_request WHERE connection_id = :c"),
                {"c": target.connection_id},
            )
            .tuples()
            .all()
        )
        stored = conn.execute(
            text("SELECT value FROM platform_setting WHERE topic = 'collection'")
        ).scalar_one()
        settings = read_collection(conn)
    assert schedules == [["us-east-1", "eu-west-1"]]
    assert requests == {
        "queued": ["us-east-1", "eu-west-1"],
        "claimed": ["us-east-1", "eu-west-1"],  # so its retry keeps them
        "finished": [],
    }
    assert stored == {"max_parallel_runs": 3}
    assert settings.max_parallel_runs == 3  # the model, which refuses unknown keys, reads it

    # Down writes back every region (which schedule's list to keep is not knowable), then up
    # again copies that.
    command.downgrade(alembic_config(), "0056")
    try:
        with migrated.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT value -> 'aws_regions' FROM platform_setting "
                        "WHERE topic = 'collection'"
                    )
                ).scalar_one()
                == []
            )
    finally:
        command.upgrade(alembic_config(), "head")
    with migrated.connect() as conn:
        assert conn.execute(
            text("SELECT aws_regions FROM schedule WHERE name = 'regions-0057'")
        ).scalars().all() == [[]]
