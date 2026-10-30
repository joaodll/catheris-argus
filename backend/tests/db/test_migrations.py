import pytest
from alembic import command
from sqlalchemy import Engine, text
from tests.conftest import alembic_config

pytestmark = pytest.mark.db


def _tables(engine: Engine) -> set[str]:
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        ).scalars()
        return set(rows)


def test_upgrade_downgrade_upgrade_round_trips(migrated: Engine) -> None:
    before = _tables(migrated)
    assert {"connection", "scan_run", "resource_snapshot", "metric_daily"} <= before

    command.downgrade(alembic_config(), "base")
    assert _tables(migrated) <= {"alembic_version"}

    command.upgrade(alembic_config(), "head")
    assert _tables(migrated) == before


def test_partitions_exist_for_this_month_and_the_next(migrated: Engine) -> None:
    with migrated.connect() as conn:
        parts = set(
            conn.execute(
                text(
                    "SELECT c.relname FROM pg_inherits i "
                    "JOIN pg_class c ON c.oid = i.inhrelid "
                    "JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'metric_daily'"
                )
            ).scalars()
        )
        this_month, next_month = conn.execute(
            text(
                "SELECT to_char(current_date, 'YYYYMM'), "
                "to_char(current_date + interval '1 month', 'YYYYMM')"
            )
        ).one()
    assert {f"metric_daily_{this_month}", f"metric_daily_{next_month}"} <= parts
