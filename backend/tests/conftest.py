"""Schema tests run against a throwaway database, never the development one.

The `test` service points ARGUS_DB_NAME at argus_test. This fixture recreates that database
from the owner's connection to `postgres`, then runs every migration into it.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import Engine, create_engine, event, text

from argus.core.config import get_settings
from argus.core.db import CONNECT_ARGS, get_engine
from argus.core.rawstore import FilesystemRawStore

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


def alembic_config() -> Config:
    return Config(str(ALEMBIC_INI))


@pytest.fixture(scope="session")
def migrated() -> Iterator[Engine]:
    settings = get_settings()
    if not settings.db_name.endswith("_test"):
        pytest.exit(f"refusing to run schema tests against {settings.db_name!r}", returncode=2)

    admin = create_engine(
        settings.database_url().set(database="postgres"), isolation_level="AUTOCOMMIT"
    )
    raw = admin.raw_connection()
    try:
        with raw.cursor() as cur:
            name = sql.Identifier(settings.db_name)
            cur.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(name))
            cur.execute(sql.SQL("CREATE DATABASE {}").format(name))
    finally:
        raw.close()
        admin.dispose()

    get_engine.cache_clear()
    command.upgrade(alembic_config(), "head")
    yield get_engine()
    get_engine().dispose()


# ---- shared by ingest and scheduling tests: a clean database, an engine acting as argus_worker
@pytest.fixture
def owner(migrated: Engine) -> Engine:
    with migrated.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE connection, scan_run, resource, resource_config, edge, audit_log, "
                "metric_daily, compliance_requirement, schedule, platform_setting, login_failure, "
                "user_session, app_user, flow_shape, flow_snapshot "
                "RESTART IDENTITY CASCADE"
            )
        )
    return migrated


@pytest.fixture
def worker(owner: Engine) -> Iterator[Engine]:
    engine = create_engine(get_settings().database_url(), connect_args=CONNECT_ARGS)

    @event.listens_for(engine, "connect")
    def _as_worker(dbapi_conn, _record):  # type: ignore[no-untyped-def]
        with dbapi_conn.cursor() as cur:
            cur.execute("SET ROLE argus_worker")

    yield engine
    engine.dispose()


@pytest.fixture
def scheduler(owner: Engine) -> Iterator[Engine]:
    """An engine acting as argus_scheduler (migration 0030): the Kubernetes scheduler's role."""
    engine = create_engine(get_settings().database_url(), connect_args=CONNECT_ARGS)

    @event.listens_for(engine, "connect")
    def _as_scheduler(dbapi_conn, _record):  # type: ignore[no-untyped-def]
        with dbapi_conn.cursor() as cur:
            cur.execute("SET ROLE argus_scheduler")

    yield engine
    engine.dispose()


@pytest.fixture
def store(tmp_path: Path) -> FilesystemRawStore:
    return FilesystemRawStore(tmp_path)
