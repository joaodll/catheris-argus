"""`migrate --wait` (ADR-0039): ready at this image's head, or past it (a newer image migrated);
not ready while a migration is due."""

import pytest
from sqlalchemy import Engine, text
from tests.conftest import ALEMBIC_INI

from argus.entrypoints.migrate import schema_ready

pytestmark = pytest.mark.db


def _version(engine: Engine, version: str | None = None) -> str:
    with engine.begin() as conn:
        if version is not None:
            conn.execute(text("UPDATE alembic_version SET version_num = :v"), {"v": version})
        current: str = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        return current


def test_ready_at_head_or_past_it_and_not_before(migrated: Engine) -> None:
    head = _version(migrated)
    try:
        assert schema_ready(ALEMBIC_INI)
        _version(migrated, "0028")
        assert not schema_ready(ALEMBIC_INI)  # a migration is due
        _version(migrated, "9999_from_a_newer_image")
        assert schema_ready(ALEMBIC_INI)
    finally:
        _version(migrated, head)
