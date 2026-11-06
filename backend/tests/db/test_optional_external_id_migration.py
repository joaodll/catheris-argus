"""Migration 0044: an assume-role connection may have no ExternalId (owner, 2026-11-05)."""

import pytest
from alembic import command
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from tests.conftest import alembic_config

pytestmark = pytest.mark.db
INSERT = text(
    "INSERT INTO connection (name, kind, account_id, auth_method, role_arn, created_by, "
    "updated_by) VALUES ('no-ext', 'aws', '210987654321', 'assume_role', "
    "'arn:aws:iam::210987654321:role/ArgusScanner', 't', 't')"
)


def _insert_refused(engine: Engine) -> bool:
    with engine.connect() as conn, conn.begin() as tx:
        try:
            conn.execute(INSERT)
        except IntegrityError:
            return True
        finally:
            if tx.is_active:
                tx.rollback()
    return False


def test_a_role_connection_needs_an_external_id_only_before_0044(migrated: Engine) -> None:
    assert not _insert_refused(migrated)
    command.downgrade(alembic_config(), "0043")
    try:
        assert _insert_refused(migrated)
    finally:
        command.upgrade(alembic_config(), "head")
    assert not _insert_refused(migrated)
