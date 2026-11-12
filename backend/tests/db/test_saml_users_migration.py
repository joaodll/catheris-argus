"""Migration 0049: users who sign in with SAML (ADR-0048)."""

from collections.abc import Iterator

import pytest
from alembic import command
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from tests.conftest import alembic_config

pytestmark = pytest.mark.db

INSERT = text(
    "INSERT INTO app_user (username, email, password_hash, role, auth_source, external_id, "
    "role_group, must_change_password, created_by, updated_by) "
    "VALUES (:u, :e, :h, 'viewer', :s, :x, :g, :m, 't', 't')"
)
SSO = {
    "u": "alice@example.test",
    "e": "alice@example.test",
    "h": None,
    "s": "saml",
    "x": "nameid-alice",
    "g": "sec-team",
    "m": False,
}
LOCAL = {"u": "bob", "e": None, "h": "$argon2id$x", "s": "local", "x": None, "g": None, "m": True}


@pytest.fixture
def conn(owner: Engine) -> Iterator[Connection]:
    with owner.connect() as c, c.begin() as tx:
        yield c
        tx.rollback()


def test_both_kinds_of_user_fit(conn: Connection) -> None:
    conn.execute(INSERT, SSO)
    conn.execute(INSERT, LOCAL)


@pytest.mark.parametrize(
    "change",
    [
        {"h": "$argon2id$x"},  # an SSO user never has a password
        {"x": None},  # nor lacks the IdP's id
        {"u": "alice"},  # their username is their email
        {"e": "other@example.test"},  # and their email is their username
        {"m": True},  # and nobody asks them for a new password
        {"x": "n" * 513},
        {"g": "g" * 257},
    ],
    ids=[
        "password",
        "no-external-id",
        "username-not-email",
        "email-differs",
        "must-change",
        "long-external-id",
        "long-group",
    ],
)
def test_an_sso_user_must_be_whole(conn: Connection, change: dict[str, object]) -> None:
    with pytest.raises(IntegrityError):
        conn.execute(INSERT, {**SSO, **change})


@pytest.mark.parametrize(
    "change",
    [{"h": None}, {"x": "nameid"}, {"g": "sec-team"}, {"u": "bob@example.test"}],
    ids=["no-password", "external-id", "role-group", "at-in-username"],
)
def test_a_local_user_keeps_its_old_shape(conn: Connection, change: dict[str, object]) -> None:
    with pytest.raises(IntegrityError):
        conn.execute(INSERT, {**LOCAL, **change})


def test_one_nameid_is_one_user(conn: Connection) -> None:
    conn.execute(INSERT, SSO)
    with pytest.raises(IntegrityError):
        conn.execute(INSERT, {**SSO, "u": "a2@example.test", "e": "a2@example.test"})


def test_an_sso_user_cannot_take_a_local_users_email(conn: Connection) -> None:
    conn.execute(INSERT, {**LOCAL, "e": "alice@example.test"})
    with pytest.raises(IntegrityError):
        conn.execute(INSERT, SSO)


def test_the_api_records_assertions_but_only_the_purge_deletes(owner: Engine) -> None:
    with owner.connect() as c, c.begin() as tx:
        c.execute(text("SET LOCAL ROLE argus_api"))
        c.execute(
            text("INSERT INTO saml_assertion_seen VALUES ('_a1', now() - interval '1 second')")
        )
        with pytest.raises(DBAPIError):
            c.execute(text("DELETE FROM saml_assertion_seen"))
        tx.rollback()
    with owner.begin() as c:
        c.execute(text("INSERT INTO saml_assertion_seen VALUES ('_old', now() - interval '1 s')"))
        c.execute(text("INSERT INTO saml_assertion_seen VALUES ('_new', now() + interval '5 m')"))
        c.execute(text("SET LOCAL ROLE argus_worker"))
        c.execute(text("SELECT argus_purge_sign_in_rows()"))
        c.execute(text("RESET ROLE"))
        left = c.execute(text("SELECT assertion_id FROM saml_assertion_seen")).scalars().all()
    assert left == ["_new"]


def test_downgrade_refuses_while_sso_users_exist_then_round_trips(owner: Engine) -> None:
    with owner.begin() as c:
        c.execute(INSERT, SSO)
    with pytest.raises(DBAPIError, match="SSO users exist"):
        command.downgrade(alembic_config(), "0048")
    with owner.begin() as c:
        c.execute(text("DELETE FROM app_user WHERE auth_source = 'saml'"))
    command.downgrade(alembic_config(), "0048")
    try:
        with owner.connect() as c, c.begin() as tx:
            with pytest.raises(DBAPIError):
                c.execute(INSERT, SSO)
            tx.rollback()
    finally:
        command.upgrade(alembic_config(), "head")
    with owner.begin() as c:
        c.execute(INSERT, SSO)
        c.execute(text("DELETE FROM app_user WHERE auth_source = 'saml'"))  # later tests downgrade
