"""The first admin from the environment, once (ADR-0041), and admin-tools' recovery of a
forgotten password."""

import pytest
from argon2 import PasswordHasher
from sqlalchemy import Engine, text

from argus.auth import bootstrap_admin, hash_password, reset_password
from argus.entrypoints import migrate

pytestmark = pytest.mark.db
PASSWORD = "a long first passphrase"
BOOTSTRAP_ENV = (
    "ARGUS_BOOTSTRAP_ADMIN_USERNAME",
    "ARGUS_BOOTSTRAP_ADMIN_PASSWORD",
    "ARGUS_BOOTSTRAP_ADMIN_PASSWORD_HASH",
    "ARGUS_ADMIN_USERNAME",
    "ARGUS_ADMIN_PASSWORD_HASH",
)


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in BOOTSTRAP_ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _users(owner: Engine) -> list[tuple[str, str, bool]]:
    with owner.connect() as conn:
        return [
            (r.username, r.role, r.must_change_password)
            for r in conn.execute(
                text("SELECT username, role, must_change_password FROM app_user ORDER BY id")
            )
        ]


def test_nothing_asked_creates_nothing(owner: Engine, clean_env: pytest.MonkeyPatch) -> None:
    assert migrate.bootstrap() is None
    # A username alone: the password was removed after the first sign-in.
    clean_env.setenv("ARGUS_BOOTSTRAP_ADMIN_USERNAME", "admin")
    assert migrate.bootstrap() is None
    assert _users(owner) == []


def test_the_first_admin_is_created_once(owner: Engine, clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("ARGUS_BOOTSTRAP_ADMIN_USERNAME", "Root")
    clean_env.setenv("ARGUS_BOOTSTRAP_ADMIN_PASSWORD", PASSWORD)
    assert migrate.bootstrap() == "created"
    assert _users(owner) == [("root", "admin", False)]
    clean_env.setenv("ARGUS_BOOTSTRAP_ADMIN_PASSWORD", "a different passphrase")
    assert migrate.bootstrap() == "skipped: an active admin exists"
    with owner.connect() as conn:
        stored = conn.execute(text("SELECT password_hash FROM app_user")).scalar_one()
        audited = conn.execute(
            text("SELECT actor FROM audit_log WHERE action = 'user.created'")
        ).scalar_one()
    assert PasswordHasher().verify(stored, PASSWORD)  # the second run changed nothing
    assert audited == "bootstrap"


def test_a_hash_from_hash_password_is_taken_as_it_is(
    owner: Engine, clean_env: pytest.MonkeyPatch
) -> None:
    clean_env.setenv("ARGUS_BOOTSTRAP_ADMIN_USERNAME", "admin")
    clean_env.setenv("ARGUS_BOOTSTRAP_ADMIN_PASSWORD_HASH", hash_password(PASSWORD))
    assert migrate.bootstrap() == "created"


def test_an_upgrade_keeps_the_environment_admin(
    owner: Engine, clean_env: pytest.MonkeyPatch
) -> None:
    """Before ADR-0041 the admin was ARGUS_ADMIN_PASSWORD_HASH: the upgrade signs in as before."""
    clean_env.setenv("ARGUS_ADMIN_PASSWORD_HASH", hash_password(PASSWORD))
    assert migrate.bootstrap() == "created"
    assert _users(owner) == [("admin", "admin", False)]


@pytest.mark.parametrize(
    "value",
    ["not-a-hash", "$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"],
    ids=["garbage", "argon2i"],
)
def test_only_an_argon2id_hash_is_taken(owner: Engine, value: str) -> None:
    with owner.begin() as conn, pytest.raises(ValueError, match="argon2id"):
        bootstrap_admin(conn, username="admin", password=None, password_hash=value)


def test_a_short_bootstrap_password_is_refused(owner: Engine) -> None:
    with owner.begin() as conn, pytest.raises(ValueError, match="password"):
        bootstrap_admin(conn, username="admin", password="short", password_hash=None)


def test_an_existing_user_is_never_changed(owner: Engine) -> None:
    with owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO app_user (username, password_hash, role, is_active, created_by, "
                "updated_by) VALUES ('admin', :h, 'admin', false, 't', 't')"
            ),
            {"h": hash_password("the old passphrase")},
        )
        result = bootstrap_admin(conn, username="admin", password=PASSWORD, password_hash=None)
    assert result.startswith("skipped: the user exists")
    assert _users(owner) == [("admin", "admin", False)]


def test_reset_password_needs_a_change_and_ends_sessions(owner: Engine) -> None:
    with owner.begin() as conn:
        user_id = conn.execute(
            text(
                "INSERT INTO app_user (username, password_hash, role, created_by, updated_by) "
                "VALUES ('maria', :h, 'operator', 't', 't') RETURNING id"
            ),
            {"h": hash_password("forgotten passphrase")},
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO user_session (token_hash, user_id, idle_expires_at, "
                "absolute_expires_at) VALUES (:t, :u, now() + interval '1 hour', "
                "now() + interval '1 hour')"
            ),
            {"t": b"x" * 32, "u": user_id},
        )
        reset_password(conn, username="Maria", password=PASSWORD)
    with owner.connect() as conn:
        live = conn.execute(
            text("SELECT count(*) FROM user_session WHERE revoked_at IS NULL")
        ).scalar_one()
        actor = conn.execute(
            text("SELECT actor FROM audit_log WHERE action = 'user.password_set'")
        ).scalar_one()
    assert _users(owner) == [("maria", "operator", True)]
    assert live == 0 and actor == "admin-tools"
    with owner.begin() as conn, pytest.raises(LookupError):
        reset_password(conn, username="nobody", password=PASSWORD)
