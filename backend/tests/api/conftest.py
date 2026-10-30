"""API tests drive the real app over HTTPS (the cookies are Secure) as the argus_api role, so
the API's grants are proven along with its behaviour."""

import base64
from collections.abc import Iterator

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, event, text

from argus.api import deps
from argus.api.app import create_app
from argus.core.config import get_settings
from argus.core.db import CONNECT_ARGS

PASSWORD = "correct horse battery staple"
KEY = base64.b64encode(b"k" * 32).decode()


@pytest.fixture
def api_engine(owner: Engine) -> Iterator[Engine]:
    engine = create_engine(get_settings().database_url(), connect_args=CONNECT_ARGS)

    @event.listens_for(engine, "connect")
    def _as_api(dbapi_conn, _record):  # type: ignore[no-untyped-def]
        with dbapi_conn.cursor() as cur:
            cur.execute("SET ROLE argus_api")

    yield engine
    engine.dispose()


def add_user(
    owner: Engine,
    username: str,
    role: str = "admin",
    *,
    password: str = PASSWORD,
    must_change: bool = False,
    active: bool = True,
) -> int:
    """A user straight into the table, as the bootstrap or an admin would make one."""
    with owner.begin() as conn:
        return int(
            conn.execute(
                text(
                    "INSERT INTO app_user (username, password_hash, role, is_active, "
                    "must_change_password, created_by, updated_by) "
                    "VALUES (:u, :h, :r, :a, :m, 't', 't') RETURNING id"
                ),
                {
                    "u": username,
                    "h": PasswordHasher().hash(password),
                    "r": role,
                    "a": active,
                    "m": must_change,
                },
            ).scalar_one()
        )


@pytest.fixture
def client(
    api_engine: Engine, owner: Engine, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    add_user(owner, "admin")
    monkeypatch.setenv("ARGUS_SECRET_KEYS", f"k1:{KEY}")
    monkeypatch.setenv("ARGUS_SECRET_KEY_ID", "k1")
    get_settings.cache_clear()
    monkeypatch.setattr(deps, "get_engine", lambda: api_engine)
    with TestClient(create_app(), base_url="https://testserver") as test_client:
        yield test_client
    get_settings.cache_clear()


def csrf(client: TestClient) -> dict[str, str]:
    return {"X-Argus-CSRF": client.cookies.get("argus_csrf") or ""}


@pytest.fixture
def signed_in(client: TestClient) -> TestClient:
    response = client.post("/api/v1/auth/sign-in", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 204
    return client
