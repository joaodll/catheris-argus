"""Administration -> Users (ADR-0041): an admin manages users, the safety rules hold, every change
ends the sessions it should and is audited, and no hash ever leaves the API."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.api.conftest import PASSWORD, add_user, csrf

from argus.auth import SessionUser, UserRuleError, update_user
from argus.core.config import get_settings

pytestmark = pytest.mark.db
NEW = "another long passphrase"


def _sign_in(app_client: TestClient, username: str, password: str = PASSWORD) -> TestClient:
    other = TestClient(app_client.app, base_url="https://testserver")
    response = other.post("/api/v1/auth/sign-in", json={"username": username, "password": password})
    assert response.status_code == 204, response.text
    return other


def _user_id(owner: Engine, username: str) -> int:
    with owner.connect() as conn:
        return int(
            conn.execute(
                text("SELECT id FROM app_user WHERE username = :u"), {"u": username}
            ).scalar_one()
        )


def _audit(owner: Engine) -> list[str]:
    with owner.connect() as conn:
        return list(conn.execute(text("SELECT action FROM audit_log ORDER BY id")).scalars())


def test_an_admin_adds_a_user_who_must_choose_a_password(
    signed_in: TestClient, owner: Engine
) -> None:
    created = signed_in.post(
        "/api/v1/users",
        json={"username": "Maria", "display_name": "Maria S.", "role": "operator", "password": NEW},
        headers=csrf(signed_in),
    )
    assert created.status_code == 201
    body = created.json()
    assert body["username"] == "maria"  # usernames are lowercase
    assert body["role"] == "operator" and body["must_change_password"] is True
    assert "password" not in body and "argon2" not in created.text
    again = signed_in.post(
        "/api/v1/users",
        json={"username": "maria", "role": "viewer", "password": NEW},
        headers=csrf(signed_in),
    )
    assert again.status_code == 409
    listed = signed_in.get("/api/v1/users")
    assert [u["username"] for u in listed.json()["items"]] == ["admin", "maria"]
    assert "argon2" not in listed.text
    assert "user.created" in _audit(owner)


@pytest.mark.parametrize(
    ("username", "password"),
    [("x", NEW), ("bad name!", NEW), ("maria", "short"), ("maria.long", "maria.long")],
    ids=["too-short-name", "bad-characters", "short-password", "password-is-username"],
)
def test_bad_usernames_and_passwords_are_refused(
    signed_in: TestClient, username: str, password: str
) -> None:
    response = signed_in.post(
        "/api/v1/users",
        json={"username": username, "role": "viewer", "password": password},
        headers=csrf(signed_in),
    )
    assert response.status_code == 422


def test_you_cannot_demote_or_deactivate_yourself(signed_in: TestClient, owner: Engine) -> None:
    me = _user_id(owner, "admin")
    for patch in ({"role": "viewer"}, {"is_active": False}):
        response = signed_in.patch(f"/api/v1/users/{me}", json=patch, headers=csrf(signed_in))
        assert response.status_code == 409
        assert response.json()["detail"] == "You can't change your own role or deactivate yourself."
    renamed = signed_in.patch(
        f"/api/v1/users/{me}", json={"display_name": "Head admin"}, headers=csrf(signed_in)
    )
    assert renamed.status_code == 200 and renamed.json()["display_name"] == "Head admin"


def test_one_admin_may_demote_another_which_ends_their_session(
    signed_in: TestClient, owner: Engine
) -> None:
    add_user(owner, "second", "admin")
    second = _sign_in(signed_in, "second")
    me = _user_id(owner, "admin")
    demoted = second.patch(f"/api/v1/users/{me}", json={"role": "operator"}, headers=csrf(second))
    assert demoted.status_code == 200 and demoted.json()["role"] == "operator"
    assert signed_in.get("/api/v1/overview").status_code == 401  # the role change ended it
    with owner.connect() as conn:
        detail = conn.execute(
            text("SELECT detail FROM audit_log WHERE action = 'user.updated'")
        ).scalar_one()
    assert detail == {"role": ["admin", "operator"]}


def test_the_only_admin_cannot_be_demoted_by_anyone(signed_in: TestClient, owner: Engine) -> None:
    me = _user_id(owner, "admin")
    operator = add_user(owner, "oper", "operator")
    acting = SessionUser(operator, "oper", "", "admin", False)  # as if op held admin rights
    with owner.begin() as conn, pytest.raises(UserRuleError, match="at least one active admin"):
        update_user(conn, user_id=me, actor=acting, role="viewer")


def test_deactivating_a_user_ends_their_sessions(signed_in: TestClient, owner: Engine) -> None:
    viewer = add_user(owner, "watcher", "viewer")
    theirs = _sign_in(signed_in, "watcher")
    assert theirs.get("/api/v1/overview").status_code == 200
    response = signed_in.patch(
        f"/api/v1/users/{viewer}", json={"is_active": False}, headers=csrf(signed_in)
    )
    assert response.status_code == 200 and response.json()["is_active"] is False
    assert theirs.get("/api/v1/overview").status_code == 401
    refused = TestClient(signed_in.app, base_url="https://testserver").post(
        "/api/v1/auth/sign-in", json={"username": "watcher", "password": PASSWORD}
    )
    assert refused.status_code == 401
    assert "user.deactivated" in _audit(owner)


def test_only_an_inactive_user_is_deleted(signed_in: TestClient, owner: Engine) -> None:
    gone = add_user(owner, "leaver", "viewer")
    active = signed_in.delete(f"/api/v1/users/{gone}", headers=csrf(signed_in))
    assert active.status_code == 409
    signed_in.patch(f"/api/v1/users/{gone}", json={"is_active": False}, headers=csrf(signed_in))
    assert signed_in.delete(f"/api/v1/users/{gone}", headers=csrf(signed_in)).status_code == 204
    assert signed_in.delete(f"/api/v1/users/{gone}", headers=csrf(signed_in)).status_code == 404
    with owner.connect() as conn:
        actor = conn.execute(
            text("SELECT target_id FROM audit_log WHERE action = 'user.deleted'")
        ).scalar_one()
    assert actor == "leaver"  # the history keeps the username


def test_a_password_an_admin_sets_must_be_changed(signed_in: TestClient, owner: Engine) -> None:
    user = add_user(owner, "forgetful", "operator")
    theirs = _sign_in(signed_in, "forgetful")
    response = signed_in.post(
        f"/api/v1/users/{user}/password", json={"password": NEW}, headers=csrf(signed_in)
    )
    assert response.status_code == 204
    assert theirs.get("/api/v1/overview").status_code == 401  # their session ended
    fresh = _sign_in(signed_in, "forgetful", NEW)
    assert fresh.get("/api/v1/auth/session").json()["must_change_password"] is True
    me = _user_id(owner, "admin")
    own = signed_in.post(
        f"/api/v1/users/{me}/password", json={"password": NEW}, headers=csrf(signed_in)
    )
    assert own.status_code == 409  # your own goes through PUT /auth/password
    assert "user.password_set" in _audit(owner)


def test_changing_your_password_keeps_this_session_and_ends_the_others(
    signed_in: TestClient, owner: Engine
) -> None:
    elsewhere = _sign_in(signed_in, "admin")
    wrong = signed_in.put(
        "/api/v1/auth/password",
        json={"current_password": "not it at all", "new_password": NEW},
        headers=csrf(signed_in),
    )
    assert wrong.status_code == 422
    with owner.connect() as conn:
        failures = conn.execute(
            text("SELECT count(*) FROM login_failure WHERE username = 'admin'")
        ).scalar_one()
    assert failures == 1  # a guess counts against the sign-in limit
    ok = signed_in.put(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": NEW},
        headers=csrf(signed_in),
    )
    assert ok.status_code == 204
    assert signed_in.get("/api/v1/overview").status_code == 200
    assert elsewhere.get("/api/v1/overview").status_code == 401
    assert {"user.password_change_failed", "user.password_changed"} <= set(_audit(owner))


def test_guessing_the_current_password_hits_the_sign_in_limit(
    signed_in: TestClient, owner: Engine
) -> None:
    for _ in range(get_settings().login_max_failures):
        signed_in.put(
            "/api/v1/auth/password",
            json={"current_password": "a wrong guess", "new_password": NEW},
            headers=csrf(signed_in),
        )
    limited = signed_in.put(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": NEW},
        headers=csrf(signed_in),
    )
    assert limited.status_code == 429


def test_unlock_clears_a_locked_username(signed_in: TestClient, owner: Engine) -> None:
    user = add_user(owner, "locked.out", "viewer")
    with owner.begin() as conn:
        for _ in range(get_settings().login_max_failures):
            conn.execute(
                text("INSERT INTO login_failure (username, client_ip) VALUES ('locked.out', NULL)")
            )
    row = next(u for u in signed_in.get("/api/v1/users").json()["items"] if u["id"] == user)
    assert row["locked"] is True
    unlocked = signed_in.post(f"/api/v1/users/{user}/unlock", headers=csrf(signed_in))
    assert unlocked.status_code == 204
    row = next(u for u in signed_in.get("/api/v1/users").json()["items"] if u["id"] == user)
    assert row["locked"] is False
    assert "user.unlocked" in _audit(owner)


def test_sign_in_is_case_insensitive_on_the_username(client: TestClient) -> None:
    response = client.post("/api/v1/auth/sign-in", json={"username": "Admin", "password": PASSWORD})
    assert response.status_code == 204
    assert client.get("/api/v1/auth/session").json()["username"] == "admin"
