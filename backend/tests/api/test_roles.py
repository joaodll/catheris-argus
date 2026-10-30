"""Roles on every route (ADR-0041): each route declares the least role it needs, the table below
is the whole matrix, and a request below it is refused (and audited) before anything else
runs."""

from collections.abc import Callable

import pytest
from fastapi import routing
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.api.conftest import PASSWORD, add_user, csrf

from argus.api.app import create_app
from argus.api.deps import RoleCheck, current_user
from argus.auth import ROLES, role_allows

pytestmark = pytest.mark.db

PUBLIC = {("GET", "/api/v1/health"), ("GET", "/api/v1/ready"), ("POST", "/api/v1/auth/sign-in")}
# Any signed-in user, even one who must change their password first.
ANY_USER = {
    ("POST", "/api/v1/auth/sign-out"),
    ("GET", "/api/v1/auth/session"),
    ("PUT", "/api/v1/auth/password"),
}
OPERATOR = {
    ("POST", "/api/v1/connections"),
    ("PATCH", "/api/v1/connections/{connection_id}"),
    ("POST", "/api/v1/connections/{connection_id}/test"),
    ("GET", "/api/v1/connection-tests/{test_id}"),
    ("POST", "/api/v1/schedules/preview"),
    ("POST", "/api/v1/schedules"),
    ("PUT", "/api/v1/schedules/{schedule_id}"),
    ("DELETE", "/api/v1/schedules/{schedule_id}"),
    ("POST", "/api/v1/run-requests"),
    ("POST", "/api/v1/run-requests/{request_id}/cancel"),
}
ADMIN = {
    ("POST", "/api/v1/settings/identity/test"),
    ("PUT", "/api/v1/settings/collection"),
    ("PUT", "/api/v1/settings/retention"),
    ("PUT", "/api/v1/settings/raw-storage"),
    ("PUT", "/api/v1/settings/identity"),
    ("GET", "/api/v1/users"),
    ("POST", "/api/v1/users"),
    ("PATCH", "/api/v1/users/{user_id}"),
    ("POST", "/api/v1/users/{user_id}/password"),
    ("POST", "/api/v1/users/{user_id}/unlock"),
    ("DELETE", "/api/v1/users/{user_id}"),
}


def _routes() -> list[tuple[str, str, routing.RouteContext]]:
    """Every (method, full path) of the app; routers are included lazily, so walk them."""
    return [
        (method, route.path, route)
        for route in routing.iter_route_contexts(create_app().routes)
        if isinstance(route.original_route, routing.APIRoute)
        for method in sorted(route.methods or ())
    ]


def _declared(route: routing.RouteContext) -> str | None:
    """The role a route's dependencies check, "any" for current_user alone, None for none."""
    stack = list(route.dependant.dependencies)
    found: str | None = None
    while stack:
        dep = stack.pop()
        if isinstance(dep.call, RoleCheck):
            return dep.call.needed
        if dep.call is current_user:
            found = "any"
        stack.extend(dep.dependencies)
    return found


def _expected(method: str, path: str) -> str | None:
    key = (method, path)
    if key in PUBLIC:
        return None
    if key in ANY_USER:
        return "any"
    if key in ADMIN:
        return "admin"
    return "operator" if key in OPERATOR else "viewer"


def test_every_route_declares_the_role_the_matrix_gives_it() -> None:
    wrong = {
        f"{method} {path}: declares {_declared(route)}, expected {_expected(method, path)}"
        for method, path, route in _routes()
        if _declared(route) != _expected(method, path)
    }
    assert not wrong, sorted(wrong)
    listed = PUBLIC | ANY_USER | OPERATOR | ADMIN
    assert listed <= {(m, p) for m, p, _ in _routes()}  # no stale row in the matrix


@pytest.fixture
def as_role(client: TestClient, owner: Engine) -> Callable[[str], TestClient]:
    """A signed-in client per role (the `client` fixture's admin is "admin")."""

    def make(role: str) -> TestClient:
        if role == "admin":
            other = client
            username = "admin"
        else:
            username = f"a-{role}"
            add_user(owner, username, role)
            other = TestClient(client.app, base_url="https://testserver")
        response = other.post(
            "/api/v1/auth/sign-in", json={"username": username, "password": PASSWORD}
        )
        assert response.status_code == 204
        return other

    return make


def test_a_role_below_the_route_is_refused_and_audited(
    as_role: Callable[[str], TestClient], owner: Engine
) -> None:
    clients = {role: as_role(role) for role in ROLES}
    checked = 0
    for method, path, route in _routes():
        needed = _declared(route)
        if needed in (None, "any"):
            continue
        url = path.replace("{", "").replace("}", "")  # a parameter's name: never an existing id
        url = "/".join("999999" if part.endswith("_id") else part for part in url.split("/"))
        for role, http in clients.items():
            response = http.request(method, url, json={}, headers=csrf(http))
            refused = response.status_code == 403
            assert refused != role_allows(role, needed), (role, method, path, response.text)  # type: ignore[arg-type]
            checked += 1
    assert checked > 100
    with owner.connect() as conn:
        denied = conn.execute(
            text("SELECT count(*) FROM audit_log WHERE action = 'access_denied'")
        ).scalar_one()
    assert denied > 0


def test_a_password_change_comes_before_everything_else(client: TestClient, owner: Engine) -> None:
    add_user(owner, "newcomer", "operator", must_change=True)
    assert (
        client.post(
            "/api/v1/auth/sign-in", json={"username": "newcomer", "password": PASSWORD}
        ).status_code
        == 204
    )
    session = client.get("/api/v1/auth/session").json()
    assert session["must_change_password"] is True and session["role"] == "operator"
    refused = client.get("/api/v1/overview")
    assert refused.status_code == 403 and refused.json()["detail"] == "password change required"
    changed = client.put(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": "a brand new passphrase"},
        headers=csrf(client),
    )
    assert changed.status_code == 204
    assert client.get("/api/v1/overview").status_code == 200
    assert client.get("/api/v1/auth/session").json()["must_change_password"] is False
