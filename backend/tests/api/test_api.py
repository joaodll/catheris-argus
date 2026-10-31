import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from tests.api.conftest import PASSWORD, csrf
from tests.ingest.conftest import make_demo, run_tool

from argus.api import deps
from argus.auth.sessions import SignInError, TooManyAttemptsError, sign_in
from argus.collection import TOOL_ORDER
from argus.core.config import get_settings
from argus.core.rawstore import FilesystemRawStore
from argus.findings import PROWLER_EXPOSURE_CHECKS

pytestmark = pytest.mark.db
SECRET = "argus-test-only-not-a-real-secret-access-key"  # a fake, low-entropy value


def _audit(owner: Engine) -> list[str]:
    with owner.connect() as conn:
        return list(conn.execute(text("SELECT action FROM audit_log ORDER BY id")).scalars())


# --------------------------------------------------------------- auth
def test_health_is_open_everything_else_needs_a_session(client: TestClient) -> None:
    assert client.get("/api/v1/health").json() == {"status": "ok"}
    assert client.get("/api/v1/ready").json() == {"status": "ready"}
    assert client.get("/api/v1/overview").status_code == 401


def test_a_full_pool_answers_503_not_500(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    tiny = create_engine(
        get_settings().database_url(), pool_size=1, max_overflow=0, pool_timeout=0.1
    )
    monkeypatch.setattr(deps, "get_engine", lambda: tiny)
    try:
        with tiny.connect():  # the pool's only connection, held
            response = client.get("/api/v1/ready")
    finally:
        tiny.dispose()
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
    assert "pool" not in response.text.lower()  # no internals in the answer


def test_the_openapi_document_is_never_served(client: TestClient) -> None:
    paths = ("/api/v1/openapi.json", "/openapi.json", "/docs", "/redoc")
    assert {client.get(p).status_code for p in paths} == {404}
    signed = client.post("/api/v1/auth/sign-in", json={"username": "admin", "password": PASSWORD})
    assert signed.status_code == 204
    assert {client.get(p).status_code for p in paths} == {404}


def test_sign_in_lockout_and_sign_out(client: TestClient, owner: Engine) -> None:
    for _ in range(get_settings().login_max_failures):
        bad = client.post("/api/v1/auth/sign-in", json={"username": "admin", "password": "x"})
        assert bad.status_code == 401 and bad.json()["detail"] == "wrong username or password"
    locked = client.post("/api/v1/auth/sign-in", json={"username": "admin", "password": PASSWORD})
    assert locked.status_code == 429 and "Retry-After" in locked.headers
    with owner.begin() as conn:
        conn.execute(text("DELETE FROM login_failure"))
    ok = client.post("/api/v1/auth/sign-in", json={"username": "admin", "password": PASSWORD})
    assert ok.status_code == 204
    cookie = ok.headers.get_list("set-cookie")
    assert any(
        "argus_session=" in c and "HttpOnly" in c and "Secure" in c and "SameSite=strict" in c
        for c in cookie
    )
    assert client.get("/api/v1/auth/session").json() == {
        "username": "admin",
        "display_name": "",
        "role": "admin",
        "must_change_password": False,
    }
    assert client.post("/api/v1/auth/sign-out", headers=csrf(client)).status_code == 204
    assert client.get("/api/v1/auth/session").status_code == 401
    actions = _audit(owner)
    assert actions.count("auth.sign_in.failed") == 5
    assert {"auth.sign_in.limited", "auth.sign_in", "auth.sign_out"} <= set(actions)


def _failures(owner: Engine, username: str, addresses: list[str]) -> None:
    with owner.begin() as conn:
        for address in addresses:
            conn.execute(
                text(
                    "INSERT INTO login_failure (username, client_ip) VALUES (:u, CAST(:ip AS inet))"
                ),
                {"u": username, "ip": address},
            )


def test_another_address_cannot_lock_the_admin_out(client: TestClient, owner: Engine) -> None:
    settings = get_settings()
    _failures(owner, "admin", ["203.0.113.9"] * settings.login_max_failures)
    ok = client.post("/api/v1/auth/sign-in", json={"username": "admin", "password": PASSWORD})
    assert ok.status_code == 204
    # The attacker's failures survive the administrator's sign-in.
    with owner.connect() as conn:
        left = conn.execute(text("SELECT count(*) FROM login_failure")).scalar_one()
    assert left == settings.login_max_failures


def test_a_username_alone_locks_only_at_the_higher_limit(client: TestClient, owner: Engine) -> None:
    settings = get_settings()
    spread = [f"198.51.100.{i % 250}" for i in range(settings.login_max_failures_per_username)]
    _failures(owner, "admin", spread[:-1])
    ok = client.post("/api/v1/auth/sign-in", json={"username": "admin", "password": PASSWORD})
    assert ok.status_code == 204
    _failures(owner, "admin", spread[-1:])
    locked = client.post("/api/v1/auth/sign-in", json={"username": "admin", "password": PASSWORD})
    assert locked.status_code == 429


def test_one_address_spraying_usernames_is_limited(api_engine: Engine, owner: Engine) -> None:
    _failures(owner, "root", ["192.0.2.7"] * get_settings().login_max_failures_per_ip)
    with api_engine.connect() as conn, pytest.raises(TooManyAttemptsError):
        sign_in(conn, username="admin", password=PASSWORD, client_ip="192.0.2.7", user_agent=None)


def test_sign_in_attempts_for_one_username_are_serialized(api_engine: Engine) -> None:
    lock = text("SELECT pg_try_advisory_xact_lock(hashtextextended('argus.sign_in:admin', 0))")
    with api_engine.connect() as first, api_engine.connect() as second:
        with pytest.raises(SignInError):
            sign_in(first, username="admin", password="x", client_ip=None, user_agent=None)
        # Until the first attempt commits its failure, a second one waits.
        assert second.execute(lock).scalar_one() is False
        first.commit()
        assert second.execute(lock).scalar_one() is True
        second.rollback()


def test_a_wrong_username_gets_the_same_answer(client: TestClient) -> None:
    response = client.post("/api/v1/auth/sign-in", json={"username": "root", "password": "x"})
    assert response.status_code == 401
    assert response.json()["detail"] == "wrong username or password"


def test_writes_need_the_csrf_header(signed_in: TestClient) -> None:
    body = {"name": "s", "tools": ["prowler"], "cron": "0 2 * * *"}
    assert signed_in.post("/api/v1/schedules", json=body).status_code == 403
    assert (
        signed_in.post("/api/v1/schedules", json=body, headers=csrf(signed_in)).status_code == 201
    )


def test_security_headers(client: TestClient) -> None:
    headers = client.get("/api/v1/health").headers
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in headers["content-security-policy"]


# --------------------------------------------------------------- overview
def test_overview_and_context_from_real_data(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    today = datetime.now(UTC).date()
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, today)
    data = signed_in.get("/api/v1/overview", params={"connection_id": 0}).json()
    assert data["data_through"] == today.isoformat()
    assert data["kpis"]["assets"]["value"] > 100
    assert 0 < data["kpis"]["threatscore"]["value"] < 100
    assert data["kpis"]["exploitable_paths"]["value"] >= 1
    assert "delta" not in data["kpis"]["assets"]  # current state only (2026-10-03)
    assert "compared_with" not in data and "daily" not in data["inventory"]
    assert data["coverage"]["gcp"] == "not covered"
    assert {c["category"] for c in data["attack_paths_by_category"]} >= {"IAM privilege escalation"}
    context = signed_in.get("/api/v1/context").json()
    assert {r["tool"] for r in context["last_runs"]} == set(TOOL_ORDER)


def test_overview_without_data_is_null_not_zero(signed_in: TestClient) -> None:
    data = signed_in.get("/api/v1/overview").json()
    assert data["data_through"] is None
    assert data["kpis"]["assets"]["value"] is None
    assert data["check_results"]["pass_rate"] is None


# --------------------------------------------------------------- connections
def test_create_demo_connection_queues_its_backfill(signed_in: TestClient, owner: Engine) -> None:
    response = signed_in.post(
        "/api/v1/connections",
        headers=csrf(signed_in),
        json={"kind": "demo", "name": "demo-ui", "seed": 4, "backfill_days": 2},
    )
    assert response.status_code == 201 and response.json()["kind"] == "demo"
    with owner.connect() as conn:
        queued = conn.execute(text("SELECT count(*) FROM run_request")).scalar_one()
        assert queued == 2 * len(TOOL_ORDER)
    queue = signed_in.get("/api/v1/run-requests").json()
    assert queue["total"] == 2 * len(TOOL_ORDER)
    assert [(b["connection"], b["left"]) for b in queue["backfills"]] == [
        ("demo-ui", 2 * len(TOOL_ORDER))
    ]
    duplicate = signed_in.post(
        "/api/v1/connections",
        headers=csrf(signed_in),
        json={"kind": "demo", "name": "demo-ui", "seed": 5},
    )
    assert duplicate.status_code == 409


def test_aws_assume_role_connection(signed_in: TestClient) -> None:
    response = signed_in.post(
        "/api/v1/connections",
        headers=csrf(signed_in),
        json={
            "kind": "aws",
            "name": "prod",
            "account_id": "210987654321",
            "auth_method": "assume_role",
            "role_arn": "arn:aws:iam::210987654321:role/ArgusScanner",
            "external_id": "argus-external-id-0001",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["external_id_set"] is True and "external_id" not in body
    wrong_account = signed_in.post(
        "/api/v1/connections",
        headers=csrf(signed_in),
        json={
            "kind": "aws",
            "name": "x",
            "account_id": "210987654321",
            "auth_method": "assume_role",
            "role_arn": "arn:aws:iam::111111111111:role/ArgusScanner",
            "external_id": "argus-external-id-0001",
        },
    )
    assert wrong_account.status_code == 422


def test_an_access_key_connection_is_sealed_and_never_returned(
    signed_in: TestClient, owner: Engine
) -> None:
    body = {
        "kind": "aws",
        "name": "local",
        "account_id": "210987654321",
        "auth_method": "access_key",
        "access_key_id": "AKIA" + "Z" * 16,
        "secret_access_key": SECRET,
    }
    created = signed_in.post("/api/v1/connections", headers=csrf(signed_in), json=body)
    assert created.status_code == 201
    assert created.json()["access_key_id_hint"] == "…ZZZZ"
    assert created.json()["secret_set_at"] is not None
    listing = signed_in.get("/api/v1/connections").text
    assert SECRET not in created.text and SECRET not in listing
    with owner.connect() as conn:
        blob = conn.execute(text("SELECT secret_ciphertext FROM connection")).scalar_one()
        audit = json.dumps(
            [list(r) for r in conn.execute(text("SELECT * FROM audit_log"))], default=str
        )
    assert SECRET.encode() not in bytes(blob) and SECRET not in audit


TOKEN = "argus-test-only-not-a-real-session-token-" + "t" * 40  # a fake, low-entropy value


@pytest.mark.parametrize(
    ("prefix", "token", "expected"),
    [("ASIA", None, "needs its session_token"), ("AKIA", TOKEN, "takes no session_token")],
    ids=["temporary-without-token", "long-lived-with-token"],
)
def test_a_session_token_goes_with_temporary_keys_only(
    signed_in: TestClient, prefix: str, token: str | None, expected: str
) -> None:
    body = {
        "kind": "aws",
        "name": "local",
        "account_id": "210987654321",
        "auth_method": "access_key",
        "access_key_id": prefix + "Z" * 16,
        "secret_access_key": SECRET,
        "session_token": token,
    }
    refused = signed_in.post("/api/v1/connections", headers=csrf(signed_in), json=body)
    assert refused.status_code == 422 and expected in refused.json()["detail"]


def test_a_temporary_key_is_sealed_with_its_token_and_replaced_whole(
    signed_in: TestClient, owner: Engine
) -> None:
    created = signed_in.post(
        "/api/v1/connections",
        headers=csrf(signed_in),
        json={
            "kind": "aws",
            "name": "sso",
            "account_id": "210987654321",
            "auth_method": "access_key",
            "access_key_id": "ASIA" + "Z" * 16,
            "secret_access_key": SECRET,
            "session_token": TOKEN,
        },
    )
    assert created.status_code == 201
    connection_id = created.json()["id"]
    # A new SSO session: every part changes, and a long-lived key clears the token.
    replaced = signed_in.patch(
        f"/api/v1/connections/{connection_id}",
        headers=csrf(signed_in),
        json={"access_key": {"access_key_id": "AKIA" + "Q" * 16, "secret_access_key": SECRET}},
    )
    assert replaced.status_code == 200 and replaced.json()["access_key_id_hint"] == "…QQQQ"
    half = signed_in.patch(
        f"/api/v1/connections/{connection_id}",
        headers=csrf(signed_in),
        json={"access_key": {"access_key_id": "ASIA" + "Q" * 16, "secret_access_key": SECRET}},
    )
    assert half.status_code == 422
    texts = created.text + replaced.text + half.text + signed_in.get("/api/v1/connections").text
    assert TOKEN not in texts and SECRET not in texts
    with owner.connect() as conn:
        token_blob = conn.execute(
            text("SELECT session_token_ciphertext FROM connection")
        ).scalar_one()
        audit = conn.execute(
            text("SELECT detail FROM audit_log WHERE action = 'connection.update' ORDER BY id DESC")
        ).first()
        everything = json.dumps(
            [list(r) for r in conn.execute(text("SELECT * FROM audit_log"))], default=str
        )
    assert token_blob is None
    assert audit is not None and audit.detail == {"fields": ["access_key"]}
    assert TOKEN not in everything and SECRET not in everything


# --------------------------------------------------------------- schedules and runs
def test_schedule_preview_validation_and_crud(signed_in: TestClient, owner: Engine) -> None:
    preview = signed_in.post(
        "/api/v1/schedules/preview", headers=csrf(signed_in), json={"cron": "0 2 * * *"}
    ).json()
    assert preview["explanation"] and len(preview["next_runs"]) == 3
    too_often = signed_in.post(
        "/api/v1/schedules",
        headers=csrf(signed_in),
        json={"name": "x", "tools": ["prowler"], "cron": "*/5 * * * *"},
    )
    assert too_often.status_code == 422 and "minimum interval" in too_often.json()["detail"]
    created = signed_in.post(
        "/api/v1/schedules",
        headers=csrf(signed_in),
        json={
            "name": "nightly",
            "tools": ["steampipe", "prowler", "cloudfox"],
            "cron": "0 2 * * *",
        },
    ).json()
    updated = signed_in.put(
        f"/api/v1/schedules/{created['id']}",
        headers=csrf(signed_in),
        json={
            "name": "nightly",
            "tools": ["cloudfox", "steampipe"],
            "cron": "30 3 * * *",
            "enabled": False,
        },
    )
    assert updated.json()["cron"] == "30 3 * * *" and updated.json()["enabled"] is False
    assert created["tools"] == ["steampipe", "prowler", "cloudfox"]
    assert updated.json()["tools"] == ["steampipe", "cloudfox"]  # stored in tool order
    assert (
        signed_in.delete(f"/api/v1/schedules/{created['id']}", headers=csrf(signed_in)).status_code
        == 204
    )
    assert signed_in.get("/api/v1/schedules").json() == {"items": [], "total": 0}
    assert {"schedule.create", "schedule.update", "schedule.delete"} <= set(_audit(owner))


def test_run_now_and_its_cooldown(signed_in: TestClient, owner: Engine) -> None:
    target = make_demo(owner)
    first = signed_in.post(
        "/api/v1/run-requests",
        headers=csrf(signed_in),
        json={"connection_ids": [target.connection_id]},
    )
    assert first.status_code == 202 and len(first.json()["queued"]) == len(TOOL_ORDER)
    again = signed_in.post(
        "/api/v1/run-requests",
        headers=csrf(signed_in),
        json={"connection_ids": [target.connection_id], "tools": ["prowler"]},
    )
    assert again.status_code == 409
    queue = signed_in.get("/api/v1/run-requests").json()
    tools = len(TOOL_ORDER)
    assert len(queue["items"]) == tools and queue["total"] == tools and queue["backfills"] == []


def test_settings_and_their_environment_bound(signed_in: TestClient) -> None:
    settings = signed_in.get("/api/v1/settings").json()
    assert settings["collection"]["max_parallel_runs"] == 2
    collection = {**settings["collection"], "max_parallel_runs": 4}
    assert (
        signed_in.put(
            "/api/v1/settings/collection", headers=csrf(signed_in), json=collection
        ).json()["collection"]["max_parallel_runs"]
        == 4
    )
    over = signed_in.put(
        "/api/v1/settings/retention",
        headers=csrf(signed_in),
        json={"history_days": 9999, "demo_raw_days": 7},
    )
    assert over.status_code == 422 and "ARGUS_MAX_HISTORY_DAYS" in over.json()["detail"]


def test_raw_storage_setting(signed_in: TestClient, owner: Engine) -> None:
    stored = signed_in.get("/api/v1/settings").json()["raw_storage"]
    assert stored["bucket"] is None
    assert stored["prefixes"] == {
        "steampipe": "raw/steampipe",
        "prowler": "raw/prowler",
        "cloudfox": "raw/cloudfox",
        "inspector": "raw/inspector",
    }
    body = {
        "bucket": "argus-raw-example",
        "region": "eu-west-1",
        "prefixes": {
            "steampipe": "inventory",
            "prowler": "scans/prowler",
            "cloudfox": "cf",
            "inspector": "scans/inspector",
        },
    }
    saved = signed_in.put("/api/v1/settings/raw-storage", headers=csrf(signed_in), json=body)
    assert saved.status_code == 200 and saved.json()["raw_storage"] == body
    assert "settings.raw_storage" in _audit(owner)
    for bad in (
        {**body, "region": None},
        {**body, "bucket": "Not_A_Bucket"},
        {**body, "prefixes": {**body["prefixes"], "cloudfox": "../escape"}},
        {**body, "prefixes": {**body["prefixes"], "prowler": "/leading"}},
    ):
        refused = signed_in.put("/api/v1/settings/raw-storage", headers=csrf(signed_in), json=bad)
        assert refused.status_code == 422


def test_lists_are_paginated(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    today = datetime.now(UTC).date()
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, today)
    runs = signed_in.get("/api/v1/runs", params={"limit": 2}).json()
    assert len(runs["items"]) == 2 and runs["total"] == len(TOOL_ORDER)
    newest = [r["started_at"] for r in runs["items"]]
    assert newest == sorted(newest, reverse=True)
    # The run id names the run's folder in the raw archive.
    first = runs["items"][0]
    assert first["raw_path"].endswith(f"/{today:%Y/%m/%d}/{first['run_uid']}")
    oldest = signed_in.get("/api/v1/runs", params={"limit": 3, "order": "started_asc"}).json()
    assert [r["id"] for r in oldest["items"]] == sorted(r["id"] for r in oldest["items"])
    assert oldest["items"][0]["started_at"] <= oldest["items"][-1]["started_at"]
    beyond = signed_in.get("/api/v1/runs", params={"limit": 2, "offset": 10}).json()
    assert beyond == {"items": [], "total": len(TOOL_ORDER)}  # the UI moves to the last page
    assert signed_in.get("/api/v1/runs", params={"order": "tool"}).status_code == 422
    findings = signed_in.get("/api/v1/findings", params={"limit": 5, "severity": "critical"}).json()
    assert findings["items"] and all(f["severity"] == "critical" for f in findings["items"])
    paths = signed_in.get("/api/v1/attack-paths").json()
    assert paths["items"][0]["severity"] == "critical"
    assert signed_in.get("/api/v1/runs", params={"limit": 500}).status_code == 422
    # Every data list says which scan it reflects.
    assert findings["data_through"] == today.isoformat()
    assert paths["data_through"] == today.isoformat()
    resources = signed_in.get("/api/v1/resources", params={"limit": 1}).json()
    assert resources["data_through"] == today.isoformat()


def test_a_list_without_data_says_so(signed_in: TestClient) -> None:
    for path in ("/api/v1/findings", "/api/v1/attack-paths", "/api/v1/resources"):
        page = signed_in.get(path).json()
        assert page["items"] == [] and page["data_through"] is None
    assert signed_in.get("/api/v1/findings/facets").json() == {
        "regions": [],
        "services": [],
        "resource_types": [],
        "categories": [],
        "checks": [],
    }
    assert signed_in.get("/api/v1/resources/facets").json() == {"types": [], "regions": []}


SEVERITY_RANK = ["critical", "high", "medium", "low", "informational"]


def test_findings_filter_search_sort_and_count(
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = make_demo(owner)
    today = datetime.now(UTC).date()
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, today)

    def get(**params: object) -> dict:
        response = signed_in.get("/api/v1/findings", params={"limit": 200, **params})
        assert response.status_code == 200, response.text
        return response.json()

    every = get()
    items = every["items"]
    assert items and every["total"] >= len(items)
    assert {f["state"] for f in items} <= {"open", "reopened"}  # the default: still to fix
    assert {f["tool"] for f in items} == {"prowler", "cloudfox", "inspector"}
    ranks = [SEVERITY_RANK.index(f["severity"]) for f in items]
    assert ranks == sorted(ranks)  # worst first by default
    least = [SEVERITY_RANK.index(f["severity"]) for f in get(order="severity_asc")["items"]]
    assert least == sorted(least, reverse=True) and least[0] >= max(ranks)  # flipped

    # A finding's own link opens it, whatever its state.
    one = signed_in.get(f"/api/v1/findings/{items[0]['id']}")
    assert one.status_code == 200 and items[0].items() <= one.json().items()
    assert signed_in.get("/api/v1/findings/999999999").status_code == 404

    first = get(limit=5)
    assert len(first["items"]) == 5 and first["total"] == every["total"]
    beyond = get(offset=every["total"] + 10)
    assert beyond["items"] == [] and beyond["total"] == every["total"]  # the UI moves back

    regions = signed_in.get("/api/v1/findings/facets").json()["regions"]
    assert {f["region"] for f in items} <= set(regions)
    region = items[0]["region"]
    assert all(f["region"] == region for f in get(region=region)["items"])

    check = items[0]["check_id"]
    found = get(q=check.upper())  # any case
    assert found["total"] >= 1
    assert all(
        check in f["check_id"] or check in f["resource_uid"] or check in f["title"].lower()
        for f in found["items"]
    )
    assert get(q="%_no-such-text")["total"] == 0  # LIKE wildcards are taken literally

    newest = [f["last_seen"] for f in get(order="last_seen_desc")["items"]]
    assert newest == sorted(newest, reverse=True)

    linked = next(f for f in items if f["resource_id"] is not None)
    assert linked["resource_name"]
    on_resource = get(resource_id=linked["resource_id"])
    assert on_resource["total"] >= 1
    assert all(f["resource_id"] == linked["resource_id"] for f in on_resource["items"])
    unlinked = [f for f in items if f["resource_id"] is None]
    # Not in the inventory: the name Prowler reported, if any.
    assert all(f["resource_name"] for f in unlinked if f["tool"] == "prowler")

    assert get(state="resolved")["items"] == []  # one scan resolves nothing
    assert every["total_capped"] is False

    # A search counts up to the cap and says when there are more.
    broad = get(q=items[0]["resource_uid"][:4])  # "arn:" and the like: most findings
    assert broad["total"] > 2
    monkeypatch.setattr("argus.core.db.SEARCH_COUNT_CAP", 2)
    monkeypatch.setattr("argus.api.routes.findings.SEARCH_COUNT_CAP", 2)
    capped = get(q=items[0]["resource_uid"][:4])
    assert capped["total"] == 2 and capped["total_capped"] is True
    assert get()["total"] == every["total"]  # without a search the count is exact
    for bad in ({"order": "title"}, {"state": "closed"}, {"q": "x" * 201}):
        assert signed_in.get("/api/v1/findings", params=bad).status_code == 422


def test_findings_filters_take_several_values_and_match_both_tools(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Prowler-style filters (2026-10-07): repeated parameters match any of their values, and
    CloudFox findings carry Prowler's service, resource type and category names."""
    target = make_demo(owner)
    today = datetime.now(UTC).date()
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, today)

    def get(**params: object) -> dict:
        response = signed_in.get("/api/v1/findings", params={"limit": 200, **params})
        assert response.status_code == 200, response.text
        return response.json()

    every = get()
    facets = signed_in.get(
        "/api/v1/findings/facets", params={"connection_id": [target.connection_id]}
    ).json()
    assert {"iam", "awslambda"} <= set(facets["services"])
    assert "AwsIamRole" in facets["resource_types"]
    assert {"secrets", "privilege-escalation", "trust-boundaries", "internet-exposed"} <= set(
        facets["categories"]
    )
    checks = {(c["tool"], c["check_id"]) for c in facets["checks"]}
    assert {
        ("cloudfox", "cloudfox_env_var_secret"),
        ("cloudfox", "cloudfox_role_privesc_to_admin"),
        ("cloudfox", "cloudfox_cross_account_root_trust_no_external_id"),
        ("cloudfox", "cloudfox_public_endpoint"),
    } <= checks

    critical, high = get(severity="critical")["total"], get(severity="high")["total"]
    both = get(severity=["critical", "high"])
    assert both["total"] == critical + high
    assert {f["severity"] for f in both["items"]} <= {"critical", "high"}

    escalation = get(category="privilege-escalation")["items"]
    assert any(f["check_id"] == "cloudfox_role_privesc_to_admin" for f in escalation)
    assert all("privilege-escalation" in f["categories"] for f in escalation)
    iam = get(service="iam", tool=["prowler", "cloudfox"])["items"]
    assert {f["tool"] for f in iam} == {"prowler", "cloudfox"}
    assert all(f["service"] == "iam" for f in iam)
    roles = get(resource_type="AwsIamRole", tool="cloudfox")["items"]
    assert roles and all(f["resource_type"] == "AwsIamRole" for f in roles)
    picked = ["cloudfox_public_endpoint", "cloudfox_env_var_secret"]
    assert {f["check_id"] for f in get(check_id=picked)["items"]} == set(picked)

    assert get(status=["FAIL", "MANUAL"])["total"] == every["total"]
    assert all(f["status"] == "MANUAL" for f in get(status="MANUAL")["items"])
    hidden, only = get(muted="hide")["total"], get(muted="only")
    assert all(f["muted"] for f in only["items"])
    assert hidden + only["total"] == every["total"]
    assert get(new=True)["total"] == every["total"]  # one scan: everything is new
    assert get(connection_id=[target.connection_id, 999_999])["total"] == every["total"]
    # The provider is the finding's connection's (2026-10-10); only AWS connections exist yet.
    assert {f["provider"] for f in every["items"]} == {"aws"}
    assert get(provider="aws")["total"] == every["total"]
    assert get(provider=["gcp", "oci"])["total"] == 0
    for bad in (
        {"severity": "severe"},
        {"tool": "trivy"},
        {"provider": "azure"},
        {"provider": ["aws", "gcp", "oci", "aws"]},
        {"status": "PASS"},
        {"muted": "maybe"},
        {"region": "x" * 129},
        {"service": [f"s{i}" for i in range(51)]},
    ):
        assert signed_in.get("/api/v1/findings", params=bad).status_code == 422


def test_findings_reach_filter_and_reason(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """Prowler's exposure checks carry Argus's reach and why, beside CloudFox's public endpoints
    (ADR-0035, sixth amendment); the Reach filter lists them by verdict."""
    target = make_demo(owner)
    today = datetime.now(UTC).date()
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, today)

    def get(**params: object) -> dict:
        response = signed_in.get("/api/v1/findings", params={"limit": 200, **params})
        assert response.status_code == 200, response.text
        return response.json()

    reaches = ["confirmed", "restricted", "unknown", "not_covered"]
    checked = {"cloudfox_public_endpoint", *PROWLER_EXPOSURE_CHECKS}
    judged = get(reach=reaches)
    assert judged["total"] == sum(get(reach=r)["total"] for r in reaches)
    assert {f["check_id"] for f in judged["items"]} <= checked
    assert any(f["tool"] == "prowler" for f in judged["items"])
    for f in get(reach="restricted")["items"]:
        assert f["reach"] == "restricted" and f["reach_reason"], f
    assert all(f["reach_reason"] is None for f in get(reach="confirmed")["items"])
    others = [f for f in get()["items"] if f["check_id"] not in checked]
    assert others and all(f["reach"] is None and f["reach_reason"] is None for f in others)
    one = signed_in.get(f"/api/v1/findings/{judged['items'][0]['id']}").json()
    assert one["reach"] == judged["items"][0]["reach"]
    assert one["reach_reason"] == judged["items"][0]["reach_reason"]
    for bad in ({"reach": "maybe"}, {"reach": [*reaches, "confirmed"]}):
        assert signed_in.get("/api/v1/findings", params=bad).status_code == 422


def test_resources_filter_search_sort_and_count(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    today = datetime.now(UTC).date()
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, today)

    def get(**params: object) -> dict:
        response = signed_in.get("/api/v1/resources", params={"limit": 200, **params})
        assert response.status_code == 200, response.text
        return response.json()

    every = get()
    total = every["total"]
    assert every["items"] and total >= len(every["items"])
    assert all(r["deleted_on"] is None for r in every["items"])

    facets = signed_in.get("/api/v1/resources/facets").json()
    rtype = every["items"][0]["type"]
    assert rtype in facets["types"] and every["items"][0]["region"] in facets["regions"]
    of_type = get(type=rtype)
    assert of_type["total"] >= 1 and all(r["type"] == rtype for r in of_type["items"])

    if total <= 200:  # the whole list on one page: Z to A is A to Z reversed
        z_a = [r["id"] for r in get(order="name_desc")["items"]]
        assert [r["id"] for r in every["items"]] == list(reversed(z_a))

    one = every["items"][0]
    found = get(q=one["native_id"].upper())
    assert one["id"] in {r["id"] for r in found["items"]}

    # Open findings on a resource: the count and the worst severity.
    findings = signed_in.get("/api/v1/findings", params={"limit": 200}).json()["items"]
    linked = next(f for f in findings if f["resource_id"] is not None)
    on_it = signed_in.get(
        "/api/v1/findings", params={"limit": 200, "resource_id": linked["resource_id"]}
    ).json()["items"]
    row = next(
        r for r in get(q=linked["resource_uid"])["items"] if r["id"] == linked["resource_id"]
    )
    assert row["open_findings"] == len(on_it)
    worst = min(on_it, key=lambda f: SEVERITY_RANK.index(f["severity"]))["severity"]
    assert row["worst_severity"] == worst

    # A deleted resource leaves the list unless asked for.
    with owner.begin() as conn:
        conn.execute(
            text("UPDATE resource SET deleted_on = :d WHERE id = :i"), {"d": today, "i": one["id"]}
        )
    assert get()["total"] == total - 1
    assert get(include_deleted=True)["total"] == total
    detail = signed_in.get(f"/api/v1/resources/{one['id']}").json()
    assert detail["deleted_on"] == today.isoformat()


# --------------------------------------------------------------- history reads
def test_compliance_and_a_resource_as_of_a_past_day(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    today = datetime.now(UTC).date()
    earlier = today - timedelta(days=3)
    for day in (earlier, today):
        for tool in TOOL_ORDER:
            run_tool(worker, store, target, tool, day)
    response = signed_in.get("/api/v1/compliance")
    assert response.status_code == 200, response.text
    compliance = response.json()
    frameworks = {f["framework"]: f for f in compliance["items"]}
    assert set(frameworks) == {"cis_6.0_aws", "prowler_threatscore_aws"}
    assert compliance["total"] == 2 and compliance["data_through"] == today.isoformat()
    # Weekly points: the scan three days ago falls between two samples.
    assert all(len(f["trend"]) == 1 for f in frameworks.values())
    assert all(0 <= p["score"] <= 100 for f in frameworks.values() for p in f["trend"])

    page = signed_in.get(
        "/api/v1/resources", params={"type": "aws_ec2_instance", "limit": 200}
    ).json()
    with_edges = None
    for item in page["items"]:
        detail = signed_in.get(
            f"/api/v1/resources/{item['id']}", params={"as_of": earlier.isoformat()}
        ).json()
        if detail["edges"]:
            with_edges = detail
            break
    assert with_edges is not None
    assert with_edges["seen_on"] == earlier.isoformat() and with_edges["config"]
    for edge in with_edges["edges"]:  # an end in the inventory carries its name
        for end in ("source", "target"):
            assert (edge[f"{end}_name"] is None) == (edge[f"{end}_resource_id"] is None)
    before_any_scan = signed_in.get(
        f"/api/v1/resources/{with_edges['id']}",
        params={"as_of": (earlier - timedelta(days=1)).isoformat()},
    )
    assert before_any_scan.json()["seen_on"] is None
    assert before_any_scan.json()["config"] is None and before_any_scan.json()["edges"] == []
    assert signed_in.get("/api/v1/resources/999999").status_code == 404


def test_runs_report_denied_actions_and_raw_encryption(
    signed_in: TestClient, owner: Engine
) -> None:
    target = make_demo(owner)
    with owner.begin() as conn:
        for denied, encryption in (([], "aws:kms"), (["ec2:GetLaunchTemplateData"], "AES256")):
            conn.execute(
                text(
                    "INSERT INTO scan_run (run_uid, connection_id, tool, tool_version, source, "
                    "snapshot_date, status, started_at, raw_path, denied_actions, raw_encryption) "
                    "VALUES (gen_random_uuid(), :c, 'steampipe', '1.34.0', 'aws', '2026-10-05', "
                    "'partial', now(), 'x', :dn, :enc)"
                ),
                {"c": target.connection_id, "dn": denied, "enc": encryption},
            )
    every = signed_in.get("/api/v1/runs").json()["items"]
    assert len(every) == 2
    missing = signed_in.get("/api/v1/runs", params={"missing_permissions": True}).json()["items"]
    assert [(r["denied_actions"], r["raw_encryption"]) for r in missing] == [
        (["ec2:GetLaunchTemplateData"], "AES256")
    ]


def test_schedules_are_searched_by_name_and_paginated(signed_in: TestClient) -> None:
    for name in ("nightly-prod", "Nightly staging", "weekly", "100%_literal"):
        created = signed_in.post(
            "/api/v1/schedules",
            headers=csrf(signed_in),
            json={"name": name, "tools": ["prowler"], "cron": "0 2 * * *"},
        )
        assert created.status_code == 201, created.text

    def names(**params: object) -> tuple[set[str], int]:
        page = signed_in.get("/api/v1/schedules", params=params).json()
        return {s["name"] for s in page["items"]}, page["total"]

    # Names sort by the database's collation, so pages are compared as sets.
    assert names(q="NIGHTLY") == ({"Nightly staging", "nightly-prod"}, 2)  # any case
    assert names(q="%") == ({"100%_literal"}, 1)  # LIKE wildcards are literal
    assert names(q="_") == ({"100%_literal"}, 1)
    first, total = names(limit=2)
    second, _ = names(limit=2, offset=2)
    assert total == 4 and len(first) == len(second) == 2
    assert first | second == {"nightly-prod", "Nightly staging", "weekly", "100%_literal"}
    assert names(q="none") == (set(), 0)
    assert signed_in.get("/api/v1/schedules", params={"limit": 101}).status_code == 422
