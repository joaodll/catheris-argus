"""MVP exit-gate flows, from an administrator's API write to what the worker does next.

The API runs as argus_api and the worker as argus_worker, sharing one database and no process
state. So each test also proves that the change needs no restart and no environment change:
the worker picks it up because it re-reads Postgres on every tick and every claim.
"""

import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.api.conftest import csrf
from tests.ingest.conftest import RULES_DIR, make_demo, run_tool

from argus.collection import TOOL_ORDER
from argus.core.config import get_settings
from argus.core.logging import JsonFormatter
from argus.core.rawstore import FilesystemRawStore
from argus.entrypoints import seed
from argus.scheduling import maintenance, runner

pytestmark = pytest.mark.db

# Secret values the synthetic generators plant in raw output on purpose (estate.py: Lambda
# DB_PASSWORD; steampipe.py: an APP_TOKEN inside base64 user_data). "IyEvYmluL2Jhc2g" is
# base64 of "#!/bin/bash", the start of every planted user_data.
MARKERS = re.compile(r"pw-[0-9a-f]{12}|tok-[0-9a-f]{16}|IyEvYmluL2Jhc2g")
SECRET = "argus-test-only-not-a-real-identity-secret"  # a fake, low-entropy value
OPENAPI = Path(__file__).resolve().parents[2] / "openapi.json"


def _put_collection(client: TestClient, **values: object) -> None:
    current = client.get("/api/v1/settings/collection").json()
    response = client.put(
        "/api/v1/settings/collection", headers=csrf(client), json={**current, **values}
    )
    assert response.status_code == 200, response.text


def _maintain(worker: Engine, store: FilesystemRawStore, now: datetime) -> None:
    # One main-loop pass without retention.
    maintenance.maintain(worker, now=now)


def _queued(owner: Engine) -> list[datetime]:
    with owner.connect() as conn:
        return list(
            conn.execute(
                text("SELECT not_before FROM run_request WHERE reason = 'schedule' ORDER BY id")
            ).scalars()
        )


# --------------------------------------------------------------- gate check 7
def test_a_schedule_changed_in_the_ui_runs_at_its_new_time(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    make_demo(owner)
    _put_collection(signed_in, stagger_window_minutes=0)
    old = (datetime.now(UTC) + timedelta(hours=2)).replace(minute=0, second=0, microsecond=0)
    new = old + timedelta(hours=2)
    created = signed_in.post(
        "/api/v1/schedules",
        headers=csrf(signed_in),
        json={"name": "nightly", "tools": ["prowler"], "cron": f"0 {old.hour} * * *"},
    ).json()
    moved = signed_in.put(
        f"/api/v1/schedules/{created['id']}",
        headers=csrf(signed_in),
        json={"name": "nightly", "tools": ["prowler"], "cron": f"0 {new.hour} * * *"},
    )
    assert moved.status_code == 200, moved.text

    _maintain(worker, store, old + timedelta(minutes=1))
    assert _queued(owner) == []  # the old time no longer runs
    _maintain(worker, store, new + timedelta(minutes=1))
    assert _queued(owner) == [new]  # the new time does, with the stagger set in the UI (0)


# --------------------------------------------------------------- gate check 8
def test_a_demo_connection_created_in_the_ui_backfills_onto_the_overview(
    signed_in: TestClient, worker: Engine, store: FilesystemRawStore
) -> None:
    _put_collection(signed_in, synthetic_throttle_share=0.0)
    created = signed_in.post(
        "/api/v1/connections",
        headers=csrf(signed_in),
        # Seed 3 is the prod profile: staging's Prowler fails on purpose every 47th day.
        json={"kind": "demo", "name": "demo-gate", "seed": 3, "backfill_days": 2},
    )
    assert created.status_code == 201, created.text
    cid = created.json()["id"]
    before = signed_in.get("/api/v1/overview", params={"connection_id": cid}).json()
    assert before["data_through"] is None

    statuses = []
    while (
        status := runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="gate")
    ) is not None:
        statuses.append(status)
    assert statuses == ["complete"] * (2 * len(TOOL_ORDER))

    today = datetime.now(UTC).date().isoformat()
    after = signed_in.get("/api/v1/overview", params={"connection_id": cid}).json()
    assert after["data_through"] == today
    assert after["kpis"]["assets"]["value"] > 0
    context = signed_in.get("/api/v1/context").json()
    assert "demo-gate" in {c["name"] for c in context["connections"]}
    assert signed_in.get("/api/v1/run-requests").json()["total"] == 0


def test_without_demo_connections_only_aws_is_offered(
    signed_in: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert signed_in.get("/api/v1/connections/kinds").json() == ["aws", "demo"]  # Compose
    # The chart's bound (ADR-0039): Kubernetes offers real connections only.
    monkeypatch.setenv("ARGUS_DEMO_CONNECTIONS", "false")
    get_settings.cache_clear()
    assert signed_in.get("/api/v1/connections/kinds").json() == ["aws"]
    refused = signed_in.post(
        "/api/v1/connections",
        headers=csrf(signed_in),
        json={"kind": "demo", "name": "demo-k8s", "seed": 1, "backfill_days": 1},
    )
    assert refused.status_code == 422
    assert "Docker Compose" in refused.json()["detail"]
    assert "demo-k8s" not in {c["name"] for c in signed_in.get("/api/v1/connections").json()}
    assert seed.main(["--days", "1"]) == 1  # the seed command refuses too


# --------------------------------------------------------------- gate check 9
def test_a_collection_setting_takes_effect_on_the_next_claim(
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = [make_demo(owner, seed).connection_id for seed in range(3)]
    queued = signed_in.post(
        "/api/v1/run-requests", headers=csrf(signed_in), json={"connection_ids": ids}
    )
    assert queued.status_code == 202, queued.text
    # Claim through the real loop, but leave each claim open instead of running it.
    monkeypatch.setattr(runner, "execute", lambda *_, **__: "claimed")

    def claim() -> str | None:
        return runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="gate")

    _put_collection(signed_in, max_parallel_runs=1)
    assert claim() == "claimed"
    assert claim() is None  # the cap of 1, set in the UI a moment ago, holds
    _put_collection(signed_in, max_parallel_runs=3)
    assert claim() == "claimed" and claim() == "claimed"
    assert claim() is None  # one claim per account: three accounts, three claims
    with owner.connect() as conn:
        claimed = conn.execute(
            text("SELECT count(*) FROM run_request WHERE status = 'claimed'")
        ).scalar_one()
    assert claimed == 3


# --------------------------------------------------------------- gate check 10
def test_an_access_key_identity_is_sealed_and_never_returned(signed_in: TestClient) -> None:
    # Access keys are the administrator's choice, with nothing set in the environment
    # (ADR-0024, amended 2026-10-24).
    body = {"mode": "access_key", "access_key_id": "AKIA" + "Y" * 16, "secret_access_key": SECRET}
    assert signed_in.get("/api/v1/settings").json()["identity"]["mode"] == "ambient"
    saved = signed_in.put("/api/v1/settings/identity", headers=csrf(signed_in), json=body)
    assert saved.status_code == 200 and saved.json()["identity"]["secret_set"] is True
    read = signed_in.get("/api/v1/settings")
    assert SECRET not in saved.text and SECRET not in read.text
    back = signed_in.put(
        "/api/v1/settings/identity", headers=csrf(signed_in), json={"mode": "ambient"}
    )
    assert back.status_code == 200 and back.json()["identity"]["secret_set"] is False


def test_a_temporary_identity_key_needs_its_session_token(
    signed_in: TestClient, owner: Engine
) -> None:
    token = "argus-test-only-not-a-real-session-token-" + "t" * 40
    body = {"mode": "access_key", "access_key_id": "ASIA" + "Y" * 16, "secret_access_key": SECRET}
    refused = signed_in.put("/api/v1/settings/identity", headers=csrf(signed_in), json=body)
    assert refused.status_code == 422 and "session_token" in refused.json()["detail"]
    two_lines = signed_in.put(
        "/api/v1/settings/identity",
        headers=csrf(signed_in),
        json={**body, "session_token": token + "\nregion = x"},
    )
    assert two_lines.status_code == 422 and token not in two_lines.text
    saved = signed_in.put(
        "/api/v1/settings/identity",
        headers=csrf(signed_in),
        json={**body, "session_token": token},
    )
    assert saved.status_code == 200 and saved.json()["identity"]["secret_set"] is True
    assert token not in saved.text and token not in signed_in.get("/api/v1/settings").text
    with owner.connect() as conn:
        blob = conn.execute(
            text("SELECT session_token_ciphertext FROM platform_setting WHERE topic = 'identity'")
        ).scalar_one()
        audit = json.dumps(
            [list(r) for r in conn.execute(text("SELECT * FROM audit_log"))], default=str
        )
    assert blob is not None and token.encode() not in bytes(blob) and token not in audit


# --------------------------------------------------------------- gate check 11
def test_no_planted_secret_reaches_any_api_response_or_log(
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    target = make_demo(owner)
    today = datetime.now(UTC).date()
    earlier = today - timedelta(days=1)
    for day in (earlier, today):
        for tool in TOOL_ORDER:
            run_tool(worker, store, target, tool, day)
    raw = "".join(p.read_text(errors="ignore") for p in store.root.rglob("*") if p.is_file())
    assert MARKERS.search(raw), "the synthetic estate no longer plants secrets: fix this test"

    bodies = {}
    for path in (
        "/api/v1/auth/session",
        "/api/v1/compliance",
        "/api/v1/compliance/cis_6.0_aws",
        "/api/v1/compliance/cis_6.0_aws/accounts",
        "/api/v1/compliance/cis_6.0_aws/requirements?limit=200",
        f"/api/v1/compliance/cis_6.0_aws/requirements?connection_id={target.connection_id}",
        "/api/v1/connections",
        "/api/v1/connections/kinds",
        "/api/v1/context",
        "/api/v1/findings?limit=200",
        "/api/v1/findings?limit=200&state=resolved",
        "/api/v1/findings/facets",
        "/api/v1/findings/summary",
        "/api/v1/findings/groups?limit=200",
        "/api/v1/findings/groups?limit=200&state=resolved",
        "/api/v1/resources/facets",
        "/api/v1/resources/summary",
        "/api/v1/overview",
        f"/api/v1/overview?as_of={earlier}",
        "/api/v1/run-requests",
        "/api/v1/runs?limit=200",
        "/api/v1/schedules",
        "/api/v1/settings",
        "/api/v1/settings/collection",
        "/api/v1/users",
        "/api/v1/vulnerabilities?limit=200&state=resolved",
        "/api/v1/vulnerabilities/facets",
        "/api/v1/vulnerabilities/groups?limit=200",
        "/api/v1/vulnerabilities/summary",
    ):
        response = signed_in.get(path)
        assert response.status_code == 200, (path, response.text)
        bodies[path] = response.text
    offset, total = 0, 1
    while offset < total:  # every resource, deleted ones too, today and as of the earlier day
        listing = f"/api/v1/resources?limit=200&include_deleted=true&offset={offset}"
        bodies[listing] = signed_in.get(listing).text
        page = json.loads(bodies[listing])
        for item in page["items"]:
            for day in (today, earlier):
                path = f"/api/v1/resources/{item['id']}?as_of={day}"
                bodies[path] = signed_in.get(path).text
        offset, total = offset + 200, page["total"]
    for listed in ("findings", "vulnerabilities"):  # every finding and CVE, each by its link too
        offset, total = 0, 1
        while offset < total:
            listing = f"/api/v1/{listed}?limit=200&state=open&offset={offset}"
            response = signed_in.get(listing)
            bodies[listing] = response.text
            page = response.json()
            for item in page["items"]:
                path = f"/api/v1/findings/{item['id']}"
                bodies[path] = signed_in.get(path).text
            offset, total = offset + 200, page["total"]

    tested = signed_in.post("/api/v1/settings/identity/test", headers=csrf(signed_in)).json()
    path = f"/api/v1/connection-tests/{tested['id']}"
    bodies[path] = signed_in.get(path).text

    # The sweep covers every GET route the contract has; a new route must join it.
    contract = json.loads(OPENAPI.read_text())["paths"]
    routes = {p for p, ops in contract.items() if "get" in ops} - {
        "/api/v1/health",
        "/api/v1/ready",
    }
    swept = {p.split("?")[0] for p in bodies}
    swept = {re.sub(r"/resources/\d+$", "/resources/{resource_id}", p) for p in swept}
    swept = {re.sub(r"/findings/\d+$", "/findings/{finding_id}", p) for p in swept}
    swept = {re.sub(r"/connection-tests/\d+$", "/connection-tests/{test_id}", p) for p in swept}
    swept = {re.sub(r"/compliance/cis_6\.0_aws", "/compliance/{framework}", p) for p in swept}
    assert routes == swept

    leaked = {path for path, body in bodies.items() if MARKERS.search(body)}
    assert leaked == set()
    logs = "\n".join(JsonFormatter().format(r) for r in caplog.records)  # with extra= fields
    assert logs and not MARKERS.search(logs)
