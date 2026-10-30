"""The run queue does what the administrator last said (argus_v7, 2026-10-07).

- A disabled, narrowed or deleted schedule leaves nothing queued behind it, and its retries stop.
- A queued request can be cancelled from the UI, which frees Run now for that tool and account.
- Every run says what started it and what it ran.

The API runs as argus_api and the worker as argus_worker, so both roles' grants are proven."""

from datetime import UTC, date, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.api.conftest import csrf
from tests.ingest.conftest import RULES_DIR, make_demo

from argus.core.rawstore import FilesystemRawStore
from argus.scheduling import claims, maintenance, runner
from argus.settings import CollectionSettings, write_topic

pytestmark = pytest.mark.db
QUIET = CollectionSettings(synthetic_throttle_share=0.0)


class _Broken:
    name = "synthetic"

    def collect(self, **_: object) -> None:
        raise RuntimeError("tool crashed")


def _schedule(client: TestClient, *, tools: list[str], at: datetime) -> dict[str, object]:
    response = client.post(
        "/api/v1/schedules",
        headers=csrf(client),
        json={"name": "nightly", "tools": tools, "cron": f"0 {at.hour} * * *"},
    )
    assert response.status_code == 201, response.text
    body: dict[str, object] = response.json()
    return body


def _tick(worker: Engine, store: FilesystemRawStore, now: datetime) -> None:
    maintenance.maintain(worker, now=now)


def _statuses(owner: Engine) -> dict[str, str]:
    with owner.connect() as conn:
        rows = conn.execute(text("SELECT tool, status FROM run_request ORDER BY id")).all()
    return {r.tool: r.status for r in rows}


def _next_hour() -> datetime:
    return (datetime.now(UTC) + timedelta(hours=2)).replace(minute=0, second=0, microsecond=0)


def test_disabling_a_schedule_cancels_what_it_queued(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    make_demo(owner)
    at = _next_hour()
    created = _schedule(signed_in, tools=["steampipe", "prowler"], at=at)
    _tick(worker, store, at + timedelta(minutes=1))
    assert _statuses(owner) == {"steampipe": "queued", "prowler": "queued"}

    # Taking a tool out cancels only that tool's queued run.
    narrowed = signed_in.put(
        f"/api/v1/schedules/{created['id']}",
        headers=csrf(signed_in),
        json={"name": "nightly", "tools": ["steampipe"], "cron": created["cron"]},
    )
    assert narrowed.status_code == 200, narrowed.text
    assert _statuses(owner) == {"steampipe": "queued", "prowler": "cancelled"}

    disabled = signed_in.put(
        f"/api/v1/schedules/{created['id']}",
        headers=csrf(signed_in),
        json={
            "name": "nightly",
            "tools": ["steampipe"],
            "cron": created["cron"],
            "enabled": False,
        },
    )
    assert disabled.status_code == 200, disabled.text
    assert _statuses(owner) == {"steampipe": "cancelled", "prowler": "cancelled"}
    assert signed_in.get("/api/v1/run-requests").json()["total"] == 0
    with owner.connect() as conn:
        detail = conn.execute(
            text(
                "SELECT detail FROM audit_log WHERE action = 'schedule.update' "
                "ORDER BY id DESC LIMIT 1"
            )
        ).scalar_one()
    assert len(detail["cancelled"]) == 1


def test_deleting_a_schedule_cancels_what_it_queued(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    make_demo(owner)
    at = _next_hour()
    created = _schedule(signed_in, tools=["prowler"], at=at)
    _tick(worker, store, at + timedelta(minutes=1))
    deleted = signed_in.delete(f"/api/v1/schedules/{created['id']}", headers=csrf(signed_in))
    assert deleted.status_code == 204, deleted.text
    assert _statuses(owner) == {"prowler": "cancelled"}
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") is None


def test_a_cancelled_retry_frees_run_now(
    signed_in: TestClient, owner: Engine, worker: Engine
) -> None:
    target = make_demo(owner)
    with owner.begin() as conn:
        waiting = conn.execute(
            text(
                "INSERT INTO run_request (connection_id, tool, reason, attempt, not_before, "
                "requested_by) VALUES (:c, 'prowler', 'retry', 3, now() + interval '2 hours', "
                "'admin') RETURNING id"
            ),
            {"c": target.connection_id},
        ).scalar_one()
    body = {"connection_ids": [target.connection_id], "tools": ["prowler"]}
    refused = signed_in.post("/api/v1/run-requests", headers=csrf(signed_in), json=body)
    assert refused.status_code == 409  # the waiting retry blocks it, as before

    assert signed_in.post(f"/api/v1/run-requests/{waiting}/cancel").status_code == 403  # CSRF
    cancelled = signed_in.post(f"/api/v1/run-requests/{waiting}/cancel", headers=csrf(signed_in))
    assert cancelled.status_code == 204, cancelled.text
    again = signed_in.post(f"/api/v1/run-requests/{waiting}/cancel", headers=csrf(signed_in))
    assert again.status_code == 404  # only a queued request can be cancelled

    queued = signed_in.post("/api/v1/run-requests", headers=csrf(signed_in), json=body)
    assert queued.status_code == 202, queued.text
    with owner.connect() as conn:
        audit = conn.execute(
            text("SELECT actor, target_id FROM audit_log WHERE action = 'run.cancel'")
        ).one()
    assert audit.actor == "admin" and audit.target_id == str(waiting)


def test_a_running_request_cannot_be_cancelled(
    signed_in: TestClient, owner: Engine, worker: Engine
) -> None:
    target = make_demo(owner)
    with owner.begin() as conn:
        running = conn.execute(
            text(
                "INSERT INTO run_request (connection_id, tool, reason, status, claimed_at, "
                "heartbeat_at, requested_by) VALUES (:c, 'prowler', 'manual', 'claimed', now(), "
                "now(), 'admin') RETURNING id"
            ),
            {"c": target.connection_id},
        ).scalar_one()
    response = signed_in.post(f"/api/v1/run-requests/{running}/cancel", headers=csrf(signed_in))
    assert response.status_code == 404
    assert _statuses(owner) == {"prowler": "claimed"}


def test_a_scheduled_run_is_not_retried_once_its_schedule_is_disabled(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_demo(owner)
    monkeypatch.setattr(runner, "source_for", lambda kind: _Broken())
    with owner.begin() as conn:
        schedule_id = conn.execute(
            text(
                "INSERT INTO schedule (name, tools, cron, all_connections, updated_by) "
                "VALUES ('n', '{steampipe,prowler}', '0 2 * * *', true, 'admin') RETURNING id"
            )
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO run_request (connection_id, tool, reason, schedule_id, "
                "snapshot_date, not_before, requested_by) "
                "VALUES (:c, 'steampipe', 'schedule', :s, :d, now() - interval '1 minute', "
                "'scheduler')"
            ),
            {"c": target.connection_id, "s": schedule_id, "d": date(2026, 10, 2)},
        )
    with worker.begin() as conn:
        claimed = claims.claim(conn, worker_id="t", settings=QUIET)
    assert claimed is not None and claimed.schedule_id == schedule_id
    with owner.begin() as conn:
        conn.execute(text("UPDATE schedule SET enabled = false WHERE id = :s"), {"s": schedule_id})
    status = runner.execute(
        worker, store=store, rules_dir=RULES_DIR, request=claimed, today=date(2026, 10, 2)
    )
    assert status == "failed"  # it would have been retried
    assert _statuses(owner) == {"steampipe": "finished"}  # and is not


def test_a_retry_keeps_its_schedule_and_who_asked(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_demo(owner)
    monkeypatch.setattr(runner, "source_for", lambda kind: _Broken())
    with owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO run_request (connection_id, tool, reason, snapshot_date, not_before, "
                "requested_by) VALUES (:c, 'steampipe', 'manual', :d, "
                "now() - interval '1 minute', 'admin')"
            ),
            {"c": target.connection_id, "d": date(2026, 10, 2)},
        )
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    with owner.connect() as conn:
        retry = conn.execute(
            text("SELECT reason, requested_by, attempt FROM run_request WHERE status = 'queued'")
        ).one()
    assert (retry.reason, retry.requested_by, retry.attempt) == ("retry", "admin", 2)


def test_the_worker_cancels_a_request_queued_for_a_disabled_schedule(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """A tick that read the schedule just before it was disabled can still insert a request."""
    target = make_demo(owner)
    with owner.begin() as conn:
        schedule_id = conn.execute(
            text(
                "INSERT INTO schedule (name, tools, cron, all_connections, enabled, updated_by) "
                "VALUES ('n', '{prowler}', '0 2 * * *', true, false, 'admin') RETURNING id"
            )
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO run_request (connection_id, tool, reason, schedule_id, not_before, "
                "requested_by) VALUES (:c, 'prowler', 'schedule', :s, "
                "now() - interval '1 minute', 'scheduler')"
            ),
            {"c": target.connection_id, "s": schedule_id},
        )
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") is None
    _tick(worker, store, datetime.now(UTC))
    assert _statuses(owner) == {"prowler": "cancelled"}


def test_each_run_says_what_started_it_and_what_it_ran(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    with owner.begin() as conn:
        write_topic(
            conn, topic="collection", values={"synthetic_throttle_share": 0.0}, actor="test"
        )
    queued = signed_in.post(
        "/api/v1/run-requests",
        headers=csrf(signed_in),
        json={"connection_ids": [target.connection_id], "tools": ["prowler"]},
    )
    assert queued.status_code == 202, queued.text
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "complete"
    run = signed_in.get("/api/v1/runs").json()["items"][0]
    assert run["trigger"] == {
        "reason": "manual",
        "origin": "manual",
        "schedule": None,
        "requested_by": "admin",
        "attempt": 1,
    }
    assert run["command"] == ""  # the synthetic source runs no tool
