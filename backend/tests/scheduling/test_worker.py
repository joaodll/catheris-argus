"""The worker's guarantees: schedules become requests once, claims respect the account and the
global cap, dead claims are released, failed runs retry, and the real execute path drains a
backfill into history. Runs as argus_worker, so the worker's grants are proven too."""

import base64
import re
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.exc import DataError
from tests.ingest.conftest import make_aws, make_demo

from argus.collection import source_for, store_for
from argus.collection.collect import Outcome
from argus.core.config import get_settings
from argus.core.db import CONNECT_ARGS
from argus.core.rawstore import FilesystemRawStore, S3RawStore
from argus.ingest import pipeline
from argus.scheduling import (
    check_cron,
    claims,
    maintenance,
    recently_completed,
    runner,
    schedules,
)
from argus.scheduling.schedules import InvalidScheduleError
from argus.settings import CollectionSettings, write_identity, write_topic

pytestmark = pytest.mark.db
RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
NOW = datetime(2026, 10, 2, 2, 30, tzinfo=UTC)
QUIET = CollectionSettings(synthetic_throttle_share=0.0)


def _schedule(
    owner: Engine,
    *,
    tools: tuple[str, ...] = ("prowler",),
    cron: str = "0 2 * * *",
    updated_at: datetime = NOW - timedelta(days=1),
    all_connections: bool = True,
) -> int:
    with owner.begin() as conn:
        return int(
            conn.execute(
                text(
                    "INSERT INTO schedule (name, tools, cron, all_connections, updated_at, "
                    "updated_by) VALUES (:n, :t, :c, :a, :u, 'admin') RETURNING id"
                ),
                {
                    "n": f"{'+'.join(tools)}-{cron}",
                    "t": list(tools),
                    "c": cron,
                    "a": all_connections,
                    "u": updated_at,
                },
            ).scalar_one()
        )


def _request(
    owner: Engine,
    connection_id: int,
    tool: str,
    *,
    reason: str = "manual",
    day: date | None = None,
    status: str = "queued",
    attempt: int = 1,
) -> int:
    # A scheduled request runs only while its (enabled) schedule exists.
    schedule_id = _schedule(owner, tools=(tool,)) if reason == "schedule" else None
    with owner.begin() as conn:
        return int(
            conn.execute(
                text("""
            INSERT INTO run_request (connection_id, tool, reason, schedule_id, snapshot_date,
                                     status, claimed_at, heartbeat_at, attempt, not_before,
                                     requested_by)
            VALUES (:c, :t, :r, :sid, :d, :s,
                    CASE WHEN :s = 'claimed' THEN now() END,
                    CASE WHEN :s = 'claimed' THEN now() END, :a, now() - interval '1 minute',
                    'admin')
            RETURNING id"""),
                {
                    "c": connection_id,
                    "t": tool,
                    "r": reason,
                    "sid": schedule_id,
                    "d": day,
                    "s": status,
                    "a": attempt,
                },
            ).scalar_one()
        )


def _claim(worker: Engine, settings: CollectionSettings = QUIET) -> claims.ClaimedRequest | None:
    with worker.begin() as conn:
        return claims.claim(conn, worker_id="test", settings=settings)


# --------------------------------------------------------------- cron
def test_cron_is_explained_and_too_frequent_schedules_are_refused() -> None:
    check = check_cron("0 2 * * *", min_interval_minutes=60, now=NOW)
    assert check.explanation and check.next_runs[0] == datetime(2026, 10, 3, 2, tzinfo=UTC)
    with pytest.raises(InvalidScheduleError, match="minimum interval"):
        check_cron("*/5 * * * *", min_interval_minutes=60, now=NOW)
    with pytest.raises(InvalidScheduleError, match="invalid"):
        check_cron("every day", min_interval_minutes=60, now=NOW)


# --------------------------------------------------------------- tick
def test_tick_queues_each_account_once_with_a_staggered_start(
    owner: Engine, worker: Engine
) -> None:
    a, b = make_demo(owner, 0), make_demo(owner, 1)
    _schedule(owner)
    with worker.begin() as conn:
        assert schedules.tick(conn, now=NOW, settings=QUIET) == 2
        assert schedules.tick(conn, now=NOW, settings=QUIET) == 0  # occurrence deduped
        rows = conn.execute(
            text("SELECT connection_id, not_before, occurrence_at, snapshot_date FROM run_request")
        ).all()
    assert {r.connection_id for r in rows} == {a.connection_id, b.connection_id}
    for r in rows:
        assert r.occurrence_at == datetime(2026, 10, 2, 2, tzinfo=UTC)
        assert timedelta(0) <= r.not_before - r.occurrence_at < timedelta(minutes=180)
        assert r.snapshot_date == date(2026, 10, 2)


def test_a_schedule_queues_each_of_its_tools_in_tool_order(owner: Engine, worker: Engine) -> None:
    make_demo(owner)
    _schedule(owner, tools=("cloudfox", "steampipe"))
    with worker.begin() as conn:
        assert schedules.tick(conn, now=NOW, settings=QUIET) == 2
        assert schedules.tick(conn, now=NOW, settings=QUIET) == 0  # each tool deduped
        tools = conn.execute(text("SELECT tool FROM run_request ORDER BY id")).scalars().all()
    assert tools == ["steampipe", "cloudfox"]


def test_an_edited_schedule_waits_for_its_next_occurrence(owner: Engine, worker: Engine) -> None:
    make_demo(owner)
    _schedule(owner, updated_at=NOW - timedelta(minutes=10))  # edited after 02:00
    with worker.begin() as conn:
        assert schedules.tick(conn, now=NOW, settings=QUIET) == 0


def test_a_schedule_limited_to_some_accounts(owner: Engine, worker: Engine) -> None:
    a, _ = make_demo(owner, 0), make_demo(owner, 1)
    sid = _schedule(owner, all_connections=False)
    with owner.begin() as conn:
        conn.execute(
            text("INSERT INTO schedule_connection VALUES (:s, :c)"),
            {"s": sid, "c": a.connection_id},
        )
    with worker.begin() as conn:
        assert schedules.tick(conn, now=NOW, settings=QUIET) == 1


# --------------------------------------------------------------- claims
def test_one_claim_per_account_and_the_global_cap(owner: Engine, worker: Engine) -> None:
    a, b, c = make_demo(owner, 0), make_demo(owner, 1), make_demo(owner, 2)
    for target in (a, b, c):
        _request(owner, target.connection_id, "steampipe")
        _request(owner, target.connection_id, "prowler")
    capped = CollectionSettings(max_parallel_runs=2)
    first, second = _claim(worker, capped), _claim(worker, capped)
    assert first and second and first.connection_id != second.connection_id
    assert _claim(worker, capped) is None  # the cap holds
    third = _claim(worker, CollectionSettings(max_parallel_runs=4))
    assert third and third.connection_id not in {first.connection_id, second.connection_id}
    assert _claim(worker, CollectionSettings(max_parallel_runs=4)) is None  # one per account


def test_claim_order_oldest_day_first_then_tool_order(owner: Engine, worker: Engine) -> None:
    target = make_demo(owner)
    day1, day2 = date(2026, 9, 1), date(2026, 9, 2)
    for day in (day2, day1):
        for tool in ("cloudfox", "prowler", "steampipe"):
            _request(owner, target.connection_id, tool, reason="backfill", day=day)
    order = []
    while (claimed := _claim(worker)) is not None:
        order.append((claimed.snapshot_date, claimed.tool))
        with worker.begin() as conn:
            assert claims.finish(conn, claimed, scan_run_id=None)
    assert order == [
        (day1, "steampipe"),
        (day1, "prowler"),
        (day1, "cloudfox"),
        (day2, "steampipe"),
        (day2, "prowler"),
        (day2, "cloudfox"),
    ]


def test_disabled_accounts_and_future_requests_are_not_claimed(
    owner: Engine, worker: Engine
) -> None:
    target = make_demo(owner)
    rid = _request(owner, target.connection_id, "steampipe")
    with owner.begin() as conn:
        conn.execute(text("UPDATE connection SET enabled = false"))
    assert _claim(worker) is None
    with owner.begin() as conn:
        conn.execute(text("UPDATE connection SET enabled = true"))
        conn.execute(
            text("UPDATE run_request SET not_before = now() + interval '1 hour' WHERE id = :i"),
            {"i": rid},
        )
    assert _claim(worker) is None


def test_a_dead_workers_claim_is_released(owner: Engine, worker: Engine) -> None:
    target = make_demo(owner)
    rid = _request(owner, target.connection_id, "prowler", status="claimed")
    with owner.begin() as conn:
        conn.execute(
            text(
                "UPDATE run_request SET heartbeat_at = now() - interval '11 minutes' WHERE id = :i"
            ),
            {"i": rid},
        )
    with worker.begin() as conn:
        assert claims.release_stale(conn, older_than=maintenance.STALE_AFTER) == 1
    claimed = _claim(worker)
    assert claimed is not None and claimed.id == rid


def test_a_released_claim_is_no_longer_its_old_workers(owner: Engine, worker: Engine) -> None:
    """Fencing (ADR-0039): once the reaper released a claim and another worker took it, the old
    worker can neither keep it alive nor finish it."""
    target = make_demo(owner)
    _request(owner, target.connection_id, "prowler")
    old = _claim(worker)
    assert old is not None
    with owner.begin() as conn:
        conn.execute(text("UPDATE run_request SET heartbeat_at = now() - interval '11 minutes'"))
    with worker.begin() as conn:
        assert claims.release_stale(conn, older_than=maintenance.STALE_AFTER) == 1
    new = _claim(worker)
    assert new is not None and new.id == old.id and new.token != old.token
    assert new.lost == 1  # the reaper counted the loss
    with worker.begin() as conn:
        assert not claims.heartbeat(conn, old)
        assert not claims.finish(conn, old, scan_run_id=None, error="late")
        assert claims.heartbeat(conn, new)
        assert claims.finish(conn, new, scan_run_id=None)


class _Delayed:
    """The synthetic source, after `before()` and a pause long enough for a few heartbeats."""

    def __init__(self, before: object = None) -> None:
        self.real = source_for("demo")
        self.name = self.real.name
        self.before = before

    def collect(self, **kwargs: object) -> Outcome:
        if callable(self.before):
            self.before()
        time.sleep(0.4)
        return self.real.collect(**kwargs)  # type: ignore[arg-type]


def test_a_run_whose_claim_was_lost_registers_nothing(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_demo(owner)
    rid = _request(owner, target.connection_id, "steampipe", day=date(2026, 10, 2))

    def steal() -> None:  # the reaper released the claim and another worker took it
        with owner.begin() as conn:
            conn.execute(text("UPDATE run_request SET claimed_by = 'other:000000000000'"))

    monkeypatch.setattr(runner, "HEARTBEAT_EVERY", timedelta(milliseconds=50))
    monkeypatch.setattr(runner, "source_for", lambda kind: _Delayed(steal))
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "lost"
    with owner.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM scan_run")).scalar_one() == 0
        row = conn.execute(
            text("SELECT status, claimed_by FROM run_request WHERE id = :i"), {"i": rid}
        ).one()
    assert (row.status, row.claimed_by) == ("claimed", "other:000000000000")  # left to its owner


def test_one_heartbeat_error_does_not_stop_the_heartbeats(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_demo(owner)
    _request(owner, target.connection_id, "steampipe", day=date(2026, 10, 2))
    calls: list[bool] = []
    real_heartbeat = claims.heartbeat

    def flaky(conn: object, request: claims.ClaimedRequest) -> bool:
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("database restarting")
        return real_heartbeat(conn, request)  # type: ignore[arg-type]

    monkeypatch.setattr(runner, "HEARTBEAT_EVERY", timedelta(milliseconds=50))
    monkeypatch.setattr(runner.claims, "heartbeat", flaky)
    monkeypatch.setattr(runner, "source_for", lambda kind: _Delayed())
    status = runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t")
    assert status in {"complete", "partial"}
    assert len(calls) >= 3  # it kept beating after the error


def test_a_run_lost_twice_ends_as_a_failed_run_and_is_not_retried(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    rid = _request(owner, target.connection_id, "prowler", reason="schedule", day=date(2026, 10, 2))
    with owner.begin() as conn:
        conn.execute(text("UPDATE run_request SET lost = :n"), {"n": claims.MAX_LOST})
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    with owner.connect() as conn:
        row = conn.execute(
            text("SELECT status, scan_run_id FROM run_request WHERE id = :i"), {"i": rid}
        ).one()
        run = conn.execute(text("SELECT status, log_tail FROM scan_run")).one()
        retries = conn.execute(
            text("SELECT count(*) FROM run_request WHERE retry_of = :i"), {"i": rid}
        ).scalar_one()
    assert row.status == "finished" and row.scan_run_id is not None
    assert run.status == "failed" and "lost 2 times while running" in run.log_tail
    assert retries == 0


# --------------------------------------------------------------- execution
class _Broken:
    name = "synthetic"

    def collect(self, **_: object) -> None:
        raise RuntimeError("tool crashed")


def test_a_partial_run_is_not_retried(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """A partial run is usually partial because the scanner role denies actions by design; a
    retry would end partial again (argus_v8, 2026-10-08)."""
    target = make_demo(owner)
    with owner.begin() as conn:
        write_topic(
            conn, topic="collection", values={"synthetic_throttle_share": 1.0}, actor="test"
        )
    _request(owner, target.connection_id, "steampipe", reason="schedule", day=date(2026, 10, 2))
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "partial"
    with owner.connect() as conn:
        queued = conn.execute(
            text("SELECT count(*) FROM run_request WHERE status = 'queued'")
        ).scalar_one()
    assert queued == 0


def test_a_failed_scheduled_run_is_retried_and_a_backfill_is_not(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_demo(owner)
    monkeypatch.setattr(runner, "source_for", lambda kind: _Broken())
    _request(owner, target.connection_id, "steampipe", reason="schedule", day=date(2026, 10, 2))
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    with owner.connect() as conn:
        retry = conn.execute(
            text(
                "SELECT attempt, reason, not_before - now() AS wait FROM run_request "
                "WHERE status = 'queued'"
            )
        ).one()
    assert retry.attempt == 2 and retry.reason == "retry"
    assert timedelta(minutes=29) < retry.wait < timedelta(minutes=37)

    _request(owner, target.connection_id, "prowler", reason="backfill", day=date(2026, 10, 1))
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    with owner.connect() as conn:
        queued = conn.execute(
            text("SELECT count(*) FROM run_request WHERE status = 'queued'")
        ).scalar_one()
    assert queued == 1  # only the earlier retry; the backfill was not retried


def test_the_worker_drains_a_backfill_into_history(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    with owner.begin() as conn:
        write_topic(
            conn, topic="collection", values={"synthetic_throttle_share": 0.0}, actor="test"
        )
    for day in (date(2026, 9, 30), date(2026, 10, 1)):
        for tool in ("steampipe", "prowler", "cloudfox"):
            _request(owner, target.connection_id, tool, reason="backfill", day=day)
    statuses = []
    while (
        status := runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t")
    ) is not None:
        statuses.append(status)
    assert statuses == ["complete"] * 6
    with owner.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM run_request WHERE status <> 'finished'")
            ).scalar_one()
            == 0
        )
        assert (
            conn.execute(
                text(
                    "SELECT count(DISTINCT snapshot_date) FROM metric_daily "
                    "WHERE metric = 'assets.total'"
                )
            ).scalar_one()
            == 2
        )
        assert (
            conn.execute(text("SELECT count(*) FROM attack_path WHERE state = 'open'")).scalar_one()
            > 0
        )


def test_a_failing_source_still_finishes_the_request(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_demo(owner)

    monkeypatch.setattr(runner, "source_for", lambda kind: _Broken())
    rid = _request(
        owner, target.connection_id, "cloudfox", reason="schedule", day=date(2026, 10, 2)
    )
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    with owner.connect() as conn:
        row = conn.execute(
            text("SELECT status, scan_run_id FROM run_request WHERE id = :i"), {"i": rid}
        ).one()
        log_tail = conn.execute(text("SELECT log_tail FROM scan_run")).scalar_one()
    assert row.status == "finished" and row.scan_run_id is not None
    assert "tool crashed" in log_tail


def test_a_failing_ingest_marks_the_run_failed_and_retries(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_demo(owner)

    def broken(*_: object, **__: object) -> None:
        raise RuntimeError("adapter blew up")

    monkeypatch.setattr(pipeline, "load_prowler", broken)
    rid = _request(owner, target.connection_id, "prowler", reason="schedule", day=date(2026, 10, 2))
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    with owner.connect() as conn:
        run = conn.execute(text("SELECT status, ingested_at, log_tail FROM scan_run")).one()
        request = conn.execute(
            text("SELECT error FROM run_request WHERE id = :i"), {"i": rid}
        ).scalar_one()
        retries = conn.execute(
            text("SELECT count(*) FROM run_request WHERE retry_of = :i"), {"i": rid}
        ).scalar_one()
    assert run.status == "failed" and run.ingested_at is not None
    assert "RuntimeError: adapter blew up" in run.log_tail
    assert "adapter blew up" in request
    assert retries == 1


def test_an_aws_run_never_writes_to_the_local_volume(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    rid = _request(owner, make_aws(owner), "prowler", reason="manual", day=date(2026, 10, 2))
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    with owner.connect() as conn:
        error = conn.execute(
            text("SELECT error FROM run_request WHERE id = :i"), {"i": rid}
        ).scalar_one()
        run = conn.execute(text("SELECT status, raw_path, log_tail FROM scan_run")).one()
    assert "Raw output storage" in error
    # Shown in Runs with the reason, and nothing was archived.
    assert run.status == "failed" and run.raw_path == ""
    assert "Raw output storage" in run.log_tail
    assert not any(store.root.rglob("*"))


def test_a_run_that_cannot_be_registered_still_shows_as_failed(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_demo(owner)

    def refuse(*_: object, **__: object) -> int:
        raise RuntimeError("the database refused the manifest")

    monkeypatch.setattr(runner, "register_run", refuse)
    rid = _request(owner, target.connection_id, "prowler", reason="schedule", day=date(2026, 10, 2))
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    with owner.connect() as conn:
        run = conn.execute(
            text("SELECT id, status, tool, raw_path, ingested_at, log_tail FROM scan_run")
        ).one()
        request = conn.execute(
            text("SELECT status, scan_run_id, error FROM run_request WHERE id = :i"), {"i": rid}
        ).one()
        retries = conn.execute(
            text("SELECT count(*) FROM run_request WHERE retry_of = :i"), {"i": rid}
        ).scalar_one()
    assert run.status == "failed" and run.tool == "prowler"
    assert run.ingested_at is not None  # through ingest's failure path: metrics carried forward
    assert "the database refused the manifest" in run.log_tail
    # The archived output is linked: collection finished before the failure.
    assert re.fullmatch(r"raw/prowler/aws/[0-9]{12}/2026/10/02/[0-9a-f-]{36}", run.raw_path)
    assert request.status == "finished" and request.scan_run_id == run.id
    assert "the database refused the manifest" in request.error
    assert retries == 1


def test_a_log_tail_with_control_characters_is_recorded(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_demo(owner)

    class Noisy:
        name = "synthetic"

        def collect(self, **_: object) -> Outcome:
            now = datetime.now(UTC)
            return Outcome(
                status="failed",
                exit_code=1,
                tool_version="unknown",
                started_at=now,
                finished_at=now,
                region_scope=[],
                log_lines=["\x1b[31mprogress\x1b[0m\x00 done"],
            )

    monkeypatch.setattr(runner, "source_for", lambda kind: Noisy())
    _request(owner, target.connection_id, "cloudfox", reason="schedule", day=date(2026, 10, 2))
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    with owner.connect() as conn:
        log_tail = conn.execute(text("SELECT log_tail FROM scan_run")).scalar_one()
    assert log_tail.startswith("progress done")


def test_a_database_error_is_reduced_to_the_driver_message() -> None:
    error = DataError("INSERT INTO scan_run ...", {"log": "x" * 5000}, ValueError("NUL"))
    assert runner.describe_error(error) == "ValueError: NUL"


def test_a_refused_role_shows_as_a_failed_run_with_the_reason(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(**_: object) -> None:
        raise RuntimeError("AccessDenied: not authorized to perform sts:AssumeRole")

    monkeypatch.setattr("argus.collection.aws.access.aws.assume_role", refuse)
    # The bucket is replaced by the local store: this test is about the run, not S3.
    monkeypatch.setattr(runner, "store_for", lambda conn, kind, local: local)
    rid = _request(owner, make_aws(owner), "prowler", reason="manual", day=date(2026, 10, 2))
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    with owner.connect() as conn:
        run = conn.execute(text("SELECT status, source, log_tail FROM scan_run")).one()
        retried = conn.execute(
            text("SELECT count(*) FROM run_request WHERE retry_of = :i"), {"i": rid}
        ).scalar_one()
    assert run.status == "failed" and run.source == "aws"
    assert "not authorized to perform sts:AssumeRole" in run.log_tail
    assert retried == 1  # like any failed run that is not a backfill


@pytest.mark.parametrize(
    ("key_id", "token"),
    [("AKIA" + "T" * 16, None), ("ASIA" + "T" * 16, "test-only-session-" + "t" * 40)],
    ids=["long-lived-key", "temporary-key"],
)
def test_an_aws_run_writes_to_the_bucket_with_the_platform_identity(
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    monkeypatch: pytest.MonkeyPatch,
    key_id: str,
    token: str | None,
) -> None:
    monkeypatch.setenv("ARGUS_SECRET_KEYS", "k1:" + base64.b64encode(b"k" * 32).decode())
    monkeypatch.setenv("ARGUS_SECRET_KEY_ID", "k1")
    get_settings.cache_clear()
    with owner.begin() as conn:
        write_topic(
            conn,
            topic="raw_storage",
            values={"bucket": "argus-raw-example", "region": "eu-west-1"},
            actor="admin",
        )
        write_identity(
            conn,
            mode="access_key",
            access_key_id=key_id,
            secret_access_key="test-only-" + "s" * 30,
            session_token=token,
            actor="admin",
        )
    with worker.connect() as conn:
        chosen = store_for(conn, "aws", local=store)
    get_settings.cache_clear()
    assert isinstance(chosen, S3RawStore)
    assert chosen.client.meta.region_name == "eu-west-1"  # type: ignore[attr-defined]
    credentials = chosen.client._request_signer._credentials  # type: ignore[attr-defined]
    assert credentials.access_key == key_id
    assert credentials.token == token
    assert chosen.path_for("cloudfox", "210987654321", date(2026, 10, 2), UUID(int=1)) == (
        "s3://argus-raw-example/raw/cloudfox/aws/210987654321/2026/10/02/"
        "00000000-0000-0000-0000-000000000001"
    )


def test_maintenance_ticks_and_runs_retention_once_a_day(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    make_demo(owner)
    _schedule(owner)
    maintenance.maintain(worker, now=NOW)
    done = maintenance.daily_retention(worker, store=store, today=NOW.date(), done_on=None)
    assert done == NOW.date()
    assert maintenance.daily_retention(worker, store=store, today=NOW.date(), done_on=done) == done
    with owner.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM run_request")).scalar_one() == 1


def test_run_now_cooldown(owner: Engine, worker: Engine) -> None:
    target = make_demo(owner)
    _request(owner, target.connection_id, "prowler")
    with worker.begin() as conn:
        assert recently_completed(
            conn, connection_id=target.connection_id, tool="prowler", cooldown_minutes=60
        )  # still queued
    claimed = _claim(worker)
    assert claimed is not None
    with worker.begin() as conn:
        assert claims.finish(conn, claimed, scan_run_id=None)
        assert recently_completed(
            conn, connection_id=target.connection_id, tool="prowler", cooldown_minutes=60
        )  # finished just now
        assert not recently_completed(
            conn, connection_id=target.connection_id, tool="steampipe", cooldown_minutes=60
        )


def test_a_run_holds_at_most_run_connections_at_once(
    owner: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RUN_CONNECTIONS is what the scan Job's and the worker's pools are sized by: measure the
    real peak on an uncapped pool, with the heartbeat beating through collect and ingest."""
    engine = create_engine(get_settings().database_url(), connect_args=CONNECT_ARGS, pool_size=20)
    held = {"now": 0, "peak": 0}

    @event.listens_for(engine, "connect")
    def _as_worker(dbapi_conn, _record):  # type: ignore[no-untyped-def]
        with dbapi_conn.cursor() as cur:
            cur.execute("SET ROLE argus_worker")

    @event.listens_for(engine, "checkout")
    def _out(*_args):  # type: ignore[no-untyped-def]
        held["now"] += 1
        held["peak"] = max(held["peak"], held["now"])

    @event.listens_for(engine, "checkin")
    def _in(*_args):  # type: ignore[no-untyped-def]
        held["now"] -= 1

    target = make_demo(owner)
    with owner.begin() as conn:
        write_topic(
            conn, topic="collection", values={"synthetic_throttle_share": 0.0}, actor="test"
        )
    for tool in ("steampipe", "prowler", "cloudfox"):
        _request(owner, target.connection_id, tool, reason="backfill", day=date(2026, 10, 1))
    monkeypatch.setattr(runner, "HEARTBEAT_EVERY", timedelta(milliseconds=5))
    try:
        statuses = []
        while (
            status := runner.run_once(engine, store=store, rules_dir=RULES_DIR, worker_id="t")
        ) is not None:
            statuses.append(status)
    finally:
        engine.dispose()
    assert statuses == ["complete"] * 3
    assert 2 <= held["peak"] <= runner.RUN_CONNECTIONS


def test_backfill_does_not_trigger_the_run_now_cooldown(owner: Engine, worker: Engine) -> None:
    target = make_demo(owner)
    _request(owner, target.connection_id, "prowler", reason="backfill", day=date(2026, 9, 1))
    claimed = _claim(worker)
    assert claimed is not None
    with worker.begin() as conn:
        assert claims.finish(conn, claimed, scan_run_id=None)
        assert not recently_completed(
            conn, connection_id=target.connection_id, tool="prowler", cooldown_minutes=60
        )
