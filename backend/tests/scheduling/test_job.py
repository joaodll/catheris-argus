"""Kubernetes scan Jobs and the scheduler's role (ADR-0039, ADR-0046): a test Job answers a queued
connection test and never scans; a tool Job takes one AWS scan of its tools within the cap, only a
connection's next request, never Demo work and never a test; an unknown work or a missing tool
stops a Job before it claims; the scheduler's role can keep the queue but cannot read secrets or
scanned data."""

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError
from tests.ingest.conftest import make_aws, make_demo

from argus.collection import TOOL_ORDER
from argus.collection.aws.tools import TOOL_BINARIES
from argus.core.rawstore import FilesystemRawStore
from argus.scheduling import claims, connection_checks, maintenance
from argus.scheduling.job import WorkError, check_work, run_job, work_of
from argus.settings import CollectionSettings

pytestmark = pytest.mark.db
RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
CAP = CollectionSettings(max_parallel_runs=8)
NOW = datetime(2026, 10, 2, 2, 30, tzinfo=UTC)


def _queue(owner: Engine, connection_id: int, tool: str, day: date | None = None) -> int:
    reason = "backfill" if day else "manual"
    with owner.begin() as conn:
        return int(
            conn.execute(
                text("""
            INSERT INTO run_request (connection_id, tool, reason, snapshot_date, not_before,
                                     requested_by)
            VALUES (:c, :t, :r, :d, now() - interval '1 minute', 'admin') RETURNING id"""),
                {"c": connection_id, "t": tool, "r": reason, "d": day},
            ).scalar_one()
        )


def _status(owner: Engine, request_id: int) -> str:
    with owner.connect() as conn:
        return str(
            conn.execute(
                text("SELECT status FROM run_request WHERE id = :i"), {"i": request_id}
            ).scalar_one()
        )


def _job(worker: Engine, tmp_path: Path, work: str = "prowler", max_runs: int = 4) -> str:
    return run_job(
        worker,
        work=work,
        store=FilesystemRawStore(tmp_path),
        rules_dir=RULES_DIR,
        worker_id="pod-1",
        max_runs=max_runs,
        scratch=tmp_path / "scratch",
    )


def test_claimable_work_counts_connections_not_requests(owner: Engine, worker: Engine) -> None:
    demo = make_demo(owner)
    aws = make_aws(owner)
    for day in (date(2026, 9, 1), date(2026, 9, 2)):
        for tool in ("steampipe", "prowler", "cloudfox"):
            _queue(owner, demo.connection_id, tool, day)
    _queue(owner, aws, "prowler")
    with worker.begin() as conn:
        assert sorted((r.kind, r.tool) for r in claims.next_requests(conn)) == [
            ("aws", "prowler"),
            ("demo", "steampipe"),  # the oldest day's first tool
        ]
        assert claims.claimed_count(conn) == 0
        got = claims.claim(conn, worker_id="t", settings=CAP, kinds=("aws",))
        assert got is not None and got.connection_id == aws
        assert claims.claim(conn, worker_id="t", settings=CAP, kinds=("aws",)) is None
        # The aws connection is busy now: only the Demo one has claimable work.
        assert [r.kind for r in claims.next_requests(conn)] == ["demo"]
        assert claims.claimed_count(conn) == 1
        assert claims.claimed_tools(conn) == {("aws", "prowler"): 1}


def test_a_tool_job_takes_only_a_connections_next_request(owner: Engine, worker: Engine) -> None:
    first = make_aws(owner, "first", "111111111111")
    second = make_aws(owner, "second", "222222222222")
    steampipe = _queue(owner, first, "steampipe")
    cloudfox = _queue(owner, first, "cloudfox")
    _queue(owner, second, "vulnerabilities")
    later = _queue(owner, second, "prowler")
    with worker.begin() as conn:
        # The first connection's next request is Steampipe's: a CloudFox Job does not run ahead
        # of it, and the second connection's next is Prowler's.
        assert claims.claim(conn, worker_id="t", settings=CAP, tools=("cloudfox",)) is None
        got = claims.claim(conn, worker_id="t", settings=CAP, tools=("prowler",))
        assert got is not None and got.id == later
        got = claims.claim(
            conn, worker_id="t", settings=CAP, tools=("steampipe", "vulnerabilities")
        )
        assert got is not None and got.id == steampipe
    for request in (steampipe, later):
        with owner.begin() as conn:
            conn.execute(
                text("UPDATE run_request SET status = 'finished' WHERE id = :i"), {"i": request}
            )
    with worker.begin() as conn:
        got = claims.claim(conn, worker_id="t", settings=CAP, tools=("cloudfox",))
        assert got is not None and got.id == cloudfox  # now it is the first connection's next
        # Without tools, as the Compose worker claims: the next request, in claim order.
        got = claims.claim(conn, worker_id="t", settings=CAP)
        assert got is not None and got.tool == "vulnerabilities"


def test_a_test_job_answers_a_test_and_never_scans(
    owner: Engine, worker: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def caller_identity(_credentials: object) -> tuple[str, str]:
        return "210987654321", "arn:aws:sts::210987654321:assumed-role/Argus/argus-1"

    monkeypatch.setattr(connection_checks.aws, "caller_identity", caller_identity)
    scan = _queue(owner, make_aws(owner), "prowler")
    with owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO connection_test (target, requested_by, requested_at) "
                "VALUES ('identity', 'admin', now())"
            )
        )
    assert _job(worker, tmp_path, "prowler") == "scan"  # a tool Job never answers a test
    with owner.connect() as conn:
        assert conn.execute(text("SELECT status FROM connection_test")).scalar_one() == "queued"
    assert _job(worker, tmp_path, "test") == "test"
    with owner.connect() as conn:
        assert conn.execute(text("SELECT status FROM connection_test")).scalar_one() == "passed"
    other = _queue(owner, make_aws(owner, "other", "333333333333"), "prowler")
    assert _job(worker, tmp_path, "test") == "nothing"  # no test left, and it never scans
    assert _status(owner, other) == "queued"
    assert _status(owner, scan) != "queued"


@pytest.mark.parametrize(
    ("work", "match"),
    [("", "must be one of"), ("all", "must be one of"), ("prowler", "does not carry prowler")],
    ids=["missing", "unknown", "no-binary"],
)
def test_a_job_refuses_work_it_cannot_do(work: str, match: str) -> None:
    # The test image carries no tool: Prowler's work is refused before any claim.
    with pytest.raises(WorkError, match=match):
        check_work(work)


def test_the_test_work_needs_no_tool() -> None:
    check_work("test")


def test_a_scan_job_never_takes_demo_work_and_respects_the_cap(
    owner: Engine, worker: Engine, tmp_path: Path
) -> None:
    demo = _queue(owner, make_demo(owner).connection_id, "prowler")
    assert _job(worker, tmp_path) == "nothing"
    assert _status(owner, demo) == "queued"  # Demo connections are not scanned on Kubernetes

    running = _queue(owner, make_aws(owner, "running", "111111111111"), "prowler")
    waiting = _queue(owner, make_aws(owner, "waiting", "222222222222"), "prowler")
    with worker.begin() as conn:
        got = claims.claim(conn, worker_id="pod-0", settings=CAP, kinds=("aws",))
    assert got is not None and got.id == running
    # One scan runs: the deployment's cap of one leaves the other queued, whatever the UI allows.
    assert _job(worker, tmp_path, max_runs=1) == "nothing"
    assert _status(owner, waiting) == "queued"
    assert not any(tmp_path.rglob("*"))  # nothing written to the local volume


def test_the_scheduler_role_keeps_the_queue(owner: Engine, scheduler: Engine) -> None:
    demo = make_demo(owner)
    with owner.begin() as conn:
        sid = conn.execute(
            text(
                "INSERT INTO schedule (name, tools, cron, all_connections, updated_at, "
                "updated_by) VALUES ('nightly', ARRAY['steampipe'], '0 2 * * *', true, "
                ":u, 'admin') RETURNING id"
            ),
            {"u": NOW - timedelta(days=1)},
        ).scalar_one()
        conn.execute(
            text("""
            INSERT INTO run_request (connection_id, tool, reason, status, claimed_at,
                                     claimed_by, heartbeat_at, requested_by)
            VALUES (:c, 'prowler', 'manual', 'claimed', now() - interval '1 hour', 'gone:0',
                    now() - interval '1 hour', 'admin')"""),
            {"c": demo.connection_id},
        )
        conn.execute(
            text("""
            INSERT INTO connection_test (target, requested_by, requested_at)
            VALUES ('identity', 'admin', now() - interval '1 hour')""")
        )
    maintenance.maintain(scheduler, now=NOW)
    with scheduler.connect() as conn:
        assert [r.kind for r in claims.next_requests(conn)] == ["demo"]
        assert claims.claimed_count(conn) == 0  # the lost claim went back to the queue
    with owner.connect() as conn:
        tests = conn.execute(text("SELECT status FROM connection_test")).scalar_one()
        ticked = conn.execute(
            text("SELECT count(*) FROM run_request WHERE schedule_id = :s"), {"s": sid}
        ).scalar_one()
    assert tests == "failed"
    assert ticked == 1


@pytest.mark.parametrize(
    "query",
    [
        "SELECT secret_ciphertext FROM connection",
        "SELECT external_id FROM connection",
        "SELECT secret_ciphertext FROM platform_setting",
        "SELECT count(*) FROM scan_run",
        "SELECT count(*) FROM resource",
        "SELECT count(*) FROM audit_log",
    ],
    ids=["connection-secret", "external-id", "identity-secret", "runs", "resources", "audit"],
)
def test_the_scheduler_role_reads_no_secret_and_no_data(scheduler: Engine, query: str) -> None:
    with scheduler.connect() as conn, pytest.raises(ProgrammingError, match="permission denied"):
        conn.execute(text(query))


def test_every_tool_has_a_scan_job_and_an_image_binary() -> None:
    # A tool no Job runs would stop the scheduler on every pass (launcher.read_work).
    assert {work_of(tool) for tool in TOOL_ORDER} == {"steampipe", "prowler", "cloudfox"}
    assert set(TOOL_BINARIES) == set(TOOL_ORDER)
