"""The scheduler's reconcile (ADR-0039, ADR-0046): it starts the Jobs that AWS scans and
connection tests need and no more, one template per work, within both bounds, with a test slot
beside the scans; each connection's next request decides which work it needs; a work with a
stuck Job starts no more; it submits each template byte for byte; with nothing to do it never
calls Kubernetes; Demo work starts nothing."""

import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_aws, make_demo

from argus.core.kube import JobState
from argus.scheduling.job import WORK
from argus.scheduling.launcher import (
    Bounds,
    TemplateError,
    Work,
    load_template,
    load_templates,
    plan,
    reconcile,
    selector,
)

BOUNDS = Bounds(max_run_jobs=4, max_test_jobs=1)
LABELS = {"app.kubernetes.io/instance": "argus", "app.kubernetes.io/component": "run"}


def _work(
    *next_work: str,
    claimed: dict[str, int] | None = None,
    queued_tests: int = 0,
    max_parallel_runs: int = 8,
) -> Work:
    return Work(tuple(next_work), claimed or {}, queued_tests, max_parallel_runs)


def _only(**started: int) -> dict[str, int]:
    return {**dict.fromkeys(WORK, 0), **started}


@pytest.mark.parametrize(
    ("work", "live", "stuck", "expected"),
    [
        (_work(), {}, (), _only()),
        (_work("steampipe", "prowler"), {}, (), _only(steampipe=1, prowler=1)),
        (_work(*["prowler"] * 6), {}, (), _only(prowler=4)),  # ARGUS_MAX_RUN_JOBS
        (_work(*["cloudfox"] * 6, max_parallel_runs=2), {}, (), _only(cloudfox=2)),  # the UI
        # Slots are filled in claim order, whatever the work.
        (
            _work("prowler", "steampipe", "cloudfox", "steampipe", "prowler"),
            {},
            (),
            _only(prowler=1, steampipe=2, cloudfox=1),
        ),
        # A Job that has not claimed yet takes the first request of its own work only.
        (_work("prowler"), {"prowler": 1}, (), _only()),
        (_work("prowler"), {"steampipe": 1}, (), _only(prowler=1)),
        (
            _work("steampipe", "steampipe", claimed={"steampipe": 1}),
            {"steampipe": 2},
            (),
            _only(steampipe=1),
        ),
        (
            _work(*["prowler"] * 5, claimed={"cloudfox": 3}),
            {"cloudfox": 3},
            (),
            _only(prowler=1),
        ),  # three running, one more within the bound
        # Tests have their own slot: one starts even with every scan slot taken.
        (_work(queued_tests=3), {}, (), _only(test=1)),
        (
            _work("prowler", claimed={"prowler": 4}, queued_tests=1),
            {"prowler": 4},
            (),
            _only(test=1),
        ),
        (_work(queued_tests=3), {"test": 1}, (), _only()),  # that Job answers one
        # The bound the UI lowered under the scans running: nothing more.
        (
            _work("steampipe", claimed={"prowler": 4}, max_parallel_runs=2),
            {"prowler": 4},
            (),
            _only(),
        ),
        # A claim whose pod died holds its slot until the reaper.
        (_work("steampipe", "cloudfox", claimed={"prowler": 4}), {"prowler": 3}, (), _only()),
        # A work whose Job is stuck starts no more of it; the others still start.
        (
            _work("prowler", "prowler", "steampipe"),
            {"prowler": 1},
            ("prowler",),
            _only(steampipe=1),
        ),
        (_work(queued_tests=1), {"test": 1}, ("test",), _only()),
    ],
    ids=[
        "nothing",
        "one-each",
        "run-bound",
        "ui-bound",
        "claim-order",
        "starting-job",
        "other-work-starting",
        "one-more-steampipe",
        "claimed-count",
        "tests",
        "test-slot-beside-full-scans",
        "test-running",
        "bound-lowered",
        "dead-claim",
        "stuck-work",
        "stuck-test",
    ],
)
def test_plan(
    work: Work, live: dict[str, int], stuck: tuple[str, ...], expected: dict[str, int]
) -> None:
    assert plan(work, live, BOUNDS, frozenset(stuck)) == expected


def _manifest(work: str) -> dict[str, object]:
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "generateName": f"argus-scan-{work}-",
            "labels": {**LABELS, "argus/work": work},
        },
        "spec": {"template": {"spec": {"containers": [{"name": "run"}]}}},
    }


def _write_templates(directory: Path) -> dict[str, bytes]:
    bodies = {}
    for work in WORK:
        bodies[work] = json.dumps(_manifest(work), indent=1).encode()
        (directory / f"{work}.json").write_bytes(bodies[work])
    return bodies


def test_the_templates_are_checked_and_give_the_selectors(tmp_path: Path) -> None:
    _write_templates(tmp_path)
    templates = load_templates(tmp_path)
    assert sorted(templates) == sorted(WORK)
    assert selector(templates["prowler"]) == (
        "app.kubernetes.io/component=run,app.kubernetes.io/instance=argus,argus/work=prowler"
    )


@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "Pod", "metadata": {"generateName": "x-", "labels": {"argus/work": "test"}}},
        {"kind": "Job", "metadata": {"name": "fixed", "labels": {"argus/work": "test"}}},
        {"kind": "Job", "metadata": {"generateName": "x-"}},
        {"kind": "Job", "metadata": {"generateName": "x-", "labels": {"argus/work": "prowler"}}},
    ],
    ids=["not-a-job", "fixed-name", "no-labels", "another-work"],
)
def test_an_unusable_template_stops_the_scheduler(tmp_path: Path, bad: dict[str, object]) -> None:
    (tmp_path / "test.json").write_text(json.dumps(bad))
    with pytest.raises(TemplateError):
        load_template(tmp_path, "test")


def test_a_missing_template_stops_the_scheduler(tmp_path: Path) -> None:
    _write_templates(tmp_path)
    (tmp_path / "cloudfox.json").unlink()
    with pytest.raises(TemplateError):
        load_templates(tmp_path)


class _Kube:
    """Jobs per work; a selector lists its work's Jobs only."""

    def __init__(self, jobs: dict[str, list[JobState]] | None = None) -> None:
        self.jobs = jobs or {}
        self.created: list[bytes] = []
        self.listed = 0

    def create_job(self, body: bytes) -> str:
        self.created.append(body)
        return f"job-{len(self.created)}"

    def list_jobs(self, selector: str) -> list[JobState]:
        self.listed += 1
        work = dict(part.split("=", 1) for part in selector.split(","))["argus/work"]
        return self.jobs.get(work, [])


def _queue(owner: Engine, connection_id: int, *tools: str) -> None:
    with owner.begin() as conn:
        for tool in tools:
            conn.execute(
                text(
                    "INSERT INTO run_request (connection_id, tool, reason, not_before, "
                    "requested_by) VALUES (:c, :t, 'manual', now() - interval '1 minute', "
                    "'admin')"
                ),
                {"c": connection_id, "t": tool},
            )


@pytest.mark.db
def test_reconcile_starts_jobs_byte_for_byte_and_is_quiet_when_idle(
    owner: Engine, scheduler: Engine, tmp_path: Path
) -> None:
    bodies = _write_templates(tmp_path)
    templates = load_templates(tmp_path)
    kube = _Kube()
    assert reconcile(scheduler, kube, templates, BOUNDS) == 0
    assert kube.listed == 0  # nothing to do: no Kubernetes call

    _queue(owner, make_demo(owner).connection_id, "steampipe")
    assert reconcile(scheduler, kube, templates, BOUNDS) == 0  # Demo work starts nothing
    assert kube.listed == 0

    # One connection, whose next request is Steampipe's: one Steampipe Job, not a Prowler one.
    _queue(owner, make_aws(owner), "prowler", "steampipe")
    assert reconcile(scheduler, kube, templates, BOUNDS) == 1
    assert kube.created == [bodies["steampipe"]]

    kube.jobs = {"steampipe": [JobState("job-1", finished=False)]}
    assert reconcile(scheduler, kube, templates, BOUNDS) == 0  # that Job will claim it
    kube.jobs = {"steampipe": [JobState("job-1", finished=True)]}
    assert reconcile(scheduler, kube, templates, BOUNDS) == 1


@pytest.mark.db
def test_a_queued_test_gets_a_test_job_beside_the_scans(
    owner: Engine, scheduler: Engine, tmp_path: Path
) -> None:
    bodies = _write_templates(tmp_path)
    templates = load_templates(tmp_path)
    _queue(owner, make_aws(owner), "cloudfox")
    with owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO connection_test (target, requested_by, requested_at) "
                "VALUES ('identity', 'admin', now())"
            )
        )
    kube = _Kube()
    assert reconcile(scheduler, kube, templates, Bounds(max_run_jobs=1, max_test_jobs=1)) == 2
    assert sorted(kube.created) == sorted([bodies["cloudfox"], bodies["test"]])


@pytest.mark.db
def test_a_job_with_no_running_pod_is_logged_once_and_stops_its_work(
    owner: Engine, scheduler: Engine, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bodies = _write_templates(tmp_path)
    templates = load_templates(tmp_path)
    _queue(owner, make_aws(owner, "a", "111111111111"), "prowler")
    _queue(owner, make_aws(owner, "b", "222222222222"), "prowler")
    _queue(owner, make_aws(owner, "c", "333333333333"), "steampipe")
    now = datetime(2026, 10, 24, 12, tzinfo=UTC)
    pulling = JobState("job-1", False, ready=0, started_at=now - timedelta(minutes=6))
    kube = _Kube({"prowler": [pulling]})
    warned: set[str] = set()
    with caplog.at_level(logging.WARNING, logger="argus.scheduler"):
        # The pulling Prowler Job takes one Prowler request; no second Prowler Job starts while
        # it is stuck, and Steampipe's still does.
        assert reconcile(scheduler, kube, templates, BOUNDS, warned=warned, now=now) == 1
        assert kube.created == [bodies["steampipe"]]
        reconcile(scheduler, kube, templates, BOUNDS, warned=warned, now=now)
    stuck = [r for r in caplog.records if r.getMessage() == "job not running"]
    assert [(r.job, r.work) for r in stuck] == [("job-1", "prowler")]  # type: ignore[attr-defined]
    kube.jobs = {}
    reconcile(scheduler, kube, templates, BOUNDS, warned=warned, now=now)
    assert warned == set()  # forgotten once the Job is gone


@pytest.mark.db
def test_a_failed_job_stops_its_work_until_it_is_deleted(
    owner: Engine, scheduler: Engine, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # A Prowler Job on an image without Prowler refuses its work and fails, leaving its request
    # queued: no other Prowler Job may start to fail the same way, every pass.
    bodies = _write_templates(tmp_path)
    templates = load_templates(tmp_path)
    _queue(owner, make_aws(owner, "a", "111111111111"), "prowler")
    _queue(owner, make_aws(owner, "b", "222222222222"), "steampipe")
    refused = JobState("job-1", finished=True, failed=True)
    kube = _Kube({"prowler": [refused]})
    warned: set[str] = set()
    with caplog.at_level(logging.WARNING, logger="argus.scheduler"):
        assert reconcile(scheduler, kube, templates, BOUNDS, warned=warned) == 1
        assert kube.created == [bodies["steampipe"]]
        kube.jobs["steampipe"] = [JobState("job-2", finished=False)]
        assert reconcile(scheduler, kube, templates, BOUNDS, warned=warned) == 0
    failed = [r for r in caplog.records if r.getMessage() == "job failed"]
    assert [(r.job, r.work) for r in failed] == [("job-1", "prowler")]  # type: ignore[attr-defined]
    kube.jobs = {}  # deleted after ttlSecondsAfterFinished: Prowler may start again
    assert reconcile(scheduler, kube, templates, BOUNDS, warned=warned) == 2
    assert warned == set()
