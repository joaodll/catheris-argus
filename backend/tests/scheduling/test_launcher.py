"""The scheduler's reconcile (ADR-0039): it starts the scan Jobs that AWS scans and connection
tests need and no more, within both bounds, with a test slot beside the scans; it submits the
template byte for byte; with nothing to do it never calls Kubernetes; Demo work starts nothing."""

import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_aws, make_demo

from argus.core.kube import JobState
from argus.scheduling.launcher import (
    Bounds,
    TemplateError,
    Work,
    load_template,
    plan,
    reconcile,
    selector,
)

BOUNDS = Bounds(max_run_jobs=4, max_test_jobs=1)
LABELS = {"app.kubernetes.io/instance": "argus", "app.kubernetes.io/component": "run"}


def _work(**kw: int) -> Work:
    base = {
        "claimable": 0,
        "claimed": 0,
        "queued_tests": 0,
        "max_parallel_runs": 8,
    }
    return Work(**{**base, **kw})


@pytest.mark.parametrize(
    ("work", "active", "expected"),
    [
        (_work(), 0, 0),
        (_work(claimable=2), 0, 2),
        (_work(claimable=6), 0, 4),  # ARGUS_MAX_RUN_JOBS
        (_work(claimable=6, max_parallel_runs=2), 0, 2),  # the UI setting
        # A Job that has not claimed yet counts against the claimable work it will take.
        (_work(claimable=1), 1, 0),
        (_work(claimable=2, claimed=1), 2, 1),
        (_work(claimable=5, claimed=3), 3, 1),  # three running, one more within the bound
        # Tests have their own slot: one starts even with every scan slot taken.
        (_work(queued_tests=3), 0, 1),
        (_work(claimable=6, claimed=4, queued_tests=1), 4, 1),
        (_work(queued_tests=3), 1, 0),  # that Job answers one; the next pass starts another
        # The bound the UI lowered under the scans running: nothing more.
        (_work(claimable=1, claimed=4, max_parallel_runs=2), 4, 0),
        # A claim whose pod died holds its slot until the reaper: no Job only to find the cap full.
        (_work(claimable=2, claimed=4), 3, 0),
        (_work(claimable=2, claimed=4, queued_tests=1), 3, 1),
    ],
    ids=[
        "nothing",
        "scans",
        "run-bound",
        "ui-bound",
        "starting-job",
        "one-more",
        "claimed-count",
        "tests",
        "test-slot-beside-full-scans",
        "test-running",
        "bound-lowered",
        "dead-claim",
        "dead-claim-test",
    ],
)
def test_plan(work: Work, active: int, expected: int) -> None:
    assert plan(work, active, BOUNDS) == expected


def _write_template(directory: Path, manifest: dict[str, object] | None = None) -> bytes:
    manifest = manifest or {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"generateName": "argus-scan-", "labels": LABELS},
        "spec": {"template": {"spec": {"containers": [{"name": "run"}]}}},
    }
    body = json.dumps(manifest, indent=1).encode()
    (directory / "scan.json").write_bytes(body)
    return body


def test_the_template_is_checked_and_gives_the_selector(tmp_path: Path) -> None:
    _write_template(tmp_path)
    template = load_template(tmp_path)
    assert selector(template) == "app.kubernetes.io/component=run,app.kubernetes.io/instance=argus"


@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "Pod", "metadata": {"generateName": "x-", "labels": LABELS}},
        {"kind": "Job", "metadata": {"name": "fixed", "labels": LABELS}},
        {"kind": "Job", "metadata": {"generateName": "x-"}},
    ],
    ids=["not-a-job", "fixed-name", "no-labels"],
)
def test_an_unusable_template_stops_the_scheduler(tmp_path: Path, bad: dict[str, object]) -> None:
    _write_template(tmp_path, bad)
    with pytest.raises(TemplateError):
        load_template(tmp_path)


def test_a_missing_template_stops_the_scheduler(tmp_path: Path) -> None:
    with pytest.raises(TemplateError):
        load_template(tmp_path)


class _Kube:
    def __init__(self, jobs: list[JobState] | None = None) -> None:
        self.jobs = jobs or []
        self.created: list[bytes] = []
        self.listed = 0

    def create_job(self, body: bytes) -> str:
        self.created.append(body)
        return f"job-{len(self.created)}"

    def list_jobs(self, selector: str) -> list[JobState]:
        self.listed += 1
        return self.jobs


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
    body = _write_template(tmp_path)
    template = load_template(tmp_path)
    kube = _Kube()
    assert reconcile(scheduler, kube, template, BOUNDS) == 0
    assert kube.listed == 0  # nothing to do: no Kubernetes call

    _queue(owner, make_demo(owner).connection_id, "steampipe")
    assert reconcile(scheduler, kube, template, BOUNDS) == 0  # Demo work starts nothing
    assert kube.listed == 0

    _queue(owner, make_aws(owner), "steampipe", "prowler")
    assert reconcile(scheduler, kube, template, BOUNDS) == 1  # one connection
    assert kube.created == [body]

    kube.jobs = [JobState("job-1", finished=False)]
    assert reconcile(scheduler, kube, template, BOUNDS) == 0  # that Job will claim it
    kube.jobs = [JobState("job-1", finished=True)]
    assert reconcile(scheduler, kube, template, BOUNDS) == 1


@pytest.mark.db
def test_a_queued_test_gets_a_job_beside_the_scans(
    owner: Engine, scheduler: Engine, tmp_path: Path
) -> None:
    _write_template(tmp_path)
    template = load_template(tmp_path)
    _queue(owner, make_aws(owner), "prowler")
    with owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO connection_test (target, requested_by, requested_at) "
                "VALUES ('identity', 'admin', now())"
            )
        )
    kube = _Kube()
    assert reconcile(scheduler, kube, template, Bounds(max_run_jobs=1, max_test_jobs=1)) == 2


@pytest.mark.db
def test_a_job_with_no_running_pod_is_logged_once(
    owner: Engine, scheduler: Engine, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _write_template(tmp_path)
    template = load_template(tmp_path)
    _queue(owner, make_aws(owner), "prowler")
    now = datetime(2026, 10, 24, 12, tzinfo=UTC)
    pulling = JobState("job-1", False, ready=0, started_at=now - timedelta(minutes=6))
    kube = _Kube([pulling, JobState("job-2", False, 1, now - timedelta(hours=1))])
    warned: set[str] = set()
    with caplog.at_level(logging.WARNING, logger="argus.scheduler"):
        reconcile(scheduler, kube, template, BOUNDS, warned=warned, now=now)
        reconcile(scheduler, kube, template, BOUNDS, warned=warned, now=now)
    stuck = [r for r in caplog.records if r.getMessage() == "job not running"]
    assert [r.job for r in stuck] == ["job-1"]  # type: ignore[attr-defined]  # once
    kube.jobs = []
    reconcile(scheduler, kube, template, BOUNDS, warned=warned, now=now)
    assert warned == set()  # forgotten once the Job is gone
