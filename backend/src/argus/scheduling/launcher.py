"""The scheduler's reconcile (ADR-0039): count the work that could start, count the scan Jobs
alive, and start the missing Jobs from the chart's single fixed template.

- The template is submitted byte for byte: the scheduler fills in nothing, so the admission
  policy that pins it (ADR-0040) sees exactly what the chart rendered. Kubernetes names each Job
  from its generateName.
- Each scan Job does one unit of work: a connection test first, else one AWS scan
  (scheduling/job.py). Demo connections are not scanned on Kubernetes.
- Scans are counted in connections, not requests: one request per connection runs at a time.
- The Jobs wanted are the scans (claimed plus claimable connections, up to the smaller of the
  administration setting "max parallel runs" and ARGUS_MAX_RUN_JOBS) plus the queued tests (up
  to ARGUS_MAX_TEST_JOBS), so a test never waits behind a long scan. What counts against them is
  the larger of the live Jobs (claimed yet or not) and the claimed scans: a claim whose pod died
  holds its slot until the reaper requeues it, so no Job is started only to find the cap full.
  A Job started for a test that another Job answered takes a scan within the cap, or exits.
- With nothing to start, the Kubernetes API is not called at all.
- Every Job started is logged with its name and the work it was for (review S5).
- A Job with no running pod after STUCK_AFTER (an image it cannot pull, no node for it) is
  logged once: it still counts as in flight until its deadline, and the scheduler cannot
  delete Jobs (ADR-0040), so the log is where an operator learns why the queue waits.
"""

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from sqlalchemy import Engine

from argus.connections import checks
from argus.core.kube import JobState
from argus.scheduling import claims
from argus.settings import read_collection

log = logging.getLogger("argus.scheduler")
TEMPLATE = "scan.json"
STUCK_AFTER = timedelta(minutes=5)


class TemplateError(ValueError):
    """The Job template the chart mounted is unusable: the scheduler refuses to start."""


@dataclass(frozen=True)
class Template:
    body: bytes
    labels: dict[str, str]


@dataclass(frozen=True)
class Bounds:
    max_run_jobs: int
    max_test_jobs: int


@dataclass(frozen=True)
class Work:
    claimable: int  # AWS connections with claimable work
    claimed: int  # AWS requests claimed now
    queued_tests: int
    max_parallel_runs: int


class Kube(Protocol):
    def create_job(self, body: bytes) -> str: ...
    def list_jobs(self, selector: str) -> list[JobState]: ...


def load_template(directory: Path) -> Template:
    """`scan.json`: a Job with a generateName, no name, and labels to find its Jobs by."""
    path = directory / TEMPLATE
    try:
        body = path.read_bytes()
        manifest = json.loads(body)
    except (OSError, ValueError) as exc:
        raise TemplateError(f"{path}: {exc}") from exc
    meta = manifest.get("metadata", {}) if isinstance(manifest, dict) else {}
    labels = meta.get("labels") or {}
    if manifest.get("kind") != "Job" or not meta.get("generateName") or "name" in meta:
        raise TemplateError(f"{path}: not a Job with a generateName and no name")
    if not labels:
        raise TemplateError(f"{path}: no labels to find its Jobs by")
    return Template(body, {str(k): str(v) for k, v in labels.items()})


def selector(template: Template) -> str:
    """The template's labels (this release's scan Jobs), as a label selector."""
    return ",".join(f"{k}={v}" for k, v in sorted(template.labels.items()))


def plan(work: Work, active: int, bounds: Bounds) -> int:
    """How many Jobs to start now, with `active` live."""
    scans = min(work.claimed + work.claimable, work.max_parallel_runs, bounds.max_run_jobs)
    tests = min(work.queued_tests, bounds.max_test_jobs)
    return max(scans + tests - max(active, work.claimed), 0)


def read_work(engine: Engine) -> Work:
    with engine.connect() as conn:
        return Work(
            claimable=claims.claimable_connections(conn).get("aws", 0),
            claimed=claims.claimed_by_kind(conn).get("aws", 0),
            queued_tests=checks.queued_tests(conn),
            max_parallel_runs=read_collection(conn).max_parallel_runs,
        )


def reconcile(
    engine: Engine,
    kube: Kube,
    template: Template,
    bounds: Bounds,
    *,
    warned: set[str] | None = None,
    now: datetime | None = None,
) -> int:
    """One pass. Returns how many Jobs it started. A KubeError (a denial, the API unreachable)
    propagates: the caller backs off. `warned` holds the stuck Jobs already logged, across
    passes."""
    work = read_work(engine)
    if not work.claimable and not work.queued_tests:
        return 0
    warned = warned if warned is not None else set()
    now = now or datetime.now(UTC)
    live: set[str] = set()
    for job in kube.list_jobs(selector(template)):
        if job.finished:
            continue
        live.add(job.name)
        since = job.started_at
        stuck = since is not None and job.ready == 0 and now - since > STUCK_AFTER
        if stuck and since is not None and job.name not in warned:
            warned.add(job.name)
            log.warning("job not running", extra={"job": job.name, "since": since.isoformat()})
    warned &= live
    started = plan(work, len(live), bounds)
    for _ in range(started):
        name = kube.create_job(template.body)
        log.info(
            "job created",
            extra={
                "job": name,
                "claimable_connections": work.claimable,
                "queued_tests": work.queued_tests,
            },
        )
    return started
