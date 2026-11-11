"""The scheduler's reconcile (ADR-0039, ADR-0046): count the work that could start, count the scan
Jobs alive, and start the missing Jobs from the chart's four fixed templates, one per work.

- Each template is submitted byte for byte: the scheduler fills in nothing, so the admission
  policy that pins it (ADR-0040) sees exactly what the chart rendered. Kubernetes names each Job
  from its generateName.
- Each scan Job does one unit of its work (scheduling/job.py): a `test` Job one connection test;
  a `steampipe`, `prowler` or `cloudfox` Job one AWS scan of its tools. Demo connections are not
  scanned on Kubernetes.
- Scans are counted in connections, not requests: one request per connection runs at a time,
  and only a connection's next request may be claimed (claims.next_requests), so it decides
  which kind of Job the connection needs.
- The scan slots are the smaller of the administration setting "max parallel runs" and
  ARGUS_MAX_RUN_JOBS, filled in claim order. What holds a slot, per kind, is the larger of its
  live Jobs (claimed yet or not) and its claimed scans: a claim whose pod died holds its slot
  until the reaper requeues it, so no Job is started only to find the cap full. Tests have their
  own bound, ARGUS_MAX_TEST_JOBS, so a test never waits behind a long scan.
- With nothing to start, the Kubernetes API is not called at all.
- Every Job started is logged with its name and its work (review S5).
- A Job with no running pod after STUCK_AFTER (an image it cannot pull, no node for it) is
  logged once: it still holds its slot until its deadline, and the scheduler cannot delete Jobs
  (ADR-0040), so the log is where an operator learns why the queue waits. While it lives, no
  other Job of its kind starts: one image that cannot be pulled holds one slot, not all of them.
- A Job that failed (it refused its work, on an image without its tool; the database was out of
  reach; its deadline passed) is logged once, and no Job of its work starts while it is still
  listed, until Kubernetes deletes it (ttlSecondsAfterFinished). Its request stays queued, so
  without this every pass would start another Job to fail the same way, until the Job quota
  stopped every work.
"""

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from sqlalchemy import Engine

from argus.connections import checks
from argus.core.kube import JobState
from argus.scheduling import claims
from argus.scheduling.job import SCAN_WORK, TEST, WORK, work_of
from argus.settings import read_collection

log = logging.getLogger("argus.scheduler")
# The label that tells the four templates' Jobs apart; its value is the template's work.
WORK_LABEL = "argus/work"
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
    # Each AWS connection's next claimable request, as the work that runs it, in claim order.
    next_work: tuple[str, ...]
    claimed: Mapping[str, int]  # AWS requests claimed now, per work
    queued_tests: int
    max_parallel_runs: int


class Kube(Protocol):
    def create_job(self, body: bytes) -> str: ...
    def list_jobs(self, selector: str) -> list[JobState]: ...


def load_template(directory: Path, work: str) -> Template:
    """`<work>.json`: a Job with a generateName, no name, and labels to find its Jobs by, the
    work label naming that work."""
    path = directory / f"{work}.json"
    try:
        body = path.read_bytes()
        manifest = json.loads(body)
    except (OSError, ValueError) as exc:
        raise TemplateError(f"{path}: {exc}") from exc
    meta = manifest.get("metadata", {}) if isinstance(manifest, dict) else {}
    labels = meta.get("labels") or {}
    if manifest.get("kind") != "Job" or not meta.get("generateName") or "name" in meta:
        raise TemplateError(f"{path}: not a Job with a generateName and no name")
    if labels.get(WORK_LABEL) != work:
        raise TemplateError(f"{path}: its {WORK_LABEL} label is not {work!r}")
    return Template(body, {str(k): str(v) for k, v in labels.items()})


def load_templates(directory: Path) -> dict[str, Template]:
    """Every work's template: the scheduler refuses to start without all of them."""
    return {work: load_template(directory, work) for work in WORK}


def selector(template: Template) -> str:
    """The template's labels (this release's Jobs of its work), as a label selector."""
    return ",".join(f"{k}={v}" for k, v in sorted(template.labels.items()))


def plan(
    work: Work, live: Mapping[str, int], bounds: Bounds, stuck: frozenset[str] = frozenset()
) -> dict[str, int]:
    """How many Jobs of each work to start now, with `live` Jobs of each alive and the works in
    `stuck` holding a Job that has not run, or one that failed."""
    slots = min(work.max_parallel_runs, bounds.max_run_jobs)
    held = sum(max(live.get(w, 0), work.claimed.get(w, 0)) for w in SCAN_WORK)
    free = slots - held
    # Jobs started that have not claimed yet take the first requests of their work.
    unclaimed = {w: max(live.get(w, 0) - work.claimed.get(w, 0), 0) for w in SCAN_WORK}
    start = dict.fromkeys(WORK, 0)
    for w in work.next_work:
        if unclaimed[w]:
            unclaimed[w] -= 1
        elif free > 0 and w not in stuck:
            start[w] += 1
            free -= 1
    if TEST not in stuck:
        start[TEST] = max(min(work.queued_tests, bounds.max_test_jobs) - live.get(TEST, 0), 0)
    return start


def read_work(engine: Engine) -> Work:
    with engine.connect() as conn:
        claimed: dict[str, int] = {}
        for (kind, tool), n in claims.claimed_tools(conn).items():
            if kind == "aws":
                claimed[work_of(tool)] = claimed.get(work_of(tool), 0) + n
        return Work(
            next_work=tuple(work_of(r.tool) for r in claims.next_requests(conn) if r.kind == "aws"),
            claimed=claimed,
            queued_tests=checks.queued_tests(conn),
            max_parallel_runs=read_collection(conn).max_parallel_runs,
        )


def reconcile(
    engine: Engine,
    kube: Kube,
    templates: Mapping[str, Template],
    bounds: Bounds,
    *,
    warned: set[str] | None = None,
    now: datetime | None = None,
) -> int:
    """One pass. Returns how many Jobs it started. A KubeError (a denial, the API unreachable)
    propagates: the caller backs off. `warned` holds the stuck Jobs already logged, across
    passes."""
    work = read_work(engine)
    if not work.next_work and not work.queued_tests:
        return 0
    warned = warned if warned is not None else set()
    now = now or datetime.now(UTC)
    listed: set[str] = set()
    live: dict[str, int] = {}
    stuck: set[str] = set()
    for name, template in templates.items():
        for job in kube.list_jobs(selector(template)):
            if job.failed:
                listed.add(job.name)
                stuck.add(name)
                if job.name not in warned:
                    warned.add(job.name)
                    log.warning("job failed", extra={"job": job.name, "work": name})
                continue
            if job.finished:
                continue
            listed.add(job.name)
            live[name] = live.get(name, 0) + 1
            since = job.started_at
            if since is not None and job.ready == 0 and now - since > STUCK_AFTER:
                stuck.add(name)
                if job.name not in warned:
                    warned.add(job.name)
                    log.warning(
                        "job not running",
                        extra={"job": job.name, "work": name, "since": since.isoformat()},
                    )
    warned &= listed  # a Job is logged once while Kubernetes lists it
    started = plan(work, live, bounds, frozenset(stuck))
    for name, count in started.items():
        for _ in range(count):
            job_name = kube.create_job(templates[name].body)
            log.info(
                "job created",
                extra={
                    "job": job_name,
                    "work": name,
                    "claimable_connections": len(work.next_work),
                    "queued_tests": work.queued_tests,
                },
            )
    return sum(started.values())
