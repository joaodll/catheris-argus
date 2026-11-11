"""One Kubernetes scan Job (ADR-0039, ADR-0046). The scheduler starts it from one of the chart's
four fixed templates, each with its own image and its own work (`ARGUS_JOB_WORK`); the Job
claims its own work from the queue, with the code the Compose worker uses, and does one unit of
it:

- `test`: a queued Test connection request, on the image without tools. It never scans.
- `steampipe`, `prowler`, `cloudfox`: one AWS scan of its tools, while fewer than the cap run
  (the smaller of the administration setting "max parallel runs" and the deployment's
  ARGUS_MAX_RUN_JOBS). It claims a connection's next request only when that request is one of
  its tools, so the tools still run in order on each connection. It never answers a test.

Then it exits. Its credentials, its AWS profile and its staged raw output, which can hold secret
values, die with the pod. A Job that finds nothing to claim exits at once: the scheduler may
start one for work another Job took first. Demo connections are not scanned on Kubernetes.
"""

import logging
from pathlib import Path
from typing import Literal

from sqlalchemy import Engine

from argus.collection import missing_tools
from argus.core.rawstore import FilesystemRawStore
from argus.scheduling import connection_checks
from argus.scheduling.runner import run_once

log = logging.getLogger("argus.job")
Done = Literal["test", "scan", "nothing"]
TEST = "test"
# Each scan Job's work and the tools it may claim, one image each. The Vulnerabilities tool runs
# the Steampipe export binary (ADR-0042), so it shares Steampipe's image.
SCAN_WORK: dict[str, tuple[str, ...]] = {
    "steampipe": ("steampipe", "vulnerabilities"),
    "prowler": ("prowler",),
    "cloudfox": ("cloudfox",),
}
WORK = (TEST, *SCAN_WORK)


class WorkError(ValueError):
    """This Job cannot do the work it was given: it exits before it claims anything."""


def work_of(tool: str) -> str:
    """The scan Job work that runs `tool`."""
    for work, tools in SCAN_WORK.items():
        if tool in tools:
            return work
    raise WorkError(f"no scan Job runs the tool {tool!r}")


def check_work(work: str) -> None:
    """Refuses an unknown work, and a scan work whose tools this image does not carry: a Job
    on the wrong image would otherwise claim a run only to fail it, and spend a retry."""
    if work not in WORK:
        raise WorkError(f"ARGUS_JOB_WORK must be one of {', '.join(WORK)}, not {work!r}")
    missing = missing_tools(SCAN_WORK.get(work, ()))
    if missing:
        raise WorkError(f"this image does not carry {', '.join(missing)} for {work!r} work")


def run_job(
    engine: Engine,
    *,
    work: str,
    store: FilesystemRawStore,
    rules_dir: Path,
    worker_id: str,
    max_runs: int,
) -> Done:
    """Does this Job's one unit of work. Returns which it was."""
    if work == TEST:
        return "test" if connection_checks.run_pending(engine) else "nothing"
    if work not in SCAN_WORK:
        raise WorkError(f"unknown work {work!r}")
    status = run_once(
        engine,
        store=store,
        rules_dir=rules_dir,
        worker_id=worker_id,
        kinds=("aws",),
        tools=SCAN_WORK[work],
        max_parallel=max_runs,
    )
    return "nothing" if status is None else "scan"
