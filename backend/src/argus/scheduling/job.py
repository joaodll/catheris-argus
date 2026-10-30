"""One Kubernetes scan Job (ADR-0039). The scheduler starts it from the chart's single fixed
template; the Job claims its own work from the queue, with the code the Compose worker uses, and
does one unit of it:

1. a queued Test connection request, when there is one: tests never wait behind long scans;
2. otherwise one AWS scan, while fewer than the cap run (the smaller of the administration
   setting "max parallel runs" and the deployment's ARGUS_MAX_RUN_JOBS);
3. otherwise nothing.

Then it exits. Its credentials, its AWS profile and its staged raw output, which can hold secret
values, die with the pod. A Job that finds nothing to claim exits at once: the scheduler may
start one for work another Job took first. Demo connections are not scanned on Kubernetes.
"""

import logging
from pathlib import Path
from typing import Literal

from sqlalchemy import Engine

from argus.core.rawstore import FilesystemRawStore
from argus.scheduling import connection_checks
from argus.scheduling.runner import run_once

log = logging.getLogger("argus.job")
Done = Literal["test", "scan", "nothing"]


def run_job(
    engine: Engine,
    *,
    store: FilesystemRawStore,
    rules_dir: Path,
    worker_id: str,
    max_runs: int,
) -> Done:
    """Does this Job's one unit of work. Returns which it was."""
    if connection_checks.run_pending(engine):
        return "test"
    status = run_once(
        engine,
        store=store,
        rules_dir=rules_dir,
        worker_id=worker_id,
        kinds=("aws",),
        max_parallel=max_runs,
    )
    return "nothing" if status is None else "scan"
