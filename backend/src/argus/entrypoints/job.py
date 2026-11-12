"""A Kubernetes scan Job (ADR-0039): `python -m argus.entrypoints.job`.

The scheduler starts it from one of the chart's fixed templates (ADR-0046), which sets its work: a
connection test, one AWS scan of one tool, or one report (scheduling/job.py). A Job without a
known work, or on an image without its tool, fails before it claims anything. A scan or report
that fails is recorded as failed, so the Job itself still succeeds: Kubernetes never retries it
(backoffLimit 0), and the queue's own retries apply. Only an error outside the work (the database
unreachable) makes the Job fail.

SIGTERM is logged and otherwise ignored: the work in progress finishes if the pod's grace period
allows. A scan is otherwise released by the reaper and run again; a report is failed as abandoned
(reports.fail_stale) and requested again by its owner.
"""

import logging
import signal
import socket
import sys
from types import FrameType

from argus.core.config import get_settings
from argus.core.db import get_engine, require_pool
from argus.core.logging import configure_logging
from argus.core.process import hide_from_children
from argus.core.rawstore import FilesystemRawStore
from argus.scheduling.job import REPORT, REPORT_CONNECTIONS, WorkError, check_work, run_job
from argus.scheduling.runner import RUN_CONNECTIONS

log = logging.getLogger("argus.job")


def main() -> int:
    hide_from_children()
    settings = get_settings()
    configure_logging(settings.log_level)
    # A test or a report needs one; a scan, a run's peak.
    needed = REPORT_CONNECTIONS if settings.job_work == REPORT else RUN_CONNECTIONS
    require_pool(needed, process=f"{settings.job_work or 'scan'} job")
    try:
        check_work(settings.job_work)
    except WorkError as exc:
        log.error("job refused its work", extra={"detail": str(exc)})
        return 2

    def on_signal(signum: int, _frame: FrameType | None) -> None:
        log.info("asked to stop: finishing the work in progress", extra={"signal": signum})

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    try:
        done = run_job(
            get_engine(),
            work=settings.job_work,
            # Only Demo runs use the local store; AWS runs stage and upload to S3.
            store=FilesystemRawStore(settings.raw_root),
            rules_dir=settings.rules_dir,
            worker_id=socket.gethostname(),  # the pod's name
            max_runs=settings.max_run_jobs,
            # A report is written to the Job's scratch volume, then uploaded in one PUT.
            scratch=settings.raw_staging_root / "reports",
        )
    except Exception:
        log.exception("job failed")
        return 1
    log.info("job finished", extra={"work": settings.job_work, "done": done})
    return 0


if __name__ == "__main__":
    sys.exit(main())
