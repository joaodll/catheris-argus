"""The Kubernetes scheduler (ADR-0039): one replica, no cloud identity, never runs work.

Every 2 seconds it starts the scan Jobs that claimable scans and queued tests need
(scheduling/launcher.py); every 60 seconds it keeps the queue (scheduling/maintenance.py). A
refused or failed Kubernetes call is logged with the API's message and retried after 30
seconds. It touches a file on every pass, which the liveness probe checks, and exits on
SIGTERM: it holds no work of its own.
"""

import logging
import signal
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType

from argus.core.config import get_settings
from argus.core.db import get_engine
from argus.core.kube import KubeClient, KubeError
from argus.core.logging import configure_logging
from argus.scheduling import maintenance
from argus.scheduling.launcher import Bounds, load_template, reconcile, selector

log = logging.getLogger("argus.scheduler")
RECONCILE_EVERY_SECONDS = 2.0
MAINTAIN_EVERY_SECONDS = 60.0
BACKOFF_SECONDS = 30.0
ALIVE_FILE = Path("/tmp/argus-scheduler.alive")  # noqa: S108 - the pod's own /tmp


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)
    template = load_template(settings.job_templates_dir)
    bounds = Bounds(settings.max_run_jobs, settings.max_test_jobs)
    kube = KubeClient.in_cluster()
    engine = get_engine()
    stop = threading.Event()

    def on_signal(signum: int, _frame: FrameType | None) -> None:
        log.info("stopping", extra={"signal": signum})
        stop.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    log.info(
        "scheduler started",
        extra={
            "namespace": kube.namespace,
            "selector": selector(template),
            "max_run_jobs": bounds.max_run_jobs,
            "max_test_jobs": bounds.max_test_jobs,
        },
    )
    next_maintain = 0.0
    warned: set[str] = set()  # stuck Jobs already logged
    while not stop.is_set():
        wait = RECONCILE_EVERY_SECONDS
        if time.monotonic() >= next_maintain:
            try:
                maintenance.maintain(engine, now=datetime.now(UTC))
            except Exception:
                log.exception("maintenance error")
            next_maintain = time.monotonic() + MAINTAIN_EVERY_SECONDS
        try:
            reconcile(engine, kube, template, bounds, warned=warned)
        except KubeError as exc:
            log.error(
                "kubernetes refused",
                extra={"status": exc.status, "reason": exc.reason, "detail": exc.message},
            )
            wait = BACKOFF_SECONDS
        except Exception:
            log.exception("reconcile error")
            wait = BACKOFF_SECONDS
        ALIVE_FILE.touch()
        stop.wait(wait)
    return 0


if __name__ == "__main__":
    sys.exit(main())
