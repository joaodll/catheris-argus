"""The Compose worker process: scheduling, collection, ingest and retention (ADR-0019).

SIGTERM and SIGINT stop claiming new work; runs in progress finish before the process exits.
"""

import logging
import signal
import sys
from types import FrameType

from argus.core.config import get_settings
from argus.core.db import get_engine, require_pool
from argus.core.logging import configure_logging
from argus.core.rawstore import FilesystemRawStore, sweep_staging
from argus.scheduling.worker import Worker, connections_needed

log = logging.getLogger("argus.worker")


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)
    require_pool(connections_needed(settings.worker_threads), process="worker")
    # Before any claim: what a stopped worker staged belongs to no live run (ADR-0032).
    log.info("staging swept", extra={"runs_removed": sweep_staging(settings.raw_staging_root)})
    worker = Worker(
        get_engine(),
        store=FilesystemRawStore(settings.raw_root),
        rules_dir=settings.rules_dir,
        threads=settings.worker_threads,
    )

    def stop(signum: int, _frame: FrameType | None) -> None:
        log.info("stopping: finishing runs in progress", extra={"signal": signum})
        worker.stop.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    worker.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
