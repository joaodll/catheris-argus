"""Retention as a Kubernetes CronJob (ADR-0039): partitions, orphan configurations and old
rule loads. Demo runs keep no raw files on Kubernetes, so there is nothing of them to prune.
The Compose worker runs the same function once a day itself."""

import logging
import sys
from datetime import UTC, datetime

from argus.core.config import get_settings
from argus.core.db import get_engine, require_pool
from argus.core.logging import configure_logging
from argus.scheduling.maintenance import RETENTION_CONNECTIONS, daily_retention

log = logging.getLogger("argus.retention")


def main() -> int:
    configure_logging(get_settings().log_level)
    require_pool(RETENTION_CONNECTIONS, process="retention")
    today = datetime.now(UTC).date()
    if daily_retention(get_engine(), store=None, today=today, done_on=None) is None:
        log.info("retention skipped: another process is running it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
