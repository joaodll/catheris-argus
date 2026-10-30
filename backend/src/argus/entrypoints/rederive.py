"""Derive again after a rule upgrade, as a Kubernetes Job the chart starts once per image
(ADR-0039). It waits for the ingests running now, then re-derives each connection whose rules
changed. The Compose worker does the same when it starts."""

import logging
import sys
from datetime import UTC, datetime

from argus.core.config import get_settings
from argus.core.db import get_engine, require_pool
from argus.core.logging import configure_logging
from argus.ingest import REDERIVE_CONNECTIONS, rederive_stale

log = logging.getLogger("argus.rederive")


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)
    require_pool(REDERIVE_CONNECTIONS, process="rederive")
    rederive_stale(get_engine(), rules_dir=settings.rules_dir, today=datetime.now(UTC).date())
    return 0


if __name__ == "__main__":
    sys.exit(main())
