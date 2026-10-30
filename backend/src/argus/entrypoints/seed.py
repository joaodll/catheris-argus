"""Developer and test shortcut: three Demo connections with history (prod, staging, shared).

It calls create_demo_connection(), the same function the UI uses, so there is one way to
create a Demo connection. Existing connections with these names are left alone. Where Demo
connections are off (ARGUS_DEMO_CONNECTIONS=false, Kubernetes) it refuses and exits 1.
"""

import argparse
import logging
import sys
from datetime import UTC, datetime

from argus import connections
from argus.core.config import get_settings
from argus.core.db import get_engine
from argus.core.logging import configure_logging
from argus.scheduling import create_demo_connection

DEMO = (("demo-prod", 0), ("demo-staging", 1), ("demo-shared", 2))
log = logging.getLogger("argus.seed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create the demo connections")
    parser.add_argument("--days", type=int, default=180, help="days of history to backfill")
    args = parser.parse_args(argv)
    configure_logging(get_settings().log_level)

    if "demo" not in connections.allowed_kinds():
        log.error("demo connections are off in this deployment (ARGUS_DEMO_CONNECTIONS)")
        return 1
    engine = get_engine()
    today = datetime.now(UTC).date()
    for name, seed in DEMO:
        with engine.connect() as conn:
            if connections.by_name(conn, name):
                log.info("demo connection exists, skipped", extra={"connection": name})
                continue
        connection, queued = create_demo_connection(
            engine, name=name, seed=seed, days=args.days, today=today, actor="seed"
        )
        log.info(
            "demo connection created",
            extra={"connection": name, "account": connection.account_id, "requests_queued": queued},
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
