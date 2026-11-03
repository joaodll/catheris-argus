"""The Kubernetes graph sync (ADR-0044): one replica that keeps the Memgraph read model equal
to Postgres. It is the only process on Kubernetes holding the graph's login; scan Jobs never do.

Every 15 seconds it re-projects connections whose data changed; every 10 minutes it runs the
integrity check (graph/loop.py). It touches a file on every pass, which the liveness probe
checks, and exits on SIGTERM: a sync it stops mid-way never committed, and the next start redoes
it.
"""

import logging
import signal
import sys
import threading
from pathlib import Path
from types import FrameType

from argus.core.config import get_settings
from argus.core.db import get_engine, require_pool
from argus.core.logging import configure_logging
from argus.graph import GRAPH_CONNECTIONS, loop

log = logging.getLogger("argus.graph")
ALIVE_FILE = Path("/tmp/argus-graph-sync.alive")  # noqa: S108 - the pod's own /tmp


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)
    require_pool(GRAPH_CONNECTIONS, process="graph-sync")
    if settings.graph_password is None:
        log.error("ARGUS_GRAPH_PASSWORD is not set: the graph sync has no login")
        return 2
    stop = threading.Event()

    def on_signal(signum: int, _frame: FrameType | None) -> None:
        log.info("stopping", extra={"signal": signum})
        stop.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    log.info("graph sync started")
    loop.run(get_engine(), stop, alive=ALIVE_FILE.touch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
