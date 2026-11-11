"""The Compose worker (ADR-0019): run threads that claim and execute requests, a thread that
answers Test connection, a thread that builds reports where this install keeps them (ADR-0047),
and a main loop that keeps the queue (maintenance.py) and runs retention
once a day. On Kubernetes the same work is split between the scheduler and run Jobs (ADR-0039),
with the same code.
"""

import logging
import socket
import threading
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from sqlalchemy import Engine

from argus import reports
from argus.core.rawstore import FilesystemRawStore
from argus.ingest import REDERIVE_CONNECTIONS, rederive_stale
from argus.scheduling import connection_checks, maintenance
from argus.scheduling.runner import RUN_CONNECTIONS, run_once

log = logging.getLogger("argus.worker")
TICK_EVERY = timedelta(seconds=60)
IDLE_WAIT_SECONDS = 5
# Test connection is answered within seconds: the UI waits for it (ADR-0024).
TEST_WAIT_SECONDS = 2
# A queued report waits at most this long for the report thread to look.
REPORT_WAIT_SECONDS = 3


def connections_needed(threads: int) -> int:
    """The most connections a worker holds at once: every run thread at its peak, the test
    thread, the report thread (one at a time: claim, read, record), and the main loop (re-derive
    at start, then retention)."""
    main_loop = max(REDERIVE_CONNECTIONS, maintenance.RETENTION_CONNECTIONS)
    return threads * RUN_CONNECTIONS + 1 + 1 + main_loop


class Worker:
    def __init__(
        self,
        engine: Engine,
        *,
        store: FilesystemRawStore,
        rules_dir: Path,
        threads: int,
        reports_store: reports.LocalReportStore | None = None,
    ) -> None:
        self.engine = engine
        self.store = store
        self.reports_store = reports_store
        self.rules_dir = rules_dir
        self.threads = threads
        self.stop = threading.Event()
        self.worker_id = f"{socket.gethostname()}-{uuid4().hex[:8]}"

    def _run_loop(self, index: int) -> None:
        name = f"{self.worker_id}/{index}"
        while not self.stop.is_set():
            try:
                status = run_once(
                    self.engine, store=self.store, rules_dir=self.rules_dir, worker_id=name
                )
            except Exception:
                log.exception("claim loop error")
                status = None
            if status is None:
                self.stop.wait(IDLE_WAIT_SECONDS)

    def _test_loop(self) -> None:
        """Test connection runs on its own thread: a scan of hours never makes it wait."""
        while not self.stop.is_set():
            try:
                ran = connection_checks.run_pending(self.engine)
            except Exception:
                log.exception("connection test loop error")
                ran = False
            if not ran:
                self.stop.wait(TEST_WAIT_SECONDS)

    def _report_loop(self, store: reports.LocalReportStore) -> None:
        """Reports are built one at a time on their own thread: a scan never waits for one,
        and one never waits for a scan."""
        # As the thread starts nothing builds (one worker per Compose install): end what a
        # stopped worker left building, then remove every file no report names.
        try:
            with self.engine.begin() as conn:
                failed = reports.fail_abandoned(conn)
                kept = reports.kept_keys(conn)
            swept = store.sweep(kept)
            if failed or swept:
                log.info(
                    "reports left by a stopped worker",
                    extra={"reports_failed": failed, "files_removed": swept},
                )
        except Exception:
            log.exception("report loop error")
        while not self.stop.is_set():
            try:
                built = reports.build_pending(self.engine, store=store)
            except Exception:
                log.exception("report loop error")
                built = False
            if not built:
                self.stop.wait(REPORT_WAIT_SECONDS)

    def run(self) -> None:
        # Before any run thread: a rule upgrade shows at once, and no ingest races it.
        try:
            rederive_stale(self.engine, rules_dir=self.rules_dir, today=datetime.now(UTC).date())
        except Exception:
            log.exception("re-derive error")
        runners = [
            threading.Thread(target=self._run_loop, args=(i,), name=f"run-{i}")
            for i in range(self.threads)
        ]
        runners.append(threading.Thread(target=self._test_loop, name="tests"))
        if self.reports_store is not None:
            runners.append(
                threading.Thread(
                    target=self._report_loop, args=(self.reports_store,), name="reports"
                )
            )
        for runner in runners:
            runner.start()
        log.info("worker started", extra={"worker_id": self.worker_id, "threads": self.threads})
        retention_done_on: date | None = None
        while not self.stop.is_set():
            now = datetime.now(UTC)
            try:
                maintenance.maintain(self.engine, now=now)
                retention_done_on = maintenance.daily_retention(
                    self.engine,
                    store=self.store,
                    today=now.date(),
                    done_on=retention_done_on,
                    reports_store=self.reports_store,
                )
            except Exception:
                log.exception("maintenance error")
            self.stop.wait(TICK_EVERY.total_seconds())
        for runner in runners:
            runner.join()  # each finishes the run it is on (graceful shutdown)
        log.info("worker stopped", extra={"worker_id": self.worker_id})
