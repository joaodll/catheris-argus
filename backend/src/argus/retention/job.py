import logging
import shutil
from dataclasses import dataclass
from datetime import date, timedelta

from sqlalchemy import Engine, text

from argus import auth, ingest, inventory, relationships, reports
from argus.core.rawstore import FilesystemRawStore

log = logging.getLogger("argus.retention")


@dataclass
class RetentionResult:
    partitions_dropped: list[str]
    configs_deleted: int
    demo_runs_pruned: int
    sign_in_rows_purged: int
    report_files_deleted: int = 0


def run_retention(
    engine: Engine,
    *,
    store: FilesystemRawStore | None,
    today: date,
    retention_days: int,
    demo_raw_days: int,
    reports_store: reports.LocalReportStore | None = None,
) -> RetentionResult:
    cutoff = today - timedelta(days=retention_days)
    with engine.begin() as conn:
        # Next months first, so tomorrow's ingest never meets a missing partition.
        conn.execute(
            text("SELECT argus_ensure_partitions(:a, :b)"),
            {"a": today, "b": today + timedelta(days=62)},
        )
        dropped = list(
            conn.execute(text("SELECT argus_drop_partitions_before(:c)"), {"c": cutoff}).scalars()
        )
        configs = inventory.delete_orphan_configs(conn)
        inventory.delete_loads_before(conn, cutoff=cutoff)
        relationships.delete_loads_before(conn, cutoff=cutoff)
        sign_in_rows = auth.purge_old_sign_in_rows(conn)
        demo_paths = ingest.synthetic_raw_paths_before(
            conn, day=today - timedelta(days=demo_raw_days)
        )
        # Reports past their expiry: the API already refuses them; only their files remain.
        # Without a store (Kubernetes until reports go to S3) there are none to delete.
        report_keys = reports.expired_files(conn) if reports_store is not None else []
    pruned = 0
    # No store: demo runs keep nothing on disk (a Kubernetes demo Job deletes its own).
    if store is not None:
        for path in demo_paths:
            run_dir = store.open(path)
            if run_dir.exists():
                shutil.rmtree(run_dir)  # synthetic output is regenerable from its seed
                pruned += 1
    report_files = 0
    if reports_store is not None:
        for key in report_keys:
            try:
                report_files += reports_store.delete(key)
            except (OSError, reports.ReportStoreError):
                # Marked deleted already; the API refuses it by its expiry whatever stays.
                log.warning("report file not deleted", extra={"storage_key": key})
    result = RetentionResult(dropped, configs, pruned, sign_in_rows, report_files)
    log.info(
        "retention",
        extra={
            "partitions_dropped": len(dropped),
            "configs_deleted": configs,
            "demo_runs_pruned": pruned,
            "sign_in_rows_purged": sign_in_rows,
            "report_files_deleted": report_files,
        },
    )
    return result
