import logging
import shutil
from dataclasses import dataclass
from datetime import date, timedelta

from sqlalchemy import Engine, text

from argus import ingest, inventory, relationships
from argus.core.rawstore import FilesystemRawStore

log = logging.getLogger("argus.retention")


@dataclass
class RetentionResult:
    partitions_dropped: list[str]
    configs_deleted: int
    demo_runs_pruned: int


def run_retention(
    engine: Engine,
    *,
    store: FilesystemRawStore | None,
    today: date,
    retention_days: int,
    demo_raw_days: int,
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
        relationships.delete_loads_before(conn, cutoff=cutoff)
        relationships.delete_orphan_flow_shapes(conn)
        demo_paths = ingest.synthetic_raw_paths_before(
            conn, day=today - timedelta(days=demo_raw_days)
        )
    pruned = 0
    # No store: demo runs keep nothing on disk (a Kubernetes demo Job deletes its own).
    if store is not None:
        for path in demo_paths:
            run_dir = store.open(path)
            if run_dir.exists():
                shutil.rmtree(run_dir)  # synthetic output is regenerable from its seed
                pruned += 1
    result = RetentionResult(dropped, configs, pruned)
    log.info(
        "retention",
        extra={
            "partitions_dropped": len(dropped),
            "configs_deleted": configs,
            "demo_runs_pruned": pruned,
        },
    )
    return result
