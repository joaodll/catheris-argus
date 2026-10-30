"""Ingest tests run as argus_worker, so they also prove the worker's grants are enough."""

from datetime import date
from pathlib import Path
from uuid import uuid4

from sqlalchemy import Engine, text

from argus.collection import (
    CollectOptions,
    CollectTarget,
    FilesystemRawStore,
    collect,
    source_for,
)
from argus.connections import demo_account_id
from argus.ingest import IngestOutcome, ingest_run, register_run

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
QUIET = CollectOptions(synthetic_throttle_share=0.0)


def make_demo(owner: Engine, seed: int = 0) -> CollectTarget:
    with owner.begin() as conn:
        cid = conn.execute(
            text(
                "INSERT INTO connection (name, kind, account_id, auth_method, demo_seed, "
                "created_by, updated_by) VALUES (:n, 'demo', :a, 'none', :s, 't', 't') "
                "RETURNING id"
            ),
            {"n": f"demo-{seed}", "a": demo_account_id(seed), "s": seed},
        ).scalar_one()
    return CollectTarget(cid, "demo", demo_account_id(seed), seed)


def make_aws(owner: Engine, name: str = "aws-test", account_id: str = "210987654321") -> int:
    """An AWS connection by assume role, straight into the table. Returns its id."""
    with owner.begin() as conn:
        return int(
            conn.execute(
                text(
                    "INSERT INTO connection (name, kind, account_id, auth_method, role_arn, "
                    "external_id, created_by, updated_by) VALUES (:n, 'aws', :a, "
                    "'assume_role', :r, 'test-external-id-0001', 't', 't') RETURNING id"
                ),
                {"n": name, "a": account_id, "r": f"arn:aws:iam::{account_id}:role/ArgusScanner"},
            ).scalar_one()
        )


def run_tool(
    worker: Engine,
    store: FilesystemRawStore,
    target: CollectTarget,
    tool: str,
    day: date,
    options: CollectOptions = QUIET,
) -> IngestOutcome:
    path, manifest = collect(
        source_for("demo"),
        store,
        target=target,
        tool=tool,  # type: ignore[arg-type]
        day=day,
        run_uid=uuid4(),
        options=options,
    )
    with worker.begin() as conn:
        scan_run_id = register_run(
            conn, connection_id=target.connection_id, raw_path=path, manifest=manifest
        )
    return ingest_run(worker, store=store, scan_run_id=scan_run_id, rules_dir=RULES_DIR)
