"""Migration 0017 re-keys edges with its own copy of the key; it must equal ingest's."""

import importlib.util
from datetime import date
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import FilesystemRawStore
from argus.relationships.engine import edge_key

pytestmark = pytest.mark.db
MIGRATION = (
    Path(__file__).resolve().parents[2] / "migrations/versions/0017_edge_key_per_connection.py"
)


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0017", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_migration_key_is_the_ingest_key_after_a_jsonb_round_trip(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", date(2026, 10, 2))
    run_tool(worker, store, target, "cloudfox", date(2026, 10, 2))
    key = _migration().per_connection_key
    with owner.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT edge_key, connection_id, origin, source_uid, target_uid, type, "
                "attributes FROM edge WHERE origin <> 'manual'"
            )
        ).all()
    assert {r.origin.split(":")[0] for r in rows} >= {"rule", "cloudfox"}
    for r in rows:
        args = (r.connection_id, r.origin, r.source_uid, r.target_uid, r.type, r.attributes or {})
        assert bytes(r.edge_key) == key(*args) == edge_key(*args)
