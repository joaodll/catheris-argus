"""Migration 0028 masks what was stored before secrets read ******** (ADR-0024, amended
2026-10-23): the old marker, and ExternalIds in JSON and text."""

import importlib.util
import json
from datetime import date
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import FilesystemRawStore
from argus.core.redaction import REDACTED, is_secret_key
from argus.relationships.engine import edge_key

pytestmark = pytest.mark.db
MIGRATION = Path(__file__).resolve().parents[2] / "migrations/versions/0028_mask_secrets.py"
DAY = date(2026, 10, 2)
# Fake values only, built at runtime so no scanner mistakes them for real ones.
EXTERNAL_ID = "ext-" + "not-real-" + "0123"


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0028", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _trust() -> dict[str, Any]:
    return {
        "Statement": [
            {
                "Principal": {"AWS": "arn:aws:iam::111122223333:role/argus-hub"},
                "Condition": {"StringEquals": {"sts:ExternalId": EXTERNAL_ID}},
            }
        ]
    }


def _masked_trust() -> dict[str, Any]:
    trust = _trust()
    trust["Statement"][0]["Condition"]["StringEquals"]["sts:ExternalId"] = REDACTED
    return trust


def test_stored_secrets_and_external_ids_read_masked(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    run_tool(worker, store, target, "cloudfox", DAY)
    before_config = {
        "user_data": "REDACTED",
        "endpoint": "https://REDACTED@hooks.example/in?sig=REDACTED",
        "assume_role_policy": _trust(),
        "note": "UNREDACTED stays",
    }
    with owner.begin() as conn:
        config_id = conn.execute(text("SELECT min(id) FROM resource_config")).scalar_one()
        resource_id = conn.execute(text("SELECT min(id) FROM resource")).scalar_one()
        rule_edge = conn.execute(
            text("SELECT min(id) FROM edge WHERE origin LIKE 'rule:%' AND type = 'CAN_ASSUME'")
        ).scalar_one()
        cloudfox = conn.execute(
            text(
                "SELECT id, attributes FROM edge WHERE origin = 'cloudfox' AND type = 'CAN_ASSUME'"
            )
        ).first()
        run_id = conn.execute(text("SELECT min(id) FROM scan_run")).scalar_one()
        conn.execute(
            text("UPDATE resource_config SET config = CAST(:c AS jsonb) WHERE id = :i"),
            {"c": json.dumps(before_config), "i": config_id},
        )
        conn.execute(
            text("UPDATE resource SET tags = CAST(:t AS jsonb) WHERE id = :i"),
            {
                "t": json.dumps({"ExternalId": EXTERNAL_ID, "api_token": "REDACTED"}),
                "i": resource_id,
            },
        )
        conn.execute(
            text("UPDATE edge SET attributes = CAST(:a AS jsonb) WHERE id = :i"),
            {"a": json.dumps({"condition": _trust()["Statement"][0]["Condition"]}), "i": rule_edge},
        )
        conn.execute(
            text("UPDATE scan_run SET log_tail = :l, command = :c WHERE id = :i"),
            {
                "l": f"KEY=REDACTED; assume-role --external-id {EXTERNAL_ID}; an ExternalId check",
                "c": f"aws sts assume-role --role-arn r --external-id {EXTERNAL_ID}",
                "i": run_id,
            },
        )
        _migration().mask_stored(conn)
        _migration().mask_stored(conn)  # a second run changes nothing

        config = conn.execute(
            text("SELECT config FROM resource_config WHERE id = :i"), {"i": config_id}
        ).scalar_one()
        tags = conn.execute(
            text("SELECT tags FROM resource WHERE id = :i"), {"i": resource_id}
        ).scalar_one()
        edge = conn.execute(
            text(
                "SELECT connection_id, origin, source_uid, target_uid, type, attributes, edge_key "
                "FROM edge WHERE id = :i"
            ),
            {"i": rule_edge},
        ).one()
        run = conn.execute(
            text("SELECT log_tail, command FROM scan_run WHERE id = :i"), {"i": run_id}
        ).one()
        left = (
            conn.execute(
                text("SELECT attributes FROM edge WHERE id = :i"), {"i": cloudfox.id}
            ).scalar_one()
            if cloudfox
            else None
        )
        everything = conn.execute(
            text("""
            SELECT string_agg(t, ' ') FROM (
              SELECT CAST(config AS text) t FROM resource_config
              UNION ALL SELECT CAST(tags AS text) FROM resource
              UNION ALL SELECT CAST(attributes AS text) FROM edge
              UNION ALL SELECT coalesce(log_tail, '') || command FROM scan_run) x
        """)
        ).scalar_one()

    assert config == {
        "user_data": REDACTED,
        "endpoint": f"https://{REDACTED}@hooks.example/in?sig={REDACTED}",
        "assume_role_policy": _masked_trust(),
        "note": "UNREDACTED stays",
    }
    assert tags == {"ExternalId": REDACTED, "api_token": REDACTED}
    assert edge.attributes == {"condition": _masked_trust()["Statement"][0]["Condition"]}
    # The edge keeps the key the next load computes, so it is not taken for a new edge.
    args = (edge.connection_id, edge.origin, edge.source_uid, edge.target_uid, edge.type)
    assert bytes(edge.edge_key) == edge_key(*args, edge.attributes)
    assert run.log_tail == (
        f"KEY={REDACTED}; assume-role --external-id {REDACTED}; an ExternalId check"
    )
    assert run.command == f"aws sts assume-role --role-arn r --external-id {REDACTED}"
    # CloudFox's flag says whether an ExternalId is required: a boolean, kept.
    if cloudfox:
        assert left == cloudfox.attributes
    assert EXTERNAL_ID not in everything and 'REDACTED"' not in everything


@pytest.mark.parametrize(
    ("key", "external"),
    [
        ("sts:ExternalId", True),
        ("ExternalID", True),
        ("external_id", True),
        ("ExternalIdentityProvider", False),
        ("id", False),
    ],
)
def test_the_migration_reads_an_external_id_key_as_redaction_does(key: str, external: bool) -> None:
    assert _migration().is_external_id_key(key) is external
    if external:
        assert is_secret_key(key)
