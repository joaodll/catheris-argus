"""Migration 0040 applies the wider redaction rules (2026-11-05) to what is already stored."""

import importlib.util
import json
from datetime import date
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import Engine, text
from tests.test_core_redaction import SHAPE_IDS, SHAPES

from argus.core.redaction import (
    NOT_SECRET_COLUMNS,
    REDACTED,
    is_secret_key,
    redact,
    redact_tags,
    redact_text,
)

pytestmark = pytest.mark.db
MIGRATION = Path(__file__).resolve().parents[2] / "migrations/versions/0040_remask_wider_rules.py"
# Fake values only, built at runtime so no scanner mistakes them for real ones.
LEAK = "not-real-" + "0040"
CONFIG = {
    "dbpassword": LEAK,
    "parameters": [{"ParameterKey": "adminpwd", "ParameterValue": LEAK}],
    "definition": f"Server=db;Pwd={LEAK};",
    "access_key_id": "AKIA" + "Z" * 16,
    "policy": {"Action": "secretsmanager:GetSecretValue"},
    "stage": "prod",
}


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0040", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("line", SHAPES, ids=SHAPE_IDS)
def test_the_frozen_rules_match_redaction_today(line: str) -> None:
    frozen = _migration()
    assert frozen.remask_text(line) == redact_text(line)
    assert frozen.redact({"definition": line}) == redact({"definition": line})


@pytest.mark.parametrize(
    "key",
    ["pwd", "Authorization", "authorization_type", "secretsmanager", "HttpTokens", "ssh_key_name"],
)
def test_the_frozen_key_rule_matches_redaction_today(key: str) -> None:
    assert _migration().is_secret_key(key) == is_secret_key(key)


def test_the_frozen_tag_rule_matches_redaction_today() -> None:
    tags = {"Environment": "staging", "db_password": LEAK, "owner": "team-a"}
    assert _migration().redact_tags(tags) == redact_tags(tags)


def test_the_frozen_exceptions_cover_every_table_today() -> None:
    assert frozenset().union(*NOT_SECRET_COLUMNS.values()) == _migration()._KEEP


def test_stored_values_are_re_masked(migrated: Engine) -> None:
    # One transaction, rolled back: the schema tests expect empty tables.
    day = date(2026, 10, 2)
    with migrated.connect() as conn, conn.begin() as tx:
        cid = conn.execute(
            text(
                "INSERT INTO connection (name, kind, account_id, auth_method, demo_seed, "
                "created_by, updated_by) VALUES ('remask', 'demo', '100000000099', 'none', 0, "
                "'t', 't') RETURNING id"
            )
        ).scalar_one()
        config_id = conn.execute(
            text(
                "INSERT INTO resource_config (config_hash, config, created_on) "
                "VALUES (:h, CAST(:c AS jsonb), :d) RETURNING id"
            ),
            {"h": b"h" * 32, "c": json.dumps(CONFIG), "d": day},
        ).scalar_one()
        resource_id = conn.execute(
            text(
                "INSERT INTO resource (resource_uid, connection_id, region, type, native_id, tags, "
                "config_id, first_seen, last_seen) VALUES ('arn:x', :c, 'global', 'aws_s3_bucket', "
                "'x', CAST(:t AS jsonb), :cfg, :d, :d) RETURNING id"
            ),
            {
                "c": cid,
                "t": json.dumps({"db_password": LEAK, "Environment": "staging"}),
                "cfg": config_id,
                "d": day,
            },
        ).scalar_one()
        # Facts a rule chose, under a name that reads as secret.
        attributes = {"credentials": ["access_key"], "external_id": True}
        rule_edge = conn.execute(
            text(
                "INSERT INTO edge (edge_key, connection_id, source_uid, target_uid, type, origin, "
                "attributes, first_seen, last_seen) VALUES (:k, :c, 'a', 'b', 'T', 'rule:r@1', "
                "CAST(:a AS jsonb), :d, :d) RETURNING id"
            ),
            {"k": b"k" * 32, "c": cid, "a": json.dumps(attributes), "d": day},
        ).scalar_one()
        request_id = conn.execute(
            text(
                "INSERT INTO run_request (connection_id, tool, reason, requested_by, error) "
                "VALUES (:c, 'prowler', 'manual', 'admin', :e) RETURNING id"
            ),
            {"c": cid, "e": f"failed: Authorization: Bearer {LEAK}\nregion=us-east-1"},
        ).scalar_one()

        migration = _migration()
        changed = migration.remask_stored(conn)
        again = migration.remask_stored(conn)

        config, config_hash = conn.execute(
            text("SELECT config, config_hash FROM resource_config WHERE id = :i"), {"i": config_id}
        ).one()
        tags = conn.execute(
            text("SELECT tags FROM resource WHERE id = :i"), {"i": resource_id}
        ).scalar_one()
        edge = conn.execute(
            text("SELECT attributes FROM edge WHERE id = :i"), {"i": rule_edge}
        ).scalar_one()
        error = conn.execute(
            text("SELECT error FROM run_request WHERE id = :i"), {"i": request_id}
        ).scalar_one()
        tx.rollback()

    assert changed == 3 and again == 0  # config, tags, text; a second run changes nothing
    assert LEAK not in json.dumps(config) and bytes(config_hash) == b"h" * 32
    assert config["access_key_id"] == CONFIG["access_key_id"]  # the exception holds
    assert config["policy"] == CONFIG["policy"] and config["stage"] == "prod"
    assert tags == {"db_password": REDACTED, "Environment": "staging"}
    assert edge == attributes
    assert LEAK not in error and "region=us-east-1" in error
