"""Migration 0043 masks CloudFront origin custom header values already stored (2026-11-05)."""

import importlib.util
import json
from datetime import date
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import Engine, text

from argus.core.redaction import is_secret_key, redact

pytestmark = pytest.mark.db
MIGRATION = (
    Path(__file__).resolve().parents[2] / "migrations/versions/0043_mask_origin_header_values.py"
)
# Fake values only, built at runtime so no scanner mistakes them for real ones.
LEAK = "not-real-" + "0043"
CONFIG = {
    "id": "E2EXAMPLE",
    "origins": [
        {
            "Id": "alb",
            "DomainName": "app.example.com",
            "CustomHeaders": {
                "Quantity": 2,
                "Items": [
                    {"HeaderName": "X-Origin-Verify", "HeaderValue": LEAK},
                    {"HeaderName": "X-Empty", "HeaderValue": ""},
                ],
            },
        }
    ],
}


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0043", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "key", ["HeaderValue", "header_value", "HeaderName", "Value", "Header", "headers"]
)
def test_the_frozen_rule_agrees_with_redaction_today(key: str) -> None:
    # The migration masks only header values; every key it masks, redaction masks too.
    if _migration().is_header_value(key):
        assert is_secret_key(key)


def test_the_frozen_masking_matches_redaction_today() -> None:
    assert _migration().mask_header_values(CONFIG) == redact(CONFIG)


def _insert(conn, config: dict, hash_byte: bytes) -> int:  # type: ignore[no-untyped-def]
    return int(
        conn.execute(
            text(
                "INSERT INTO resource_config (config_hash, config, created_on) "
                "VALUES (:h, CAST(:c AS jsonb), :d) RETURNING id"
            ),
            {"h": hash_byte * 32, "c": json.dumps(config), "d": date(2026, 11, 5)},
        ).scalar_one()
    )


def test_stored_header_values_are_masked_and_nothing_else_changes(migrated: Engine) -> None:
    # One transaction, rolled back: the schema tests expect empty tables.
    with migrated.connect() as conn, conn.begin() as tx:
        distribution = _insert(conn, CONFIG, b"d")
        other = _insert(conn, {"stage": "prod", "Value": "DENY"}, b"o")
        migration = _migration()
        changed = migration.remask_stored(conn)
        again = migration.remask_stored(conn)
        stored, stored_hash = conn.execute(
            text("SELECT config, config_hash FROM resource_config WHERE id = :i"),
            {"i": distribution},
        ).one()
        untouched = conn.execute(
            text("SELECT config FROM resource_config WHERE id = :i"), {"i": other}
        ).scalar_one()
        tx.rollback()

    assert changed == 1 and again == 0
    assert LEAK not in json.dumps(stored) and bytes(stored_hash) == b"d" * 32
    headers = stored["origins"][0]["CustomHeaders"]["Items"]
    assert headers == [
        {"HeaderName": "X-Origin-Verify", "HeaderValue": "********"},
        {"HeaderName": "X-Empty", "HeaderValue": ""},  # none set stays none set
    ]
    assert stored["origins"][0]["DomainName"] == "app.example.com"
    assert untouched == {"stage": "prod", "Value": "DENY"}
