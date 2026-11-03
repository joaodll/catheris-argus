"""Every rule against its own fixture: input rows -> exactly the expected edges.

A rule reads the view `r` (resources). Here it is built from the fixture's rows instead of the
tables, so a rule is tested alone: a rule that fires on the wrong rows, or misses the right ones,
fails by name. The engine's tests cover reading the real view;
test_fixture_views_match_the_real_views keeps the two in step.

Fixtures: tests/rules/fixtures/relationships/<rule id>.json. A new rule needs one, with at least
one near-miss that must not match.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Connection, Engine, text

from argus import inventory, relationships
from argus.relationships import load_rules

pytestmark = pytest.mark.db

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

VIEW_COLUMNS = {
    "r": "uid text, type text, native_id text, name text, region text, vpc_id text, config jsonb",
}
FIXTURE_KEYS = {"r": "resources"}


def _fixture(kind: str, rule_id: str) -> dict[str, Any]:
    path = FIXTURES / kind / f"{rule_id}.json"
    assert path.exists(), f"rule {rule_id} has no fixture: add {path.relative_to(FIXTURES.parent)}"
    fixture: dict[str, Any] = json.loads(path.read_text())
    return fixture


def _views(names: str) -> str:
    # View names and column lists are the constants above; fixture rows are bound parameters.
    views = [
        f"{v} AS (SELECT * FROM jsonb_to_recordset(CAST(:{v} AS jsonb)) AS x({VIEW_COLUMNS[v]}))"  # noqa: S608
        for v in names
    ]
    if "r" in names:
        # The host index, ingress and exposure are derived from `r`, as in the engine.
        views.append(relationships.RULE_VIEWS_SQL)
    return "WITH " + ",\n".join(views)


def _run(conn: Connection, names: str, sql: str, fixture: dict[str, Any]) -> list[Any]:
    params = {v: json.dumps(fixture.get(FIXTURE_KEYS[v], [])) for v in names}
    conn.execute(text("SET TRANSACTION READ ONLY"))
    conn.execute(text(relationships.NO_JIT))
    try:
        return list(conn.execute(text(_views(names) + "\n" + sql), params))
    finally:
        conn.rollback()


def test_every_fixture_belongs_to_a_rule() -> None:
    ids = {r.id for r in load_rules(RULES_DIR)}
    fixtures = {p.stem for p in (FIXTURES / "relationships").glob("*.json")}
    assert fixtures == ids, f"fixtures without a rule {fixtures - ids}"


def test_fixture_views_match_the_real_views(migrated: Engine) -> None:
    real = {"r": inventory.RESOURCES_ON_DAY_SQL}
    params = {"connection_id": 0, "resource_day": None}
    with migrated.connect() as conn:
        for view, sql in real.items():
            columns = list(conn.execute(text(f"SELECT * FROM ({sql}) v LIMIT 0"), params).keys())  # noqa: S608
            expected = [c.split()[0] for c in VIEW_COLUMNS[view].split(", ")]
            assert columns == expected, f"view {view}: the fixture columns are out of date"


@pytest.mark.parametrize("rule", load_rules(RULES_DIR), ids=lambda r: r.id)
def test_relationship_rule(rule: relationships.Rule, migrated: Engine) -> None:
    fixture = _fixture("relationships", rule.id)
    with migrated.connect() as conn:
        rows = _run(conn, "r", rule.sql, fixture)
    got = sorted((s, t, json.dumps(a, sort_keys=True)) for s, t, a in rows)
    want = sorted(
        (x["source"], x["target"], json.dumps(x["attributes"], sort_keys=True))
        for x in fixture["expected"]
    )
    assert got == want
