"""Every rule against its own fixture: input rows -> exactly the expected edges, or a path
kind's targets (ADR-0037: the search itself is tested in tests/ingest).

A rule reads views (`r` resources; path kinds also `e` edges, `f` failing findings and `d`
the doors, derived from `e`).
Here those views are built from the fixture's rows instead of the tables, so a rule is tested
alone: a rule that fires on the wrong rows, or misses the right ones, fails by name. The
engines' tests cover reading the real views; test_fixture_views_match_the_real_views keeps the
two in step.

Fixtures: tests/rules/fixtures/<relationships|attack_paths>/<rule id>.json. A new rule needs
one, with at least one near-miss that must not match.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Connection, Engine, text

from argus import findings, inventory, relationships
from argus.attackpaths import DOORS_SQL, load_path_kinds
from argus.relationships import load_rules

pytestmark = pytest.mark.db

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

VIEW_COLUMNS = {
    "r": "uid text, type text, native_id text, name text, region text, vpc_id text, config jsonb",
    "e": "id bigint, source_uid text, target_uid text, type text, origin text, attributes jsonb",
    "f": "resource_uid text, check_id text, severity text",
}
FIXTURE_KEYS = {"r": "resources", "e": "edges", "f": "findings"}


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
    if "e" in names:
        # The doors are derived from `e`, as in the path engine.
        views.append(f"d AS ({DOORS_SQL})")
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
    rule_ids = {
        "relationships": {r.id for r in load_rules(RULES_DIR)},
        "attack_paths": {k.id for k in load_path_kinds(RULES_DIR)},
    }
    for kind, ids in rule_ids.items():
        fixtures = {p.stem for p in (FIXTURES / kind).glob("*.json")}
        assert fixtures == ids, f"{kind}: fixtures without a rule {fixtures - ids}"


def test_fixture_views_match_the_real_views(migrated: Engine) -> None:
    real = {
        "r": inventory.RESOURCES_ON_DAY_SQL,
        "e": relationships.EFFECTIVE_EDGES_SQL,
        "f": findings.FAILING_FINDINGS_SQL,
    }
    params = {"connection_id": 0, "resource_day": None, "rule_day": None, "cloudfox_day": None}
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


@pytest.mark.parametrize("kind", load_path_kinds(RULES_DIR), ids=lambda k: k.id)
def test_path_kind_targets(kind: Any, migrated: Engine) -> None:
    """A path kind's query selects its targets; the search (tests/ingest) finds the paths."""
    fixture = _fixture("attack_paths", kind.id)
    with migrated.connect() as conn:
        rows = _run(conn, "ref", kind.sql, fixture)
    assert sorted(uid for (uid,) in rows) == sorted(fixture["expected"])


# What a path page shows must read as words (the 2026-10-31 review): no ADR, rule version, edge
# type (CAN_ESCALATE_TO), pseudo-node (any:s3) or code span. Those go in the file's comments.
_CODE_WORDS = re.compile(r"ADR-\d|\bVersion \d|\b[A-Z]+_[A-Z_]+\b|\b[a-z]+:[a-z0-9]+\b|`|_[a-z]+_")


@pytest.mark.parametrize("kind", load_path_kinds(RULES_DIR), ids=lambda k: k.id)
def test_path_kind_text_is_plain(kind: Any) -> None:
    for field in (kind.description, kind.remediation):
        assert not _CODE_WORDS.search(field), f"{kind.id}: {_CODE_WORDS.search(field)}"
