"""The Tag filter (migration 0051): Misconfigurations, Vulnerabilities and reports narrowed to the
findings whose resource carries a tag. Values of one name are OR, names are AND; a masked value
is never an option; a tag removed in the cloud stops matching at the next load."""

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.api.conftest import csrf
from tests.ingest.conftest import make_demo, run_tool

from argus import findings, reports
from argus.collection import CollectTarget, FilesystemRawStore
from argus.core.config import get_settings
from argus.core.redaction import REDACTED
from argus.inventory import InventoryBatch, InventoryResource, load_inventory

pytestmark = pytest.mark.db

DAY = date(2026, 10, 2)


def _tag(key: str, value: str) -> str:
    return json.dumps([key, value])


def _get(client: TestClient, path: str, **params: Any) -> dict[str, Any]:
    response = client.get(path, params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


@pytest.fixture
def demo_target(owner: Engine, worker: Engine, store: FilesystemRawStore) -> CollectTarget:
    target = make_demo(owner)
    for tool in ("steampipe", "prowler", "vulnerabilities"):
        run_tool(worker, store, target, tool, DAY)
    return target


@pytest.fixture
def demo(demo_target: CollectTarget) -> int:
    return demo_target.connection_id


def _expected(owner: Engine, tools: list[str], wanted: dict[str, list[str]]) -> int:
    """Open findings of these tools whose resource carries every name with one of its values,
    counted from resource.tags directly."""
    clauses = " AND ".join(
        f"r.tags ->> CAST(:k{i} AS text) = ANY(CAST(:v{i} AS text[]))" for i in range(len(wanted))
    )
    params: dict[str, Any] = {"t": tools}
    for i, (key, values) in enumerate(wanted.items()):
        params[f"k{i}"], params[f"v{i}"] = key, values
    with owner.connect() as conn:
        return int(
            conn.execute(
                text(f"""
                SELECT count(*) FROM finding f JOIN resource r ON r.id = f.resource_id
                WHERE f.tool = ANY(CAST(:t AS text[])) AND f.state IN ('open', 'reopened')
                  AND {clauses}
            """),  # noqa: S608 - test-built placeholders only
                params,
            ).scalar_one()
        )


def test_the_tag_filter_matches_its_resources_tags(
    signed_in: TestClient, owner: Engine, demo: int
) -> None:
    facets = _get(signed_in, "/api/v1/findings/facets")
    keys = {t["key"]: t["listed"] for t in facets["tags"]}
    assert {"Environment", "Owner", "Name"} <= set(keys)
    environments = _get(signed_in, "/api/v1/findings/tag-values", key="Environment")["values"]
    assert environments
    owners = _get(signed_in, "/api/v1/findings/tag-values", key="Owner")["values"]
    assert len(owners) >= 2

    env = environments[0]
    one = _get(signed_in, "/api/v1/findings", tag=[_tag("Environment", env)], limit=1)
    assert one["total"] == _expected(owner, ["prowler", "cloudfox"], {"Environment": [env]}) > 0

    # Two values of one name: either matches.
    either = [owners[0], owners[1]]
    both = _get(signed_in, "/api/v1/findings", tag=[_tag("Owner", o) for o in either], limit=1)
    assert both["total"] == _expected(owner, ["prowler", "cloudfox"], {"Owner": either})
    first = _get(signed_in, "/api/v1/findings", tag=[_tag("Owner", owners[0])], limit=1)
    assert both["total"] >= first["total"]

    # Two names: both must match.
    anded = _get(
        signed_in,
        "/api/v1/findings",
        tag=[_tag("Environment", env), _tag("Owner", owners[0])],
        limit=1,
    )
    assert anded["total"] == _expected(
        owner, ["prowler", "cloudfox"], {"Environment": [env], "Owner": [owners[0]]}
    )
    assert anded["total"] <= first["total"]

    none = _get(signed_in, "/api/v1/findings", tag=[_tag("Environment", "no-such")], limit=1)
    assert none["total"] == 0

    vulnerabilities = _get(
        signed_in, "/api/v1/vulnerabilities", tag=[_tag("Environment", env)], limit=1
    )
    assert vulnerabilities["total"] == _expected(owner, ["vulnerabilities"], {"Environment": [env]})
    assert _get(signed_in, "/api/v1/vulnerabilities/facets")["tags"]
    assert _get(signed_in, "/api/v1/vulnerabilities/tag-values", key="Environment")["values"]

    narrowed = _get(signed_in, "/api/v1/findings/tag-values", key="Owner", q=owners[0][-3:])
    assert owners[0] in narrowed["values"]


@pytest.mark.parametrize(
    "value",
    ["Team=payments", '["only-one"]', '["k", 1]', json.dumps(["", "v"]), _tag("k" * 129, "v")],
    ids=["no-json", "one-item", "not-text", "empty-name", "long-name"],
)
def test_a_malformed_tag_is_refused(signed_in: TestClient, value: str) -> None:
    response = signed_in.get("/api/v1/findings", params={"tag": [value]})
    assert response.status_code == 422


def test_a_masked_value_is_never_an_option(signed_in: TestClient, owner: Engine, demo: int) -> None:
    with owner.begin() as conn:
        resource_id = conn.execute(
            text(
                "SELECT resource_id FROM finding "
                "WHERE tool = 'prowler' AND resource_id IS NOT NULL LIMIT 1"
            )
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO resource_tag (resource_id, key, value) VALUES (:r, 'DbPassword', :m)"
            ),
            {"r": resource_id, "m": REDACTED},
        )
        conn.execute(
            text(
                "UPDATE resource_tag SET value = 'x-' || :m "
                "WHERE resource_id = :r AND key = 'Owner'"
            ),
            {"r": resource_id, "m": REDACTED},
        )
        findings.refresh_tag_facets(conn, connection_id=demo)
    keys = {t["key"] for t in _get(signed_in, "/api/v1/findings/facets")["tags"]}
    assert "DbPassword" not in keys
    owners = _get(signed_in, "/api/v1/findings/tag-values", key="Owner")["values"]
    assert owners and not any(REDACTED in v for v in owners)


def _resource(uid: str, tags: dict[str, str]) -> InventoryResource:
    return InventoryResource(
        uid=uid,
        type="aws_s3_bucket",
        region="us-east-1",
        native_id=uid.rsplit(":", 1)[-1],
        name=None,
        vpc_id=None,
        tags=tags,
        config={},
        config_hash=bytes(32),
    )


def test_a_removed_tag_stops_matching_at_the_next_load(owner: Engine, worker: Engine) -> None:
    target = make_demo(owner)
    uid = "arn:aws:s3:::argus-tag-test"

    def load(tags: dict[str, str], day: date) -> None:
        batch = InventoryBatch(
            resources=[_resource(uid, tags)], tables_seen=frozenset(), complete=False
        )
        with worker.begin() as conn:
            load_inventory(conn, batch=batch, connection_id=target.connection_id, day=day)

    def stored() -> dict[str, str]:
        with owner.connect() as conn:
            rows = conn.execute(
                text("""
                SELECT rt.key, rt.value
                FROM resource_tag rt JOIN resource r ON r.id = rt.resource_id
                WHERE r.resource_uid = :u
            """),
                {"u": uid},
            )
            return {r.key: r.value for r in rows}

    load({"Team": "payments", "Stage": "beta"}, DAY)
    assert stored() == {"Team": "payments", "Stage": "beta"}
    load({"Team": "billing"}, date(2026, 10, 3))
    assert stored() == {"Team": "billing"}
    load({}, date(2026, 10, 4))
    assert stored() == {}


def test_a_report_keeps_its_tag_filter(
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    demo: int,
) -> None:
    root = tmp_path / "reports-root"
    root.mkdir()
    monkeypatch.setenv("ARGUS_REPORTS_ROOT", str(root))
    get_settings.cache_clear()
    env = _get(signed_in, "/api/v1/findings/tag-values", key="Environment")["values"][0]
    tag = [_tag("Environment", env)]
    asked = signed_in.post(
        "/api/v1/reports",
        json={"kind": "misconfigurations", "filters": {"tag": tag}},
        headers=csrf(signed_in),
    )
    assert asked.status_code == 202, asked.text
    report_id = asked.json()["id"]
    stored = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert stored["filters"]["tags"] == [["Environment", [env]]]
    assert reports.build_pending(worker, store=reports.LocalReportStore(root))
    built = signed_in.get(f"/api/v1/reports/{report_id}").json()
    assert built["status"] == "ready", built
    listed = _get(signed_in, "/api/v1/findings", tag=tag, limit=1)
    assert built["row_count"] == listed["total"] > 0

    # More than the stored filters can hold: refused with a sentence, never a constraint error.
    many = [_tag(f"{i:03d}" + "k" * 125, "v" * 256) for i in range(50)]
    refused = signed_in.post(
        "/api/v1/reports",
        json={"kind": "misconfigurations", "filters": {"tag": many}},
        headers=csrf(signed_in),
    )
    assert refused.status_code == 422
    assert "too many filters" in refused.text


def test_values_past_the_listed_limit_say_there_are_more(
    signed_in: TestClient, owner: Engine, demo: int
) -> None:
    """Each connection and tool lists up to 500 values; together they can pass it."""
    with owner.begin() as conn:
        for tool, start in (("prowler", 0), ("cloudfox", 300)):
            conn.execute(
                text(
                    "INSERT INTO finding_tag_key (connection_id, tool, key, listed) "
                    "VALUES (:c, :t, 'Wide', true)"
                ),
                {"c": demo, "t": tool},
            )
            conn.execute(
                text("""
                INSERT INTO finding_tag_value (connection_id, tool, key, value)
                SELECT :c, :t, 'Wide', 'v-' || lpad(g::text, 4, '0')
                FROM generate_series(:s, :s + 299) g
            """),
                {"c": demo, "t": tool, "s": start},
            )
    wide = _get(signed_in, "/api/v1/findings/tag-values", key="Wide")
    assert len(wide["values"]) == 500 and wide["more"]
    narrowed = _get(signed_in, "/api/v1/findings/tag-values", key="Wide", q="v-059")
    assert narrowed["values"] == [f"v-059{i}" for i in range(10)] and not narrowed["more"]
    assert not _get(signed_in, "/api/v1/findings/tag-values", key="Environment")["more"]


def test_a_steampipe_load_rebuilds_the_options_and_a_removed_tag_leaves_them(
    signed_in: TestClient,
    owner: Engine,
    worker: Engine,
    store: FilesystemRawStore,
    demo_target: CollectTarget,
) -> None:
    demo = demo_target.connection_id
    with owner.begin() as conn:
        conn.execute(text("DELETE FROM finding_tag_key WHERE connection_id = :c"), {"c": demo})
    assert _get(signed_in, "/api/v1/findings/facets")["tags"] == []
    with owner.connect() as conn:
        row = conn.execute(
            text("""
            SELECT r.resource_uid, r.type, r.region, r.native_id FROM finding f
            JOIN resource r ON r.id = f.resource_id
            WHERE f.connection_id = :c AND f.tool = 'prowler' AND f.state IN ('open', 'reopened')
            ORDER BY f.id LIMIT 1
        """),
            {"c": demo},
        ).one()
    run_tool(worker, store, demo_target, "steampipe", date(2026, 10, 3))  # the next day
    assert {"Environment", "Owner"} <= {
        t["key"] for t in _get(signed_in, "/api/v1/findings/facets")["tags"]
    }

    def load(tags: dict[str, str], day: date) -> None:
        resource = InventoryResource(
            uid=row.resource_uid,
            type=row.type,
            region=row.region,
            native_id=row.native_id,
            name=None,
            vpc_id=None,
            tags=tags,
            config={},
            config_hash=bytes(32),
        )
        batch = InventoryBatch(resources=[resource], tables_seen=frozenset(), complete=False)
        with worker.begin() as conn:
            load_inventory(conn, batch=batch, connection_id=demo, day=day)
            findings.refresh_tag_facets(conn, connection_id=demo)

    load({"Probe": "x1"}, date(2026, 10, 4))
    assert _get(signed_in, "/api/v1/findings/tag-values", key="Probe")["values"] == ["x1"]
    assert _get(signed_in, "/api/v1/findings", tag=[_tag("Probe", "x1")], limit=1)["total"] > 0
    load({}, date(2026, 10, 5))
    assert "Probe" not in {t["key"] for t in _get(signed_in, "/api/v1/findings/facets")["tags"]}
    assert _get(signed_in, "/api/v1/findings", tag=[_tag("Probe", "x1")], limit=1)["total"] == 0
