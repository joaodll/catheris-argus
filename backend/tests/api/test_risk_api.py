"""Risk (ADR-0049) over HTTP, as the API's role: the tiles are stored counts, and each one is
reproduced by the list filter its link sets."""

from datetime import date
from typing import Any, get_args

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from tests.ingest.conftest import make_demo, run_tool

from argus.api.routes.risk import CombinationId
from argus.collection import TOOL_ORDER, CollectTarget, FilesystemRawStore
from argus.risk import COMBINATIONS

pytestmark = pytest.mark.db
DAY = date(2026, 10, 9)


def _get(client: TestClient, path: str, **params: Any) -> Any:
    response = client.get(f"/api/v1{path}", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _scan(owner: Engine, worker: Engine, store: FilesystemRawStore, seed: int) -> CollectTarget:
    target = make_demo(owner, seed)
    for tool in TOOL_ORDER:
        assert run_tool(worker, store, target, tool, DAY).status in ("complete", "partial")
    return target


def test_the_contract_names_every_combination_in_order(signed_in: TestClient) -> None:
    assert list(get_args(CombinationId)) == [c.id for c in COMBINATIONS]
    listed = _get(signed_in, "/risk/combinations")
    assert [c["id"] for c in listed] == [c.id for c in COMBINATIONS]
    assert all(c["title"] and c["description"] for c in listed)


def test_never_computed_is_not_nothing_at_risk(signed_in: TestClient) -> None:
    summary = _get(signed_in, "/risk/summary")
    assert summary == {
        "computed": False,
        "as_of": None,
        "data_through": None,
        "total": None,
        "tiers": None,
        "combinations": None,
    }
    page = _get(signed_in, "/risk")
    assert page["computed"] is False and page["items"] == [] and page["total"] == 0


@pytest.mark.parametrize("scope", ["one", "all"], ids=["one-connection", "all-connections"])
def test_every_tile_is_reproduced_by_its_list_filter(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore, scope: str
) -> None:
    targets = [_scan(owner, worker, store, seed) for seed in (0, 2)]
    connection_id = targets[0].connection_id if scope == "one" else 0
    scoped = {"connection_id": [connection_id]} if connection_id else {}
    summary = _get(signed_in, "/risk/summary", connection_id=connection_id)
    assert summary["computed"] and summary["data_through"] == DAY.isoformat()
    assert summary["total"] == _get(signed_in, "/risk", limit=1, **scoped)["total"] > 0
    for tier, n in summary["tiers"].items():
        assert _get(signed_in, "/risk", limit=1, tier=[tier], **scoped)["total"] == n
    for combination, n in summary["combinations"].items():
        listed = _get(signed_in, "/risk", limit=1, combination=[combination], **scoped)
        assert listed["total"] == n


def test_a_row_carries_its_facts_and_name(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    _scan(owner, worker, store, 0)
    page = _get(signed_in, "/risk", limit=200)
    assert page["computed"] and page["data_through"] == DAY.isoformat()
    first = page["items"][0]
    assert first["tier"] == "critical" and "reachable-exploitable" in first["combinations"]
    assert first["door"] and first["exploitable_cves"] > 0 and first["name"]
    admin = next(
        r for r in page["items"] if "admin-user-long-lived-credential" in r["combinations"]
    )
    assert admin["resource_type"] == "aws_iam_user" and admin["admin"]
    assert set(admin["credential_kinds"]) <= {"access_key", "console_password_no_mfa"}
    types = _get(signed_in, "/risk/facets")["types"]
    assert types == sorted({r["resource_type"] for r in page["items"]})
    typed = _get(signed_in, "/risk", limit=200, type=["aws_iam_user"])
    assert {r["resource_type"] for r in typed["items"]} == {"aws_iam_user"}
    assert _get(signed_in, "/risk", limit=1, provider=["gcp"])["total"] == 0


@pytest.mark.parametrize(
    "params",
    [{"tier": ["low"]}, {"combination": ["no-such-combination"]}, {"limit": 201}],
    ids=["tier", "combination", "limit"],
)
def test_unknown_values_are_refused(signed_in: TestClient, params: dict[str, Any]) -> None:
    assert signed_in.get("/api/v1/risk", params=params).status_code == 422


def _total(client: TestClient, path: str, **params: Any) -> int:
    return int(_get(client, path, limit=1, **params)["total"])


def test_every_fact_count_is_what_its_list_shows(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """A fact's link (frontend riskFacts.ts) opens a list filtered to the resource with the
    filters Risk counts with: the list must hold exactly that many findings."""
    for seed in (0, 2):
        _scan(owner, worker, store, seed)
    rows = _get(signed_in, "/risk", limit=200)["items"]
    assert rows
    for r in rows:
        resource = {"resource_id": r["resource_id"], "muted": "hide"}
        assert r["exploitable_cves"] == _total(
            signed_in, "/vulnerabilities", exploitable=True, **resource
        ), r
        assert r["high_cves"] == _total(
            signed_in, "/vulnerabilities", severity=["critical", "high"], **resource
        ), r
        failing = {**resource, "status": ["FAIL"]}
        assert r["high_misconfigurations"] == _total(
            signed_in, "/findings", severity=["critical", "high"], **failing
        ), r
        secret = _total(signed_in, "/findings", check_id=["cloudfox_env_var_secret"], **failing)
        assert r["env_secret"] == (secret > 0), r
