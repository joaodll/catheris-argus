"""Investigate -> Attack paths (ADR-0052): the stored routes, read by index, every role.

The synthetic estate's routes are worked out once (scheduling.paths, as argus_worker); the API
lists them worst first, hides Latent ones until asked, and shows a route's steps with only the
attributes ROUTE_STEP_ATTRIBUTES allows (§9 M4)."""

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.conftest import RULES_DIR
from tests.ingest.conftest import make_demo, run_tool

from argus.attackpaths import ROUTE_STEP_ATTRIBUTES
from argus.collection import TOOL_ORDER
from argus.core.rawstore import FilesystemRawStore
from argus.scheduling import paths

pytestmark = pytest.mark.db
EVERY = {"cls": ["confirmed", "conditional", "potential", "unknown", "blocked"]}


@pytest.fixture
def estate(owner: Engine, worker: Engine, store: FilesystemRawStore) -> int:
    target = make_demo(owner)
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, datetime.now(UTC).date())
    return target.connection_id


@pytest.fixture
def evaluated(estate: int, worker: Engine) -> int:
    assert paths.run_pending(worker, rules_dir=RULES_DIR)
    return estate


def _page(client: TestClient, **params: Any) -> dict[str, Any]:
    response = client.get("/api/v1/attack-paths", params={"limit": 200, **params})
    assert response.status_code == 200, response.text
    page: dict[str, Any] = response.json()
    return page


def test_before_any_evaluation_the_list_says_so(signed_in: TestClient, estate: int) -> None:
    page = _page(signed_in)
    assert page["items"] == [] and page["evaluation"]["evaluated_at"] is None


def test_routes_are_listed_worst_first_without_latent_ones(
    signed_in: TestClient, evaluated: int
) -> None:
    page = _page(signed_in)
    assert page["items"] and page["data_through"] is not None
    assert {r["worst_class"] for r in page["items"]} <= {
        "confirmed", "conditional", "potential", "unknown"
    }  # fmt: skip
    ranks = ["critical", "high", "medium", "low", "informational"]
    severities = [ranks.index(r["severity"]) for r in page["items"]]
    assert severities == sorted(severities)
    latent = _page(signed_in, cls="blocked")["items"]
    assert latent and {r["worst_class"] for r in latent} == {"blocked"}
    assert page["evaluation"]["behind"] is False
    every = _page(signed_in, **EVERY)
    assert every["total"] == page["total"] + _page(signed_in, cls="blocked")["total"]


def test_filters_by_connection_kind_and_resource_on_a_route(
    signed_in: TestClient, evaluated: int
) -> None:
    facets = signed_in.get("/api/v1/attack-paths/facets").json()
    kind = next(iter(facets["kind"]))
    assert facets["kind_names"][kind]
    by_kind = _page(signed_in, kind=kind, **EVERY)
    assert by_kind["total"] == facets["kind"][kind]
    assert _page(signed_in, connection_id=evaluated, **EVERY)["total"] == sum(
        facets["kind"].values()
    )
    assert _page(signed_in, connection_id=evaluated + 99)["total"] == 0
    route = by_kind["items"][0]
    entry = route["entry"]["resource_id"]
    if entry is not None:
        through = _page(signed_in, through=entry, **EVERY)["items"]
        assert route["id"] in {r["id"] for r in through}


def test_a_route_shows_its_targets_and_steps(signed_in: TestClient, evaluated: int) -> None:
    routes = _page(signed_in, kind="internet-lateral-ssh", **EVERY)["items"]
    route = next(r for r in routes if r["listed_count"] > 1)
    detail = signed_in.get(f"/api/v1/attack-paths/{route['id']}").json()
    assert len(detail["targets"]) == route["listed_count"] and detail["target"] == 1
    assert detail["kind_name"] and detail["remediation"]
    types = [s["type"] for s in detail["steps"]]
    assert types[1] == "FOOTHOLD" and types[-1] == "CAN_CONNECT_TO"
    foothold = detail["steps"][1]
    assert foothold["edge_id"] is None and foothold["reason"].startswith("compromise_")
    second = signed_in.get(f"/api/v1/attack-paths/{route['id']}", params={"target": 2}).json()
    assert (
        second["target"] == 2
        and second["steps"][-1]["target"]["uid"] == second["targets"][1]["target"]["uid"]
    )
    assert signed_in.get("/api/v1/attack-paths/999999").status_code == 404


def test_a_step_shows_only_its_allowed_attributes(
    signed_in: TestClient, evaluated: int, owner: Engine
) -> None:
    with owner.begin() as conn:
        conn.execute(
            text("""UPDATE edge SET attributes = COALESCE(attributes, '{}'::jsonb)
                             || '{"not_listed": "planted"}'::jsonb""")
        )
    for route in _page(signed_in, **EVERY)["items"]:
        detail = signed_in.get(f"/api/v1/attack-paths/{route['id']}").json()
        for step in detail["steps"]:
            assert set(step["attributes"]) <= set(ROUTE_STEP_ATTRIBUTES.get(step["type"], ()))
            assert "planted" not in str(step)


def test_routes_say_when_they_are_behind_the_scans(
    signed_in: TestClient, evaluated: int, owner: Engine
) -> None:
    with owner.begin() as conn:
        conn.execute(text("UPDATE scan_run SET ingested_at = now() + interval '1 hour'"))
    assert _page(signed_in)["evaluation"]["behind"] is True


def test_signing_in_is_required(client: TestClient) -> None:
    assert client.get("/api/v1/attack-paths").status_code == 401


def test_a_target_past_the_listed_ones_is_not_found(signed_in: TestClient, evaluated: int) -> None:
    route = _page(signed_in, **EVERY)["items"][0]
    over = signed_in.get(
        f"/api/v1/attack-paths/{route['id']}", params={"target": route["listed_count"] + 1}
    )
    assert over.status_code == 404
