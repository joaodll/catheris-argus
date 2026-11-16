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

from argus import attackpaths
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
    assert {(r["through_target"], r["through_step"]) for r in by_kind["items"]} == {(None, None)}


def test_through_says_where_a_route_first_touches_the_resource(
    signed_in: TestClient, evaluated: int
) -> None:
    """Play from the Map's Routes tab opens the first listed target and step that touch the
    resource: compared with each target's own steps, read through the detail."""
    seen, later = 0, 0
    routes = _page(signed_in, **EVERY)["items"]
    # Routes with several listed targets first: their later targets end on resources the
    # first target never touches.
    for route in sorted(routes, key=lambda r: -r["listed_count"])[:8]:
        rid_ = route["id"]
        for seq in range(1, min(route["listed_count"], 3) + 1):
            steps = signed_in.get(f"/api/v1/attack-paths/{rid_}", params={"target": seq}).json()
            for n, step in enumerate(steps["steps"], start=1):
                for rid in {step["source"]["resource_id"], step["target"]["resource_id"]} - {None}:
                    row = next(
                        r
                        for r in _page(signed_in, through=rid, **EVERY)["items"]
                        if r["id"] == rid_
                    )
                    at, first = row["through_target"], row["through_step"]
                    # Never later than where this loop found it, and that step touches it.
                    assert (at, first) <= (seq, n)
                    touched = signed_in.get(
                        f"/api/v1/attack-paths/{rid_}", params={"target": at}
                    ).json()["steps"][first - 1]
                    assert rid in {
                        touched["source"]["resource_id"],
                        touched["target"]["resource_id"],
                    }
                    seen += 1
                    later += at > 1
    assert seen and later, "the estate should have a resource first met on a later target"


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
    for path in ("", "/facets", "/evaluation", "/1"):
        assert client.get(f"/api/v1/attack-paths{path}").status_code == 401, path


def test_a_target_past_the_listed_ones_is_not_found(signed_in: TestClient, evaluated: int) -> None:
    route = _page(signed_in, **EVERY)["items"][0]
    over = signed_in.get(
        f"/api/v1/attack-paths/{route['id']}", params={"target": route["listed_count"] + 1}
    )
    assert over.status_code == 404


def test_a_step_shows_the_facts_its_resource_has_on_the_security_map(
    signed_in: TestClient, evaluated: int
) -> None:
    seen = 0
    for route in _page(signed_in, **EVERY)["items"]:
        detail = signed_in.get(f"/api/v1/attack-paths/{route['id']}").json()
        for step in detail["steps"]:
            for node in (step["source"], step["target"]):
                if node["resource_id"] is None:
                    assert node["facts"] is None, node
                    continue
                facts = node["facts"]
                assert facts is not None and facts["misconfigurations"] is not None, node
                sheet = signed_in.get(f"/api/v1/resources/{node['resource_id']}").json()
                assert facts["misconfigurations"]["open"] == sum(sheet["open_by_severity"].values())
                seen += 1
    assert seen


def test_data_through_is_over_the_chosen_connection(signed_in: TestClient, evaluated: int) -> None:
    assert _page(signed_in, connection_id=evaluated)["data_through"] is not None
    assert _page(signed_in, connection_id=evaluated + 99)["data_through"] is None


def test_the_evaluation_says_when_the_last_one_failed_and_why(
    signed_in: TestClient, evaluated: int, owner: Engine
) -> None:
    done = signed_in.get("/api/v1/attack-paths/evaluation").json()
    assert done["evaluated_at"] is not None and done["failed_at"] is None and done["error"] is None
    with owner.begin() as conn:
        eid = attackpaths.start(conn, digest=b"x", newest_load_at=None)
        attackpaths.fail(conn, eid, "boom: password=hunter2")
    failed = signed_in.get("/api/v1/attack-paths/evaluation").json()
    assert failed["failed_at"] is not None and failed["evaluated_at"] == done["evaluated_at"]
    assert failed["error"].startswith("boom") and "hunter2" not in failed["error"]
    # The list carries the same state, without the error.
    listed = _page(signed_in)["evaluation"]
    assert listed["failed_at"] == failed["failed_at"] and "error" not in listed


def test_the_evaluation_before_any_is_empty(signed_in: TestClient, estate: int) -> None:
    body = signed_in.get("/api/v1/attack-paths/evaluation").json()
    assert body == {
        "evaluated_at": None, "covered_through": None, "failed_at": None, "behind": False,
        "error": None,
    }  # fmt: skip
