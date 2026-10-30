"""Posture -> Compliance (docs/ui/screens.md E9, E10): every framework, one framework's history,
its accounts month by month, and its requirements, for one connection or all."""

from datetime import UTC, date, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import CollectTarget
from argus.core.rawstore import FilesystemRawStore

pytestmark = pytest.mark.db
CIS = "cis_6.0_aws"


@pytest.fixture
def estate(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> tuple[list[CollectTarget], list[date]]:
    """Two Demo connections, Prowler 40 days ago and today: two different months. Not seed 1,
    the staging profile: its Prowler fails on purpose every 47th day."""
    targets = [make_demo(owner, seed) for seed in (0, 2)]
    today = datetime.now(UTC).date()
    days = [today - timedelta(days=40), today]
    for day in days:
        for target in targets:
            assert run_tool(worker, store, target, "prowler", day).status == "complete"
    return targets, days


def _get(client: TestClient, path: str, **params: object) -> dict:  # type: ignore[type-arg]
    response = client.get(f"/api/v1{path}", params=params)
    assert response.status_code == 200, response.text
    return response.json()  # type: ignore[no-any-return]


def test_the_list_names_scores_and_sorts_every_framework(
    signed_in: TestClient, estate: tuple[list[CollectTarget], list[date]]
) -> None:
    _, days = estate
    body = _get(signed_in, "/compliance")
    assert body["total"] == 2 and body["data_through"] == days[-1].isoformat()
    by_key = {f["framework"]: f for f in body["items"]}
    cis = by_key[CIS]
    assert cis["name"] and cis["name"].startswith("CIS") and cis["family"] == "CIS"
    assert cis["version"] == "6.0" and cis["provider"] == "aws"
    assert 0 <= cis["score"] <= 100 and len(cis["trend"]) == 2
    assert cis["change"] == pytest.approx(cis["trend"][-1]["score"] - cis["trend"][0]["score"])
    assert sum(cis["requirements"].values()) > 0 and set(cis["requirements"]) == {
        "pass",
        "fail",
        "manual",
    }

    scores = [f["score"] for f in body["items"]]
    assert scores == sorted(scores)  # lowest first by default
    desc = _get(signed_in, "/compliance", order="score_desc")["items"]
    assert [f["score"] for f in desc] == sorted(scores, reverse=True)

    found = _get(signed_in, "/compliance", q="threatscore")
    assert [f["framework"] for f in found["items"]] == ["prowler_threatscore_aws"]
    page = _get(signed_in, "/compliance", limit=1, offset=1)
    assert page["total"] == 2 and len(page["items"]) == 1


def test_the_list_filters_by_the_frameworks_provider(
    signed_in: TestClient, estate: tuple[list[CollectTarget], list[date]]
) -> None:
    aws = _get(signed_in, "/compliance", provider="aws")
    assert aws["total"] == 2 and {f["provider"] for f in aws["items"]} == {"aws"}
    either = signed_in.get("/api/v1/compliance?provider=gcp&provider=aws").json()
    assert either["total"] == 2
    gcp = _get(signed_in, "/compliance", provider="gcp")
    assert gcp["total"] == 0 and gcp["items"] == []
    assert signed_in.get("/api/v1/compliance", params={"provider": "azure"}).status_code == 422


def test_a_framework_has_its_history_and_month_table(
    signed_in: TestClient, estate: tuple[list[CollectTarget], list[date]]
) -> None:
    targets, days = estate
    detail = _get(signed_in, f"/compliance/{CIS}")
    assert detail["range"] == "6M" and detail["data_through"] == days[-1].isoformat()
    assert [p["date"] for p in detail["series"]] == [d.isoformat() for d in days]
    months = detail["month_table"]
    assert len(months) == 6 and months[-1]["month"] == days[-1].strftime("%Y-%m")
    assert sum(m["score"] is not None for m in months) == 2  # never a 0 for a month with no scan

    one = _get(signed_in, f"/compliance/{CIS}", connection_id=targets[0].connection_id, range="1M")
    assert [p["date"] for p in one["series"]] == [days[-1].isoformat()]

    assert signed_in.get(f"/api/v1/compliance/{CIS}x").status_code == 404
    assert signed_in.get("/api/v1/compliance/cis%20aws").status_code == 422


def test_accounts_month_over_month(
    signed_in: TestClient, estate: tuple[list[CollectTarget], list[date]]
) -> None:
    targets, _ = estate
    body = _get(signed_in, f"/compliance/{CIS}/accounts")
    assert body["total"] == 2
    assert {a["connection_id"] for a in body["items"]} == {t.connection_id for t in targets}
    scores = [a["score"] for a in body["items"]]
    assert scores == sorted(scores)
    for account in body["items"]:
        assert account["account_id"] and len(account["months"]) == 6
        scanned = [m for m in account["months"] if m["score"] is not None]
        assert len(scanned) == 2
        assert scanned[-1]["change"] is None or scanned[-1]["change"] == pytest.approx(
            scanned[-1]["score"] - scanned[0]["score"]
        )


def test_requirements_for_one_connection_and_for_all(
    signed_in: TestClient, estate: tuple[list[CollectTarget], list[date]]
) -> None:
    targets, days = estate
    path = f"/compliance/{CIS}/requirements"
    every = _get(signed_in, path, limit=200)
    assert every["data_through"] == days[-1].isoformat() and every["total"] == 63
    assert all(r["assessed_connections"] == 2 for r in every["items"])
    for r in every["items"]:
        assert (r["status"] == "FAIL") == (r["fail_connections"] > 0)

    one = _get(signed_in, path, limit=200, connection_id=targets[0].connection_id)
    assert one["total"] == 63
    assert all(r["fail_connections"] is None for r in one["items"])
    ids = [r["requirement_id"] for r in one["items"]]
    if "1.2" in ids and "1.10" in ids:  # natural order
        assert ids.index("1.2") < ids.index("1.10")

    failing = _get(signed_in, path, limit=200, status="FAIL")
    assert failing["total"] == sum(r["status"] == "FAIL" for r in every["items"])
    first = every["items"][0]["requirement_id"]
    assert first in [r["requirement_id"] for r in _get(signed_in, path, q=first)["items"]]


def test_nothing_before_a_prowler_scan(signed_in: TestClient, owner: Engine) -> None:
    make_demo(owner)
    body = _get(signed_in, "/compliance")
    assert body == {"data_through": None, "items": [], "total": 0}
