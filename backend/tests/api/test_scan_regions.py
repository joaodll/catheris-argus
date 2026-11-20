"""Regions are chosen per schedule and per Run now (owner, 2026-11-19), from the pinned tools'
list. A schedule's runs, a Run now's runs and a failed run's retry each scan the regions they
were asked for, and the worker passes them to the tool.

The API runs as argus_api and the worker as argus_worker, so both roles' grants are proven."""

import re
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.api.conftest import csrf
from tests.ingest.conftest import RULES_DIR, make_demo

from argus.collection import CollectOptions, aws_regions
from argus.core.rawstore import FilesystemRawStore
from argus.scheduling import maintenance, runner

pytestmark = pytest.mark.db
REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")


def _next_hour() -> datetime:
    return (datetime.now(UTC) + timedelta(hours=2)).replace(minute=0, second=0, microsecond=0)


def _requests(owner: Engine) -> list[Any]:
    with owner.connect() as conn:
        return list(
            conn.execute(
                text("SELECT tool, status, reason, aws_regions FROM run_request ORDER BY id")
            ).all()
        )


def test_the_region_list_is_the_pinned_commercial_partition(signed_in: TestClient) -> None:
    listed = signed_in.get("/api/v1/schedules/aws-regions")
    assert listed.status_code == 200, listed.text
    regions = listed.json()["regions"]
    assert regions == sorted(aws_regions()) and len(regions) >= 30
    assert all(REGION.match(r) for r in regions)
    assert "us-east-1" in regions and "eu-west-1" in regions
    # Other partitions need other credentials.
    assert not [r for r in regions if r.startswith(("us-gov-", "cn-", "us-iso"))]


def test_a_schedule_keeps_its_regions_and_its_runs_scan_them(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    make_demo(owner)
    at = _next_hour()
    cron = f"0 {at.hour} * * *"
    body = {
        "name": "nightly",
        "tools": ["steampipe", "cloudfox"],
        "cron": cron,
        "aws_regions": ["eu-west-1", "us-east-1", "eu-west-1"],
    }
    created = signed_in.post("/api/v1/schedules", headers=csrf(signed_in), json=body)
    assert created.status_code == 201, created.text
    schedule = created.json()
    assert schedule["aws_regions"] == ["eu-west-1", "us-east-1"]  # each once, in order

    maintenance.maintain(worker, now=at + timedelta(minutes=1))
    assert [(r.tool, list(r.aws_regions)) for r in _requests(owner)] == [
        ("steampipe", ["eu-west-1", "us-east-1"]),
        ("cloudfox", ["eu-west-1", "us-east-1"]),  # kept; CloudFox scans every region anyway
    ]

    # An edit applies to the runs still queued, as argus_api.
    edited = signed_in.put(
        f"/api/v1/schedules/{schedule['id']}",
        headers=csrf(signed_in),
        json={**body, "aws_regions": ["sa-east-1"]},
    )
    assert edited.status_code == 200, edited.text
    assert [(r.status, list(r.aws_regions)) for r in _requests(owner)] == [
        ("queued", ["sa-east-1"]),
        ("queued", ["sa-east-1"]),
    ]
    # Every region again: the empty list.
    again = signed_in.put(
        f"/api/v1/schedules/{schedule['id']}",
        headers=csrf(signed_in),
        json={k: v for k, v in body.items() if k != "aws_regions"},
    )
    assert again.status_code == 200 and again.json()["aws_regions"] == []
    assert {tuple(r.aws_regions) for r in _requests(owner)} == {()}

    with owner.connect() as conn:
        details = (
            conn.execute(
                text("SELECT detail FROM audit_log WHERE action LIKE 'schedule.%' ORDER BY id")
            )
            .scalars()
            .all()
        )
    assert [d["regions"] for d in details] == [["eu-west-1", "us-east-1"], ["sa-east-1"], "all"]


@pytest.mark.parametrize(
    ("regions", "says"),
    [
        (["us-east-1", "xx-north-9"], "no such AWS region: xx-north-9"),
        (["us-gov-west-1"], "no such AWS region: us-gov-west-1"),
        (["--checks"], None),  # not even a region's shape
        ([f"us-east-{n}" for n in range(1, 10)] * 5, None),  # more than 40
    ],
    ids=["unknown", "other-partition", "flag", "too-many"],
)
def test_an_unknown_region_is_refused(
    signed_in: TestClient, owner: Engine, regions: list[str], says: str | None
) -> None:
    target = make_demo(owner)
    schedule = signed_in.post(
        "/api/v1/schedules",
        headers=csrf(signed_in),
        json={"name": "n", "tools": ["prowler"], "cron": "0 2 * * *", "aws_regions": regions},
    )
    run_now = signed_in.post(
        "/api/v1/run-requests",
        headers=csrf(signed_in),
        json={"connection_ids": [target.connection_id], "aws_regions": regions},
    )
    for response in (schedule, run_now):
        assert response.status_code == 422, response.text
        if says:
            assert response.json()["detail"] == says
    assert _requests(owner) == []
    with owner.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM schedule")).scalar_one() == 0


def test_run_now_scans_the_regions_chosen_and_its_cooldown_covers_only_those(
    signed_in: TestClient, owner: Engine
) -> None:
    target = make_demo(owner)

    def run_now(tools: list[str], regions: list[str] | None = None) -> Any:
        body: dict[str, object] = {"connection_ids": [target.connection_id], "tools": tools}
        if regions is not None:
            body["aws_regions"] = regions
        return signed_in.post("/api/v1/run-requests", headers=csrf(signed_in), json=body)

    first = run_now(["prowler", "cloudfox"], ["us-east-1", "eu-west-1"])
    assert first.status_code == 202, first.text
    assert [(r.tool, list(r.aws_regions)) for r in _requests(owner)] == [
        ("prowler", ["eu-west-1", "us-east-1"]),
        ("cloudfox", ["eu-west-1", "us-east-1"]),
    ]
    # Fewer regions than the queued run: covered. CloudFox scans every region: covered.
    assert run_now(["prowler"], ["us-east-1"]).status_code == 409
    assert run_now(["cloudfox"], ["sa-east-1"]).status_code == 409
    # A region the queued run does not scan, or every region: queued.
    other = run_now(["prowler"], ["sa-east-1"])
    assert other.status_code == 202, other.text
    every = run_now(["prowler"])
    assert every.status_code == 202, every.text
    # Now every region is queued: nothing more for Prowler.
    assert run_now(["prowler"], ["ap-south-1"]).status_code == 409

    with owner.connect() as conn:
        details = (
            conn.execute(
                text("SELECT detail FROM audit_log WHERE action = 'run.request' ORDER BY id")
            )
            .scalars()
            .all()
        )
    assert [d["regions"] for d in details] == [["eu-west-1", "us-east-1"], ["sa-east-1"], "all"]


class _Recording:
    """A source that records the options it was given, then fails, so the run is retried."""

    name = "synthetic"

    def __init__(self) -> None:
        self.seen: list[CollectOptions] = []

    def collect(self, *, options: CollectOptions, **_: object) -> None:
        self.seen.append(options)
        raise RuntimeError("tool crashed")


def test_a_claimed_run_and_its_retry_scan_the_regions_asked_for(
    owner: Engine, worker: Engine, store: FilesystemRawStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_demo(owner)
    source = _Recording()
    monkeypatch.setattr(runner, "source_for", lambda kind: source)
    with owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO run_request (connection_id, tool, reason, snapshot_date, not_before, "
                "requested_by, aws_regions) VALUES (:c, 'prowler', 'manual', :d, "
                "now() - interval '1 minute', 'admin', '{ap-south-1,eu-west-1}')"
            ),
            {"c": target.connection_id, "d": date(2026, 10, 2)},
        )
    assert runner.run_once(worker, store=store, rules_dir=RULES_DIR, worker_id="t") == "failed"
    assert [o.aws_regions for o in source.seen] == [("ap-south-1", "eu-west-1")]
    retry = [r for r in _requests(owner) if r.status == "queued"]
    assert [(r.reason, list(r.aws_regions)) for r in retry] == [
        ("retry", ["ap-south-1", "eu-west-1"])
    ]


@pytest.mark.parametrize(
    "regions",
    ["{US-EAST-1}", "{--checks}", "{us-east-1,NULL}"],
    ids=["upper", "flag", "null"],
)
def test_the_database_refuses_what_is_not_a_region(owner: Engine, regions: str) -> None:
    """Whoever writes the row, nothing that could read as a flag reaches a command line."""
    target = make_demo(owner)
    with pytest.raises(Exception, match="run_request_aws_regions"), owner.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO run_request (connection_id, tool, reason, requested_by, aws_regions) "
                "VALUES (:c, 'prowler', 'manual', 'admin', CAST(:r AS text[]))"
            ),
            {"c": target.connection_id, "r": regions},
        )
