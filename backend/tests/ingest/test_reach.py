"""CloudFox's public endpoints, checked against Argus's internet rules (ADR-0035).

argus_v10: CloudFox reported an ELBv2 "reachable from the internet on port 443" whose security
groups admit specific addresses only. The finding stays; its `reach` says what Argus found."""

from datetime import date

import pytest
from sqlalchemy import Engine, text
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import TOOL_ORDER, FilesystemRawStore
from argus.findings import PROWLER_EXPOSURE_CHECKS
from argus.relationships import owners_of_hosts

pytestmark = pytest.mark.db
DAY = date(2026, 10, 9)


def _reach(owner: Engine) -> dict[str, str | None]:
    return {name: reach for name, (reach, _) in _verdicts(owner).items()}


def _verdicts(owner: Engine) -> dict[str, tuple[str | None, str | None]]:
    with owner.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT resource_uid, reach, reach_reason FROM finding "
                "WHERE check_id = 'cloudfox_public_endpoint' AND resource_uid LIKE '%-alb/%'"
            )
        ).all()
    return {r.resource_uid.split("/")[-2]: (r.reach, r.reach_reason) for r in rows}


def test_cloudfox_public_endpoints_carry_what_argus_found(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)  # seed 0: the prod profile
    for tool in TOOL_ORDER:
        run_tool(worker, store, target, tool, DAY)
    assert _reach(owner) == {"prod-edge-alb": "confirmed", "prod-admin-alb": "restricted"}
    # Why, as the door says it (ADR-0035, sixth amendment); a reachable door needs no reason.
    assert _verdicts(owner) == {
        "prod-edge-alb": ("confirmed", None),
        "prod-admin-alb": ("restricted", "sg_no_public_source"),
    }
    # A later Steampipe run checks them again (its rules may have changed what is reachable).
    run_tool(worker, store, target, "steampipe", DAY)
    assert _reach(owner) == {"prod-edge-alb": "confirmed", "prod-admin-alb": "restricted"}
    with owner.connect() as conn:
        others = conn.execute(
            text(
                "SELECT count(*) FROM finding WHERE reach IS NOT NULL "
                "AND check_id <> ALL(CAST(:checked AS text[]))"
            ),
            {"checked": ["cloudfox_public_endpoint", *PROWLER_EXPOSURE_CHECKS]},
        ).scalar_one()
    assert others == 0


def test_an_address_joins_the_inventory_through_the_host_index(
    owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """CloudFox network-ports names hosts by address (argus_v12): the instance that holds one
    is found the way the rules find it; an address nobody holds is not guessed."""
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    with owner.connect() as conn:
        uid, address = conn.execute(
            text("""
                SELECT r.resource_uid, c.config ->> 'public_ip_address'
                FROM resource r
                JOIN resource_snapshot s ON s.resource_id = r.id AND s.snapshot_date = :d
                JOIN resource_config c ON c.id = s.config_id
                WHERE r.connection_id = :c AND r.type = 'aws_ec2_instance'
                  AND c.config ->> 'public_ip_address' IS NOT NULL
                ORDER BY r.resource_uid LIMIT 1
            """),
            {"d": DAY, "c": target.connection_id},
        ).one()
        found = owners_of_hosts(
            conn, connection_id=target.connection_id, day=DAY, hosts=[address, "192.0.2.250"]
        )
    assert found == {address: uid}
