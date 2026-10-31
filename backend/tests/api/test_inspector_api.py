"""Inspector's CVEs on the API (ADR-0042): the Resources list's Vulnerabilities cell and
filter, the resource's Inspector section, and the vulnerability on a finding."""

from datetime import date
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine
from tests.ingest.conftest import make_demo, run_tool

from argus.collection import FilesystemRawStore

DAY = date(2026, 10, 2)


def test_resources_show_vulnerabilities_and_filter_by_them(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    run_tool(worker, store, target, "inspector", DAY)

    def page(**params: Any) -> list[dict[str, Any]]:
        response = signed_in.get("/api/v1/resources", params={"limit": 200, **params})
        assert response.status_code == 200, response.text
        items: list[dict[str, Any]] = response.json()["items"]
        return items

    every = page()
    instances = [r for r in every if r["type"] == "aws_ec2_instance"]
    buckets = [r for r in every if r["type"] == "aws_s3_bucket"]
    assert instances and all(r["vulnerabilities"] is not None for r in instances)
    assert buckets and all(r["vulnerabilities"] is None for r in buckets)  # not scanned type
    assert any(not r["vulnerabilities"]["scanned"] for r in instances)
    exploitable = page(vulnerabilities="exploitable")
    assert exploitable and all(r["vulnerabilities"]["exploitable"] > 0 for r in exploitable)
    high = page(vulnerabilities="high")
    assert all(r["vulnerabilities"]["worst"] in ("critical", "high") for r in high)
    assert signed_in.get("/api/v1/resources", params={"vulnerabilities": "x"}).status_code == 422

    worst = max(exploitable, key=lambda r: r["vulnerabilities"]["open"])
    detail = signed_in.get(f"/api/v1/resources/{worst['id']}").json()
    section = detail["inspector"]
    assert detail["scanned"]["inspector"] == DAY.isoformat()
    assert sum(section["by_severity"].values()) == worst["vulnerabilities"]["open"]
    assert 0 < len(section["top"]) <= 5 and section["coverage"]
    top = section["top"][0]["vulnerability"]
    assert top["finding_type"] in ("PACKAGE_VULNERABILITY", "CODE_VULNERABILITY")
    bucket = signed_in.get(f"/api/v1/resources/{buckets[0]['id']}").json()
    assert bucket["inspector"] is None


def test_findings_list_and_detail_carry_the_vulnerability(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    run_tool(worker, store, target, "prowler", DAY)
    run_tool(worker, store, target, "inspector", DAY)
    found = signed_in.get("/api/v1/findings", params={"tool": "inspector", "limit": 50}).json()[
        "items"
    ]
    assert found and all(f["vulnerability"] is not None for f in found)
    prowler = signed_in.get("/api/v1/findings", params={"tool": "prowler", "limit": 5}).json()
    assert all(f["vulnerability"] is None for f in prowler["items"])
    package = next(f for f in found if f["vulnerability"]["vulnerability_id"])
    detail = signed_in.get(f"/api/v1/findings/{package['id']}").json()
    assert detail["vulnerability"]["vulnerability_id"] == package["check_id"]
    assert detail["description"] and detail["links"][0].startswith("https://nvd.nist.gov/")
