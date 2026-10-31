"""The vulnerabilities tool on the API (ADR-0042): the Resources list's Vulnerabilities cell and
filter, the resource's Vulnerabilities section and its scanner, and the vulnerability on a
finding."""

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
    run_tool(worker, store, target, "vulnerabilities", DAY)

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
    section = detail["vulnerabilities"]
    assert detail["scanned"]["vulnerabilities"] == DAY.isoformat()
    assert sum(section["by_severity"].values()) == worst["vulnerabilities"]["open"]
    assert 0 < len(section["top"]) <= 5 and section["coverage"]
    top = section["top"][0]["vulnerability"]
    assert top["kind"] in ("package", "code") and top["scanner"] == "aws-inspector"
    assert section["scanner"] == "aws-inspector"
    assert {c["scan_type"] for c in section["coverage"]} <= {"package", "code"}
    bucket = signed_in.get(f"/api/v1/resources/{buckets[0]['id']}").json()
    assert bucket["vulnerabilities"] is None


def test_vulnerabilities_list_apart_and_carry_their_facts(
    signed_in: TestClient, owner: Engine, worker: Engine, store: FilesystemRawStore
) -> None:
    """CVEs are listed on /vulnerabilities, never on /findings (Misconfigurations), and a CVE's
    own link is /findings/{id} like any finding's."""
    target = make_demo(owner)
    run_tool(worker, store, target, "steampipe", DAY)
    run_tool(worker, store, target, "prowler", DAY)
    run_tool(worker, store, target, "vulnerabilities", DAY)

    def page(path: str = "/api/v1/vulnerabilities", **params: Any) -> dict[str, Any]:
        response = signed_in.get(path, params={"limit": 200, **params})
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    listed = page()
    found = listed["items"]
    assert found and listed["data_through"] == DAY.isoformat()
    assert {f["tool"] for f in found} == {"vulnerabilities"}
    assert all(f["vulnerability"] is not None for f in found)
    misconfigurations = page("/api/v1/findings")["items"]
    assert misconfigurations and all(f["vulnerability"] is None for f in misconfigurations)
    assert {f["tool"] for f in misconfigurations} == {"prowler"}
    refused = signed_in.get("/api/v1/findings", params={"tool": "vulnerabilities"})
    assert refused.status_code == 422

    exploitable = page(exploitable=True)["items"]
    assert exploitable and all(f["vulnerability"]["exploit_available"] for f in exploitable)
    assert len(exploitable) < len(found)
    fixed = page(fix="available")["items"]
    assert all(f["vulnerability"]["fix_available"] in ("YES", "PARTIAL") for f in fixed)
    unfixed = page(fix="none")["items"]
    assert all(f["vulnerability"]["fix_available"] == "NO" for f in unfixed)
    assert signed_in.get("/api/v1/vulnerabilities", params={"fix": "maybe"}).status_code == 422

    groups = page("/api/v1/vulnerabilities/groups")
    assert groups["items"] and {g["tool"] for g in groups["items"]} == {"vulnerabilities"}
    assert sum(g["findings"] for g in groups["items"]) == listed["total"]
    one_cve = groups["items"][0]["check_id"]
    assert {f["check_id"] for f in page(check_id=one_cve)["items"]} == {one_cve}

    facets = page("/api/v1/vulnerabilities/facets")
    assert set(facets["resource_types"]) <= {"AwsEc2Instance", "AwsLambdaFunction"}
    assert facets["resource_types"] and facets["regions"]
    misconfiguration_checks = page("/api/v1/findings/facets")["checks"]
    assert {c["tool"] for c in misconfiguration_checks} == {"prowler"}
    package = next(f for f in found if f["vulnerability"]["vulnerability_id"])
    detail = signed_in.get(f"/api/v1/findings/{package['id']}").json()
    assert detail["vulnerability"]["vulnerability_id"] == package["check_id"]
    assert detail["description"] and detail["links"][0].startswith("https://nvd.nist.gov/")
