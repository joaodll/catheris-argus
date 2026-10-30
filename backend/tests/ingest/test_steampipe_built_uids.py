"""Tables whose uid Argus builds (ADR-0033): API Gateway methods have no ARN, an event source
mapping's `arn` column is its source's ARN, and weighted Route53 records share one akas."""

from pathlib import Path

from tests.ingest.test_steampipe_json_text import ACCOUNT, _run

from argus.inventory import parse_steampipe

QUEUE = f"arn:aws:sqs:us-east-1:{ACCOUNT}:orders"
FUNCTION = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker"
ZONE = "arn:aws:route53:::hostedzone/Z0PUBLIC"


def test_an_api_gateway_method_gets_its_arn_and_keeps_its_integration(tmp_path: Path) -> None:
    integration = {
        "Type": "AWS_PROXY",
        "Uri": f"arn:aws:apigateway:us-east-1:lambda:path/x/functions/{FUNCTION}/invocations",
    }
    run = _run(
        tmp_path,
        {
            "aws_api_gateway_method": [
                {
                    "rest_api_id": "abc123",
                    "resource_id": "r1",
                    "http_method": "GET",
                    "path": "/orders",
                    "method_integration": integration,
                    "partition": "aws",
                    "region": "us-east-1",
                },
                {"rest_api_id": "abc123", "path": "/broken", "region": "us-east-1"},
            ]
        },
    )
    batch = parse_steampipe(run)
    [method] = batch.resources
    assert method.uid == "arn:aws:apigateway:us-east-1::/restapis/abc123/resources/r1/methods/GET"
    assert (method.native_id, method.name) == ("r1", "/orders")
    assert method.config["method_integration"] == integration
    assert batch.skipped == ["aws_api_gateway_method:None"]  # no resource id: reported


def test_an_event_source_mapping_never_takes_its_queues_uid(tmp_path: Path) -> None:
    run = _run(
        tmp_path,
        {
            "aws_sqs_queue": [
                {"queue_arn": QUEUE, "title": "orders", "akas": [QUEUE], "region": "us-east-1"}
            ],
            "aws_lambda_event_source_mapping": [
                {
                    "uuid": "6d1f-01",
                    "arn": QUEUE,  # the plugin's arn column: the event source
                    "function_arn": FUNCTION,
                    "function_name": "worker",
                    "region": "us-east-1",
                    "account_id": ACCOUNT,
                }
            ],
        },
    )
    batch = parse_steampipe(run)
    assert sorted((r.type, r.uid) for r in batch.resources) == [
        (
            "aws_lambda_event_source_mapping",
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:event-source-mapping:6d1f-01",
        ),
        ("aws_sqs_queue", QUEUE),
    ]
    assert batch.skipped == []


def test_weighted_records_keep_one_resource_each(tmp_path: Path) -> None:
    def record(identifier: str | None) -> dict[str, object]:
        row: dict[str, object] = {
            "name": "api.example.com.",
            "type": "A",
            "zone_id": "Z0PUBLIC",
            "akas": [f"{ZONE}/recordset/api.example.com./A"],
            "region": "global",
        }
        if identifier:
            row["set_identifier"] = identifier
        return row

    run = _run(tmp_path, {"aws_route53_record": [record("blue"), record("green"), record(None)]})
    uids = sorted(r.uid for r in parse_steampipe(run).resources)
    base = f"{ZONE}/recordset/api.example.com./A"
    assert uids == [base, f"{base}/blue", f"{base}/green"]


def test_custom_domains_get_their_arn_from_the_name_in_both_api_versions(
    tmp_path: Path,
) -> None:
    # A real run's v2 akas: .../domainname/ with no name, the same for every domain (ADR-0034).
    broken = ["arn:aws:apigateway:us-east-1::/domainname/"]
    run = _run(
        tmp_path,
        {
            "aws_api_gatewayv2_domain_name": [
                {"domain_name": "api.example.com", "region": "us-east-1", "akas": broken},
                {"domain_name": "both.example.com", "region": "us-east-1", "akas": broken},
            ],
            "aws_api_gateway_domain_name": [
                {"domain_name": "both.example.com", "region": "us-east-1"},
            ],
        },
    )
    batch = parse_steampipe(run)
    domains = "arn:aws:apigateway:us-east-1::/domainnames"
    assert sorted((r.uid, r.type) for r in batch.resources) == [
        (f"{domains}/api.example.com", "aws_api_gatewayv2_domain_name"),
        (f"{domains}/both.example.com", "aws_api_gateway_domain_name"),
    ]


def test_aws_owned_prefix_lists_are_not_inventoried(tmp_path: Path) -> None:
    def prefix_list(owner: str, pl: str) -> dict[str, str]:
        return {
            "id": pl,
            "owner_id": owner,
            "arn": f"arn:aws:ec2:us-east-1:{owner}:prefix-list/{pl}",
            "region": "us-east-1",
        }

    run = _run(
        tmp_path,
        {
            "aws_ec2_managed_prefix_list": [
                prefix_list("AWS", "pl-63a5400a"),
                prefix_list(ACCOUNT, "pl-0abc"),
            ]
        },
    )
    [own] = parse_steampipe(run).resources
    assert own.native_id == "pl-0abc"
