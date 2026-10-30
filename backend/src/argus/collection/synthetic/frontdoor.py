"""The front-door chain every synthetic estate carries (ADR-0033), so the Resource map has
something to draw from the internet down to data and identity:

    Route53 app.<zone> -> CloudFront -> { assets bucket, HTTP API -> orders-api function,
                                          edge ALB -> target groups -> function, ECS service }
    Route53 www.<zone> -> edge ALB;  rest.<zone> -> REST API custom domain
    REST API -> orders-api function, the orders queue, a partner webhook (external)
    orders queue -> orders-worker; alerts topic -> orders-worker; nightly rule -> orders-worker
    assets bucket -> thumbnail function;  EKS cluster with a public endpoint and a node group
    orders-api function -> its role -> the orders table and queue (an inline policy)
    orders queue -> pipe -> fulfil state machine -> orders-worker, orders table; a nightly
    schedule -> fulfil; API logs -> Firehose -> assets bucket; a WAF on the edge ALB
    admin ALB: internet-facing, its security group admits one office range (restricted, ADR-0035)

The resources are fixed (they never churn) and named after the profile. Their Steampipe rows
are written here, under attrs["row"], in the column names and shapes of steampipe-plugin-aws
v1.34.0 (JSON columns as the AWS SDK's PascalCase structs); the tables that already have a
builder in steampipe.py keep their attrs. In the prod profile the orders-api role can escalate
to administrator (estate.py), so the chain ends in an attack path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from argus.collection.synthetic.model import Resource, hexid

if TYPE_CHECKING:
    from argus.collection.synthetic.estate import EstateDay

# Tables written from attrs["row"] (steampipe.py writes them as they are).
ROW_TABLES = (
    "aws_route53_zone",
    "aws_route53_record",
    "aws_cloudfront_distribution",
    "aws_api_gateway_rest_api",
    "aws_api_gateway_method",
    "aws_api_gateway_domain_name",
    "aws_api_gatewayv2_api",
    "aws_api_gatewayv2_integration",
    "aws_api_gatewayv2_route",
    "aws_ecs_cluster",
    "aws_ecs_task_definition",
    "aws_ecs_service",
    "aws_eks_cluster",
    "aws_eks_node_group",
    "aws_sqs_queue",
    "aws_dynamodb_table",
    "aws_lambda_event_source_mapping",
    "aws_sns_topic",
    "aws_sns_topic_subscription",
    "aws_eventbridge_rule",
    "aws_wafv2_web_acl",
    "aws_sfn_state_machine",
    "aws_pipes_pipe",
    "aws_scheduler_schedule",
    "aws_kinesis_firehose_delivery_stream",
    "aws_cloudwatch_log_group",
    "aws_cloudwatch_log_subscription_filter",
)
# The API function's role; prefixed with the profile label, like every name here.
ORDERS_API_ROLE = "orders-api-role"


@dataclass
class _Chain:
    """One account's chain while it is built: where it goes, and what is made so far."""

    estate: EstateDay
    created: str

    @property
    def acct(self) -> str:
        return self.estate.account_id

    @property
    def label(self) -> str:
        return self.estate.profile.label

    @property
    def region(self) -> str:
        return self.estate.profile.regions[0]

    def id(self, width: int, *parts: object) -> str:
        return hexid(width, self.acct, "front-door", *parts)

    def arn(self, service: str, resource: str) -> str:
        return f"arn:aws:{service}:{self.region}:{self.acct}:{resource}"

    def add(
        self,
        table: str,
        native_id: str,
        name: str,
        uid: str,
        attrs: dict[str, Any],
        where: str | None = None,
    ) -> Resource:
        resource = Resource(
            table, where or self.region, native_id, name, uid, {**attrs, "created": self.created}
        )
        self.estate.resources.setdefault(table, []).append(resource)
        return resource

    def row(
        self,
        table: str,
        native_id: str,
        name: str,
        uid: str,
        columns: dict[str, Any],
        where: str | None = None,
    ) -> Resource:
        return self.add(table, native_id, name, uid, {"row": columns}, where)


def add_front_door(estate: EstateDay, created: str) -> None:
    c = _Chain(estate, created)
    subnets, web_sg, app_sg, vpc_id = _network(c)
    roles = _roles(c)
    fns = {
        "api": _function(c, "orders-api", roles["api"], subnets, app_sg),
        "worker": _function(c, "orders-worker", roles["worker"], subnets, app_sg),
        "thumbnail": _function(c, "thumbnail", roles["worker"], [], []),
    }
    assets, queue = _data(c, fns)
    table = _orders_table(c, roles["api"], queue)
    alb, listener = _load_balancing(c, fns["api"], subnets, vpc_id)
    _workflows(c, fns, alb, queue, table, assets)
    _containers(c, roles, subnets, web_sg, app_sg, vpc_id)
    http_id = _http_api(c, fns["api"], listener)
    zone_name, domain = _rest_api(c, fns["api"], queue)
    _edge(c, zone_name, domain, assets, http_id, alb)


def _network(c: _Chain) -> tuple[list[str], list[str], list[str], str | None]:
    """(two subnets of one VPC, a web group, an app group, the VPC id) in the region."""
    res = c.estate.resources
    in_region = [s for s in res.get("aws_vpc_subnet", []) if s.region == c.region]
    vpc_id = in_region[0].attrs["vpc_id"] if in_region else None
    subnets = [s.native_id for s in in_region if s.attrs["vpc_id"] == vpc_id][:2]
    groups = [
        g.native_id
        for g in res.get("aws_vpc_security_group", [])
        if g.region == c.region and g.attrs["vpc_id"] == vpc_id
    ]
    return subnets, groups[:1], groups[1:2] or groups[:1], vpc_id


def _roles(c: _Chain) -> dict[str, Resource]:
    def role(name: str, service: str) -> Resource:
        full = f"{c.label}-{name}"
        return c.add(
            "aws_iam_role",
            f"AROA{c.id(17, name).upper()}",
            full,
            f"arn:aws:iam::{c.acct}:role/{full}",
            {"trusted": service, "admin": False},
            where="global",
        )

    return {
        "api": role(ORDERS_API_ROLE, "lambda.amazonaws.com"),
        "worker": role("orders-worker-role", "lambda.amazonaws.com"),
        "task": role("orders-task-role", "ecs-tasks.amazonaws.com"),
        "execution": role("ecs-execution-role", "ecs-tasks.amazonaws.com"),
        "eks": role("eks-cluster-role", "eks.amazonaws.com"),
        "node": role("eks-node-role", "ec2.amazonaws.com"),
    }


def _function(
    c: _Chain, name: str, role: Resource, subnets: list[str], groups: list[str]
) -> Resource:
    full = f"{c.label}-{name}"
    attrs: dict[str, Any] = {
        "role_arn": role.uid,
        "environment": {"LOG_LEVEL": "info", "STAGE": c.label},
        "runtime": "python3.12",
        "public_url": False,
    }
    if subnets:
        attrs |= {"vpc_subnet_ids": subnets, "vpc_security_group_ids": groups}
    return c.add("aws_lambda_function", full, full, c.arn("lambda", f"function:{full}"), attrs)


def _orders_table(c: _Chain, role: Resource, queue: Resource) -> str:
    """The orders table, and the API role's inline policy that reads and writes it and sends to
    the orders queue: Lambda -> data, through its role (role-accesses, ADR-0036)."""
    name = f"{c.label}-orders"
    table_arn = c.arn("dynamodb", f"table/{name}")
    c.row(
        "aws_dynamodb_table",
        name,
        name,
        table_arn,
        {
            "name": name,
            "arn": table_arn,
            "table_status": "ACTIVE",
            "billing_mode": "PAY_PER_REQUEST",
        },
    )
    role.attrs["inline"] = [
        {
            "PolicyName": "orders-data",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["dynamodb:getitem", "dynamodb:putitem", "dynamodb:query"],
                        "Resource": [table_arn, f"{table_arn}/index/*"],
                    },
                    {"Effect": "Allow", "Action": ["sqs:sendmessage"], "Resource": [queue.uid]},
                ],
            },
        }
    ]
    return table_arn


def _workflows(
    c: _Chain,
    fns: dict[str, Resource],
    alb: Resource,
    queue: Resource,
    table: str,
    assets: Resource,
) -> None:
    """What moves data and events beside the request path (ADR-0036): a WAF on the edge ALB; a
    pipe from the orders queue to a fulfilment state machine that calls the worker and writes
    the table; a nightly schedule that starts it; the API's logs shipped through Firehose to
    the assets bucket."""
    acl_id = c.id(8, "acl")
    c.row(
        "aws_wafv2_web_acl",
        acl_id,
        f"{c.label}-edge-acl",
        c.arn("wafv2", f"regional/webacl/{c.label}-edge-acl/{acl_id}"),
        {
            "name": f"{c.label}-edge-acl",
            "id": acl_id,
            "scope": "REGIONAL",
            "arn": c.arn("wafv2", f"regional/webacl/{c.label}-edge-acl/{acl_id}"),
            "associated_resources": [alb.uid],
            "default_action": {"Allow": {}},
        },
    )
    machine = c.arn("states", f"stateMachine:{c.label}-fulfil")
    c.row(
        "aws_sfn_state_machine",
        machine,
        f"{c.label}-fulfil",
        machine,
        {
            "name": f"{c.label}-fulfil",
            "arn": machine,
            "type": "STANDARD",
            "status": "ACTIVE",
            "definition": {
                "StartAt": "Ship",
                "States": {
                    "Ship": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::lambda:invoke",
                        "Parameters": {"FunctionName": fns["worker"].uid},
                        "Next": "Record",
                    },
                    "Record": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::dynamodb:putItem",
                        "Parameters": {"TableName": table},
                        "End": True,
                    },
                },
            },
        },
    )
    pipe = c.arn("pipes", f"pipe/{c.label}-orders-to-fulfil")
    c.row(
        "aws_pipes_pipe",
        f"{c.label}-orders-to-fulfil",
        f"{c.label}-orders-to-fulfil",
        pipe,
        {
            "name": f"{c.label}-orders-to-fulfil",
            "arn": pipe,
            "source": queue.uid,
            "target": machine,
            "enrichment": None,
            "current_state": "RUNNING",
        },
    )
    schedule = c.arn("scheduler", f"schedule/default/{c.label}-nightly-fulfil")
    c.row(
        "aws_scheduler_schedule",
        f"{c.label}-nightly-fulfil",
        f"{c.label}-nightly-fulfil",
        schedule,
        {
            "name": f"{c.label}-nightly-fulfil",
            "arn": schedule,
            "state": "ENABLED",
            "schedule_expression": "cron(0 2 * * ? *)",
            "target": {"Arn": machine},
        },
    )
    stream = c.arn("firehose", f"deliverystream/{c.label}-api-logs")
    c.row(
        "aws_kinesis_firehose_delivery_stream",
        f"{c.label}-api-logs",
        f"{c.label}-api-logs",
        stream,
        {
            "delivery_stream_name": f"{c.label}-api-logs",
            "arn": stream,
            "delivery_stream_type": "DirectPut",
            "delivery_stream_status": "ACTIVE",
            "destinations": [{"ExtendedS3DestinationDescription": {"BucketARN": assets.uid}}],
        },
    )
    group = f"/aws/lambda/{fns['api'].name}"
    group_arn = c.arn("logs", f"log-group:{group}:*")
    c.row(
        "aws_cloudwatch_log_group",
        group,
        group,
        group_arn,
        {"name": group, "arn": group_arn, "retention_in_days": 30},
    )
    c.row(
        "aws_cloudwatch_log_subscription_filter",
        "ship-to-firehose",
        "ship-to-firehose",
        c.arn("logs", f"log-group:{group}:subscription-filter:ship-to-firehose"),
        {
            "name": "ship-to-firehose",
            "log_group_name": group,
            "destination_arn": stream,
            "filter_pattern": "",
            "akas": [c.arn("logs", f"log-group:{group}:subscription-filter:ship-to-firehose")],
        },
    )


def _data(c: _Chain, fns: dict[str, Resource]) -> tuple[Resource, Resource]:
    """The assets bucket and the orders queue, and what each of them triggers."""
    bucket = f"{c.label}-web-assets-{c.id(6, 'bucket')}"
    notify = {
        "Id": "thumbnails",
        "LambdaFunctionArn": fns["thumbnail"].uid,
        "Events": ["s3:ObjectCreated:*"],
    }
    assets = c.add(
        "aws_s3_bucket",
        bucket,
        bucket,
        f"arn:aws:s3:::{bucket}",
        {
            "bucket_region": c.region,
            "versioning": True,
            "notifications": {
                "LambdaFunctionConfigurations": [notify],
                "QueueConfigurations": [],
                "TopicConfigurations": [],
            },
        },
        where="global",
    )
    worker = fns["worker"]
    name = f"{c.label}-orders-queue"
    queue_arn = c.arn("sqs", name)
    queue = c.row(
        "aws_sqs_queue",
        name,
        name,
        queue_arn,
        {
            "queue_url": f"https://sqs.{c.region}.amazonaws.com/{c.acct}/{name}",
            "queue_arn": queue_arn,
            "fifo_queue": False,
            "sqs_managed_sse_enabled": True,
            "visibility_timeout_seconds": 60,
            "akas": [queue_arn],
        },
    )
    mapping = f"{c.id(8, 'esm')}-{c.id(4, 'esm', 2)}-4{c.id(3, 'esm', 3)}"
    c.row(
        "aws_lambda_event_source_mapping",
        mapping,
        worker.name,
        c.arn("lambda", f"event-source-mapping:{mapping}"),
        {
            "uuid": mapping,
            "arn": queue.uid,  # the plugin's arn column is the event source's ARN
            "function_arn": worker.uid,
            "function_name": worker.name,
            "batch_size": 10,
            "state": "Enabled",
        },
    )
    topic_arn = c.arn("sns", f"{c.label}-alerts")
    c.row(
        "aws_sns_topic",
        f"{c.label}-alerts",
        f"{c.label}-alerts",
        topic_arn,
        {"topic_arn": topic_arn, "display_name": "Alerts", "akas": [topic_arn]},
    )
    sub_id = f"{c.id(8, 'sub')}-{c.id(4, 'sub', 2)}"
    sub_arn = f"{topic_arn}:{sub_id}"
    c.row(
        "aws_sns_topic_subscription",
        sub_id,
        sub_id,
        sub_arn,
        {
            "subscription_arn": sub_arn,
            "topic_arn": topic_arn,
            "protocol": "lambda",
            "endpoint": worker.uid,
            "owner": c.acct,
            "akas": [sub_arn],
        },
    )
    rule = f"{c.label}-nightly-sync"
    c.row(
        "aws_eventbridge_rule",
        rule,
        rule,
        c.arn("events", f"rule/{rule}"),
        {
            "name": rule,
            "arn": c.arn("events", f"rule/{rule}"),
            "state": "ENABLED",
            "event_bus_name": "default",
            "schedule_expression": "cron(0 3 * * ? *)",
            "targets": [{"Id": "sync", "Arn": worker.uid}],
        },
    )
    return assets, queue


def _load_balancing(
    c: _Chain, api_fn: Resource, subnets: list[str], vpc_id: str | None
) -> tuple[Resource, str]:
    """The internet-facing edge ALB with a Lambda and an IP target group; and its listener."""
    name = f"{c.label}-edge-alb"
    lb_id = c.id(16, "alb")
    # Its own group, open to anywhere on 443 over IPv4 and IPv6: the internet reaches the
    # dual-stack ALB in both families (ADR-0035).
    edge_sg = f"sg-{c.id(17, 'edge-sg')}"
    c.add(
        "aws_vpc_security_group",
        edge_sg,
        f"{c.label}-edge-sg",
        c.arn("ec2", f"security-group/{edge_sg}"),
        {
            "vpc_id": vpc_id,
            "ingress": [
                {"cidr": "0.0.0.0/0", "from_port": 443, "to_port": 443, "protocol": "tcp"},
                {"cidr_ipv6": "::/0", "from_port": 443, "to_port": 443, "protocol": "tcp"},
            ],
        },
    )
    alb = c.add(
        "aws_ec2_application_load_balancer",
        name,
        name,
        c.arn("elasticloadbalancing", f"loadbalancer/app/{name}/{lb_id}"),
        {
            "scheme": "internet-facing",
            "vpc_id": vpc_id,
            "dns_name": f"{name}-{int(lb_id[:8], 16) % 10**9}.{c.region}.elb.amazonaws.com",
            "subnet_ids": subnets,
            "security_groups": [edge_sg],
            "ip_address_type": "dualstack",
        },
    )
    # Internet-facing by its scheme, but its security group admits one office range only:
    # CloudFox's endpoints module calls it public, Argus's rules say restricted (ADR-0035).
    admin = f"{c.label}-admin-alb"
    admin_id = c.id(16, "admin-alb")
    admin_sg = f"sg-{c.id(17, 'admin-sg')}"
    c.add(
        "aws_vpc_security_group",
        admin_sg,
        f"{c.label}-admin-sg",
        c.arn("ec2", f"security-group/{admin_sg}"),
        {
            "vpc_id": vpc_id,
            "ingress": [
                {"cidr": "203.0.113.0/24", "from_port": 443, "to_port": 443, "protocol": "tcp"}
            ],
        },
    )
    c.add(
        "aws_ec2_application_load_balancer",
        admin,
        admin,
        c.arn("elasticloadbalancing", f"loadbalancer/app/{admin}/{admin_id}"),
        {
            "scheme": "internet-facing",
            "vpc_id": vpc_id,
            "dns_name": f"{admin}-{int(admin_id[:8], 16) % 10**9}.{c.region}.elb.amazonaws.com",
            "subnet_ids": subnets,
            "security_groups": [admin_sg],
        },
    )
    listener = c.arn("elasticloadbalancing", f"listener/app/{name}/{lb_id}/{c.id(16, 'listener')}")
    for tg, kind, targets, port in (
        ("fn", "lambda", [api_fn.uid], 443),
        ("ecs", "ip", ["10.10.3.21", "10.10.3.22"], 8080),
    ):
        full = f"{c.label}-tg-{tg}"
        c.add(
            "aws_ec2_target_group",
            full,
            full,
            c.arn("elasticloadbalancing", f"targetgroup/{full}/{c.id(16, tg)}"),
            {"load_balancer_arn": alb.uid, "targets": targets, "port": port, "target_type": kind},
        )
    return alb, listener


def _containers(
    c: _Chain,
    roles: dict[str, Resource],
    subnets: list[str],
    web_sg: list[str],
    app_sg: list[str],
    vpc_id: str | None,
) -> None:
    """An ECS service behind the ALB's IP target group, and an EKS cluster with a node
    group. The task definition carries a secret in its environment, as real ones do."""
    cluster = f"{c.label}-main"
    cluster_arn = c.arn("ecs", f"cluster/{cluster}")
    c.row(
        "aws_ecs_cluster",
        cluster,
        cluster,
        cluster_arn,
        {
            "cluster_name": cluster,
            "cluster_arn": cluster_arn,
            "status": "ACTIVE",
            "akas": [cluster_arn],
        },
    )
    family = f"{c.label}-orders-svc"
    task_def = c.arn("ecs", f"task-definition/{family}:3")
    container = {
        "Name": "web",
        "Image": f"{c.acct}.dkr.ecr.{c.region}.amazonaws.com/orders:1.4.2",
        "PortMappings": [{"ContainerPort": 8080, "Protocol": "tcp"}],
        "Environment": [{"Name": "DB_PASSWORD", "Value": f"pw-{c.id(12, 'ecs-pw')}"}],
    }
    c.row(
        "aws_ecs_task_definition",
        f"{family}:3",
        f"{family}:3",
        task_def,
        {
            "task_definition_arn": task_def,
            "family": family,
            "revision": 3,
            "status": "ACTIVE",
            "network_mode": "awsvpc",
            "task_role_arn": roles["task"].uid,
            "execution_role_arn": roles["execution"].uid,
            "container_definitions": [container],
            "akas": [task_def],
        },
    )
    tg_ecs = c.arn("elasticloadbalancing", f"targetgroup/{c.label}-tg-ecs/{c.id(16, 'ecs')}")
    service_arn = c.arn("ecs", f"service/{cluster}/{family}")
    c.row(
        "aws_ecs_service",
        family,
        family,
        service_arn,
        {
            "service_name": family,
            "arn": service_arn,
            "cluster_arn": cluster_arn,
            "status": "ACTIVE",
            "task_definition": task_def,
            "launch_type": "FARGATE",
            "desired_count": 2,
            "load_balancers": [
                {"TargetGroupArn": tg_ecs, "ContainerName": "web", "ContainerPort": 8080}
            ],
            "network_configuration": {
                "AwsvpcConfiguration": {
                    "Subnets": subnets,
                    "SecurityGroups": app_sg,
                    "AssignPublicIp": "DISABLED",
                }
            },
        },
    )
    eks = f"{c.label}-eks"
    eks_arn = c.arn("eks", f"cluster/{eks}")
    c.row(
        "aws_eks_cluster",
        eks,
        eks,
        eks_arn,
        {
            "name": eks,
            "arn": eks_arn,
            "version": "1.31",
            "status": "ACTIVE",
            "role_arn": roles["eks"].uid,
            "endpoint": f"https://{c.id(32, 'eks').upper()}.gr7.{c.region}.eks.amazonaws.com",
            "resources_vpc_config": {
                "VpcId": vpc_id,
                "SubnetIds": subnets,
                "SecurityGroupIds": app_sg,
                "ClusterSecurityGroupId": web_sg[0] if web_sg else None,
                "EndpointPublicAccess": True,
                "EndpointPrivateAccess": True,
                "PublicAccessCidrs": ["0.0.0.0/0"],
            },
        },
    )
    group_arn = c.arn("eks", f"nodegroup/{eks}/general/{c.id(8, 'ng')}")
    c.row(
        "aws_eks_node_group",
        "general",
        "general",
        group_arn,
        {
            "nodegroup_name": "general",
            "arn": group_arn,
            "cluster_name": eks,
            "status": "ACTIVE",
            "node_role": roles["node"].uid,
            "subnets": subnets,
            "instance_types": ["m6i.large"],
            "scaling_config": {"MinSize": 2, "MaxSize": 6, "DesiredSize": 3},
        },
    )


def _http_api(c: _Chain, api_fn: Resource, listener: str) -> str:
    """An HTTP API: two routes to the API function, one through a VPC link to the ALB."""
    api_id = c.id(10, "http-api")
    uid = f"arn:aws:apigateway:{c.region}::/apis/{api_id}"
    c.row(
        "aws_api_gatewayv2_api",
        api_id,
        f"{c.label}-orders-http",
        uid,
        {
            "name": f"{c.label}-orders-http",
            "api_id": api_id,
            "api_endpoint": f"https://{api_id}.execute-api.{c.region}.amazonaws.com",
            "protocol_type": "HTTP",
            "route_selection_expression": "$request.method $request.path",
            "akas": [uid],
        },
    )
    # The webhook's URL carries a credential in its userinfo, as real integrations sometimes
    # do: redaction must mask it before it is stored, and the map shows the host alone.
    webhook = f"https://hooks:pw-{c.id(12, 'hook-pw')}@hooks.partner.example/in"
    integrations = {
        "lambda": (api_fn.uid, "AWS_PROXY", "INTERNET", None),
        "legacy": (listener, "HTTP_PROXY", "VPC_LINK", c.id(6, "vpclink")),
        "webhook": (webhook, "HTTP_PROXY", "INTERNET", None),
    }
    for name, (target, kind, connection, link) in integrations.items():
        integration_id = c.id(7, "integration", name)
        c.row(
            "aws_api_gatewayv2_integration",
            integration_id,
            integration_id,
            f"{uid}/integrations/{integration_id}",
            {
                "integration_id": integration_id,
                "api_id": api_id,
                "arn": f"{uid}/integrations/{integration_id}",
                "integration_type": kind,
                "integration_uri": target,
                "connection_type": connection,
                "connection_id": link,
                "payload_format_version": "2.0",
            },
        )
    for route_key, target in (
        ("GET /orders", "lambda"),
        ("POST /orders", "lambda"),
        ("ANY /legacy/{proxy+}", "legacy"),
        ("POST /hooks", "webhook"),
    ):
        route_id = c.id(7, "route", route_key)
        c.row(
            "aws_api_gatewayv2_route",
            route_id,
            route_key,
            f"{uid}/routes/{route_id}",
            {
                "route_id": route_id,
                "api_id": api_id,
                "route_key": route_key,
                "target": f"integrations/{c.id(7, 'integration', target)}",
                "authorization_type": "NONE",
                "akas": [f"{uid}/routes/{route_id}"],
            },
        )
    return api_id


def _rest_api(c: _Chain, api_fn: Resource, queue: Resource) -> tuple[str, str]:
    """A REST API calling the API function, the orders queue and a partner webhook, and its
    custom domain. Returns (the account's zone name, the domain's regional name)."""
    api_id = c.id(10, "rest-api")
    uid = f"arn:aws:apigateway:{c.region}::/restapis/{api_id}"
    c.row(
        "aws_api_gateway_rest_api",
        api_id,
        f"{c.label}-partner-rest",
        uid,
        {
            "name": f"{c.label}-partner-rest",
            "api_id": api_id,
            "root_resource_id": c.id(10, "root"),
            "endpoint_configuration_types": ["REGIONAL"],
            "api_key_source": "HEADER",
            "akas": [uid],
        },
    )
    apigw = f"arn:aws:apigateway:{c.region}"
    methods = [
        (
            "GET",
            "/users",
            "AWS_PROXY",
            f"{apigw}:lambda:path/2015-03-31/functions/{api_fn.uid}/invocations",
        ),
        ("POST", "/jobs", "AWS", f"{apigw}:sqs:path/{c.acct}/{queue.name}"),
        ("POST", "/webhook", "HTTP", f"https://hooks.{c.label}-partner.example.org/in"),
    ]
    for verb, path, kind, target in methods:
        resource_id = c.id(6, "resource", path)
        c.row(
            "aws_api_gateway_method",
            resource_id,
            path,
            f"{uid}/resources/{resource_id}/methods/{verb}",
            {
                "rest_api_id": api_id,
                "resource_id": resource_id,
                "http_method": verb,
                "path": path,
                "path_part": path.strip("/"),
                "authorization_type": "NONE",
                "api_key_required": False,
                "method_integration": {"Type": kind, "HttpMethod": "POST", "Uri": target},
            },
        )
    # Domain names are global: one zone per account.
    zone_name = f"{c.label}-{hexid(4, c.acct)}.example.com"
    domain = f"rest.{zone_name}"
    regional = f"d-{c.id(10, 'domain')}.execute-api.{c.region}.amazonaws.com"
    domain_uid = f"arn:aws:apigateway:{c.region}::/domainnames/{domain}"
    c.row(
        "aws_api_gateway_domain_name",
        domain,
        domain,
        domain_uid,
        {
            "domain_name": domain,
            "regional_domain_name": regional,
            "regional_hosted_zone_id": "Z1UJRXOUMOOFQ8",
            "endpoint_configuration": {"Types": ["REGIONAL"]},
            "security_policy": "TLS_1_2",
            "akas": [domain_uid],
        },
    )
    return zone_name, regional


def _edge(
    c: _Chain, zone_name: str, rest_domain: str, assets: Resource, http_id: str, alb: Resource
) -> None:
    """CloudFront in front of the bucket, the HTTP API and the ALB; the public zone."""
    dist_id = "E" + c.id(13, "cf").upper()
    cf_domain = f"d{c.id(13, 'cfdomain')}.cloudfront.net"
    cf_uid = f"arn:aws:cloudfront::{c.acct}:distribution/{dist_id}"
    https = {"OriginProtocolPolicy": "https-only", "HTTPSPort": 443}
    c.row(
        "aws_cloudfront_distribution",
        dist_id,
        f"app.{zone_name}",
        cf_uid,
        {
            "id": dist_id,
            "arn": cf_uid,
            "status": "Deployed",
            "enabled": True,
            "domain_name": cf_domain,
            "http_version": "http2",
            "aliases": {"Quantity": 1, "Items": [f"app.{zone_name}"]},
            "origins": [
                {
                    "Id": "assets",
                    "DomainName": f"{assets.name}.s3.{c.region}.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                },
                {
                    "Id": "api",
                    "DomainName": f"{http_id}.execute-api.{c.region}.amazonaws.com",
                    "CustomOriginConfig": https,
                },
                {"Id": "legacy", "DomainName": alb.attrs["dns_name"], "CustomOriginConfig": https},
            ],
            "default_cache_behavior": {
                "TargetOriginId": "assets",
                "ViewerProtocolPolicy": "redirect-to-https",
            },
        },
        where="global",
    )
    zone_id = "Z" + c.id(13, "zone").upper()
    zone_uid = f"arn:aws:route53:::hostedzone/{zone_id}"
    c.row(
        "aws_route53_zone",
        zone_id,
        f"{zone_name}.",
        zone_uid,
        {"name": f"{zone_name}.", "id": zone_id, "private_zone": False, "akas": [zone_uid]},
        where="global",
    )

    def alias(target: str, zone: str) -> dict[str, Any]:
        return {"alias_target": {"DNSName": f"{target}.", "HostedZoneId": zone}}

    records = [
        ("app", "A", alias(cf_domain, "Z2FDTNDATAQYW2")),
        ("www", "A", alias(f"dualstack.{alb.attrs['dns_name']}", "Z35SXDOTRQ7X7K")),
        ("rest", "A", alias(rest_domain, "Z1UJRXOUMOOFQ8")),
        # A name for a name (argus_v12): shop -> www -> the load balancer, drawn in order.
        ("shop", "CNAME", {"ttl": 300, "records": [f"www.{zone_name}"]}),
        ("status", "CNAME", {"ttl": 300, "records": [f"status.{c.label}-vendor.example.net"]}),
        ("", "TXT", {"ttl": 300, "records": ['"v=spf1 -all"']}),
    ]
    for prefix, rtype, extra in records:
        name = f"{prefix}.{zone_name}." if prefix else f"{zone_name}."
        uid = f"{zone_uid}/recordset/{name}/{rtype}"
        c.row(
            "aws_route53_record",
            name,
            name,
            uid,
            {"name": name, "zone_id": zone_id, "type": rtype, "akas": [uid], **extra},
            where="global",
        )
