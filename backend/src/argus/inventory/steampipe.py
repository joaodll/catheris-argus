"""The Steampipe adapter: one run's JSONL files -> inventory records. Pure: no network, no
database, so a fixed adapter can be replayed over old raw output (ADR-0003).

Any table of the list is read (argus_v8: every configuration table). The resource_uid is the
`arn` column, else the first of `akas` that is an ARN; COLUMNS overrides that, and the native
id, name and VPC, for the tables the rules read. Two tables can describe one ARN (a key and
its rotation setting): the row from the table that owns it is kept, the other is reported as
skipped. Configurations are redacted (core.redaction) and stripped of volatile columns before
hashing, so a counter that changes every day does not create a new configuration every day.
"""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from argus.core.manifest import Manifest
from argus.core.rawstore import RawRun
from argus.core.redaction import NOT_SECRET_COLUMNS, redact


class UnsupportedVersionError(ValueError):
    pass


SUPPORTED_VERSIONS = frozenset({"1.34.0"})
# Parts of another resource, settings and links: stored and searchable, not counted as
# assets. Named ones, plus every table whose name ends in one of the suffixes below.
NON_ASSET_TYPES = frozenset(
    {
        "aws_vpc_security_group_rule",
        "aws_iam_access_key",
        "aws_account_alternate_contact",
        "aws_account_contact",
        "aws_ec2_regional_settings",
        "aws_kms_key_rotation",
        "aws_vpc_route",
        "aws_ec2_transit_gateway_route",
        "aws_ec2_managed_prefix_list_entry",
        "aws_ec2_load_balancer_listener_rule",
        "aws_api_gateway_method",
        "aws_api_gatewayv2_route",
        "aws_api_gatewayv2_integration",
    }
)
NON_ASSET_SUFFIXES = (
    "_attachment",
    "_association",
    "_association_authorization",
    "_settings",
    "_setting",
    "_configuration",
    "_options",
    "_member",
    "_permission",
    "_version",
)


def is_asset(resource_type: str) -> bool:
    return resource_type not in NON_ASSET_TYPES and not resource_type.endswith(NON_ASSET_SUFFIXES)


def non_asset_types(types: "set[str] | frozenset[str]") -> list[str]:
    """The given types that are not assets, for a query's exclusion list."""
    return sorted(t for t in types if not is_asset(t))


@dataclass(frozen=True)
class _Columns:
    uid: str
    native_id: str
    name: str | None
    vpc: str | None = None


# Any other table: the uid from `arn` (else akas), the native id from the first of these
# columns that holds a value, the name from `name` (else `title`), the VPC from `vpc_id`.
_NATIVE_ID_COLUMNS = ("id", "name", "title")


COLUMNS: dict[str, _Columns] = {
    "aws_ec2_instance": _Columns("arn", "instance_id", "title", "vpc_id"),
    "aws_lambda_function": _Columns("arn", "name", "name"),
    "aws_vpc": _Columns("arn", "vpc_id", "title", "vpc_id"),
    "aws_vpc_subnet": _Columns("subnet_arn", "subnet_id", "title", "vpc_id"),
    "aws_vpc_security_group": _Columns("arn", "group_id", "group_name", "vpc_id"),
    "aws_vpc_security_group_rule": _Columns("akas", "security_group_rule_id", "title"),
    "aws_ec2_application_load_balancer": _Columns("arn", "name", "name", "vpc_id"),
    "aws_ec2_network_load_balancer": _Columns("arn", "name", "name", "vpc_id"),
    "aws_ec2_target_group": _Columns(
        "target_group_arn", "target_group_name", "target_group_name", "vpc_id"
    ),
    "aws_iam_role": _Columns("arn", "role_id", "name"),
    "aws_iam_user": _Columns("arn", "user_id", "name"),
    # No arn column: akas holds arn:aws:iam::<account>:user/<user>/accesskey/<key id>.
    "aws_iam_access_key": _Columns("akas", "access_key_id", "access_key_id"),
    "aws_iam_instance_profile": _Columns("arn", "instance_profile_id", "instance_profile_name"),
    "aws_rds_db_instance": _Columns(
        "arn", "db_instance_identifier", "db_instance_identifier", "vpc_id"
    ),
    "aws_s3_bucket": _Columns("arn", "name", "name"),
    # The rules join an API's methods, routes and integrations by api_id (ADR-0033).
    "aws_api_gateway_rest_api": _Columns("akas", "api_id", "name"),
    "aws_api_gatewayv2_api": _Columns("akas", "api_id", "name"),
}


def _method_uid(row: dict[str, Any]) -> str | None:
    """API Gateway (v1) methods have no arn and no akas: their ARN is built from the API,
    resource and verb, so method_integration (the Lambda or VPC link it calls) is kept."""
    parts = (row.get("region"), row.get("rest_api_id"), row.get("resource_id"))
    verb = row.get("http_method")
    if not all(isinstance(p, str) and p for p in (*parts, verb)):
        return None
    region, api, resource = parts
    partition = row.get("partition") or "aws"
    return (
        f"arn:{partition}:apigateway:{region}::/restapis/{api}/resources/{resource}/methods/{verb}"
    )


def _event_source_mapping_uid(row: dict[str, Any]) -> str | None:
    """The plugin's `arn` column on aws_lambda_event_source_mapping is the event SOURCE's
    ARN (the queue or stream), not the mapping's: taking it would hand the queue's uid to the
    mapping and drop the queue. The mapping's own ARN is built from its UUID."""
    region, account, uuid = row.get("region"), row.get("account_id"), row.get("uuid")
    if not all(isinstance(p, str) and p for p in (region, account, uuid)):
        return None
    partition = row.get("partition") or "aws"
    return f"arn:{partition}:lambda:{region}:{account}:event-source-mapping:{uuid}"


def _record_uid(row: dict[str, Any]) -> str | None:
    """A record set's akas is hostedzone/<zone>/recordset/<name>/<type>: weighted, latency or
    failover sets share it, so the set identifier is appended to keep each one."""
    base = _uid(row, "akas")
    identifier = row.get("set_identifier")
    if base and isinstance(identifier, str) and identifier:
        return f"{base}/{identifier}"
    return base


def _domain_name_uid(row: dict[str, Any]) -> str | None:
    """A custom domain's ARN is arn:<partition>:apigateway:<region>::/domainnames/<name>, in
    both API versions. The v2 table has no arn column, and its akas came out of a real run as
    .../domainname/ with no name (2026-10-09): every v2 domain of a region in every account then
    shared one uid (ADR-0034). Both tables build it, so the same domain seen by both is one
    resource, owned by the v1 table (the shorter name, see _owner_rank)."""
    region, name = row.get("region"), row.get("domain_name")
    if not all(isinstance(p, str) and p for p in (region, name)):
        return None
    partition = row.get("partition") or "aws"
    return f"arn:{partition}:apigateway:{region}::/domainnames/{name}"


# Tables whose uid is built, not read (ADR-0033): (uid builder, native id, name columns).
BUILT_UIDS: dict[str, tuple[Callable[[dict[str, Any]], str | None], str, str | None]] = {
    "aws_api_gateway_domain_name": (_domain_name_uid, "domain_name", "domain_name"),
    "aws_api_gatewayv2_domain_name": (_domain_name_uid, "domain_name", "domain_name"),
    "aws_api_gateway_method": (_method_uid, "resource_id", "path"),
    "aws_lambda_event_source_mapping": (_event_source_mapping_uid, "uuid", "function_name"),
    "aws_route53_record": (_record_uid, "name", "name"),
}

# Rows AWS owns, listed the same in every account: not inventoried, since a uid has one owning
# connection (ADR-0034). AWS-managed policies are left out at export (collection.tables).
AWS_OWNED: dict[str, Callable[[dict[str, Any]], bool]] = {
    "aws_ec2_managed_prefix_list": lambda row: row.get("owner_id") == "AWS",
}

# Left out of the configuration and its hash: they change without the resource changing.
# An IAM user's and access key's last use are kept on purpose (argus_v7): a stale key is a
# finding an operator looks for, at the cost of a new configuration on each day it is used.
VOLATILE_ALL = frozenset({"_ctx", "sp_ctx", "sp_connection_name", "title", "akas"})
VOLATILE = {
    "aws_vpc_subnet": frozenset({"available_ip_address_count"}),
    "aws_iam_role": frozenset({"role_last_used_date", "role_last_used_region"}),
    "aws_rds_db_instance": frozenset({"latest_restorable_time"}),
}


@dataclass(frozen=True)
class InventoryResource:
    uid: str
    type: str
    region: str
    native_id: str
    name: str | None
    vpc_id: str | None
    tags: dict[str, str]
    config: dict[str, Any]
    config_hash: bytes


@dataclass
class InventoryBatch:
    resources: list[InventoryResource]
    tables_seen: frozenset[str]
    complete: bool
    skipped: list[str] = field(default_factory=list)  # rows without a usable ARN
    # Per-table completeness (argus_v8). complete_types: the types whose missing resources are
    # deleted. carry_types: the types whose previous rows carry forward; None carries every
    # type (a partial run that does not say which tables were incomplete: older manifests,
    # the synthetic source's throttling).
    complete_types: frozenset[str] = frozenset()
    carry_types: frozenset[str] | None = None


def _decode(value: Any) -> Any:
    """steampipe_export_aws writes JSON columns (tags, policies, target health) as JSON text.
    Text that is a JSON object or array is decoded, so the configuration keeps its structure
    and redaction sees each key under it; anything else is left as it is."""
    if isinstance(value, str) and value[:1] in ("{", "["):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _normalise(table: str, row: dict[str, Any]) -> dict[str, Any]:
    drop = VOLATILE_ALL | VOLATILE.get(table, frozenset())
    config = {k: v for k, v in row.items() if k not in drop}
    if table == "aws_ec2_target_group":
        # Target health flips constantly; which targets are registered does not.
        health = row.get("target_health_descriptions")
        config["target_health_descriptions"] = [
            {"Target": d.get("Target")}
            for d in (health if isinstance(health, list) else [])
            if isinstance(d, dict)
        ]
    redacted: dict[str, Any] = redact(config, keep=NOT_SECRET_COLUMNS.get(table, frozenset()))
    return redacted


def config_hash(config: dict[str, Any]) -> bytes:
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).digest()


def _uid(row: dict[str, Any], column: str | None) -> str | None:
    candidates = [row.get(column)] if column else [row.get("arn"), row.get("akas")]
    for value in candidates:
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str) and item.startswith("arn:"):
                return item
    return None


def _native_id(row: dict[str, Any], uid: str) -> str:
    for column in _NATIVE_ID_COLUMNS:
        value = row.get(column)
        if isinstance(value, str | int) and str(value):
            return str(value)
    return uid


def _identity(table: str, row: dict[str, Any], uid: str) -> tuple[str, Any, Any]:
    """(native id, name, VPC id) as the table's columns give them."""
    built, cols = BUILT_UIDS.get(table), COLUMNS.get(table)
    if built:
        return str(row.get(built[1]) or uid), row.get(built[2]) if built[2] else None, None
    if cols:
        return (
            str(row.get(cols.native_id)),
            row.get(cols.name) if cols.name else None,
            row.get(cols.vpc) if cols.vpc else None,
        )
    name = row.get("name") if isinstance(row.get("name"), str) else row.get("title")
    return _native_id(row, uid), name, row.get("vpc_id")


def _owner_rank(table: str, row: dict[str, Any], uid: str) -> tuple[int, int, str]:
    """Which table owns an ARN two tables report: one whose own `arn` column holds it, then
    the shorter name (aws_kms_key before aws_kms_key_rotation), then the name."""
    owns = row.get("arn") == uid or table in COLUMNS or table in BUILT_UIDS
    return (0 if owns else 1, len(table), table)


def parse_steampipe(run: RawRun) -> InventoryBatch:
    manifest = run.manifest
    if manifest.tool != "steampipe":
        raise ValueError(f"not a steampipe run: {manifest.tool}")
    if manifest.tool_version not in SUPPORTED_VERSIONS:
        raise UnsupportedVersionError(f"steampipe export {manifest.tool_version} not supported")
    chosen: dict[str, tuple[tuple[int, int, str], InventoryResource]] = {}
    skipped: list[str] = []
    seen: set[str] = set()
    for file in manifest.files:
        table = file.path.removesuffix(".jsonl")
        if not file.path.endswith(".jsonl") or not table.startswith("aws_"):
            continue
        seen.add(table)
        cols = COLUMNS.get(table)
        built = BUILT_UIDS.get(table)
        aws_owned = AWS_OWNED.get(table)
        for line in run.path(file.path).read_text().splitlines():
            if not line:
                continue
            # Decoded before anything reads the row, and before redaction.
            row = {k: _decode(v) for k, v in json.loads(line).items()}
            if aws_owned and aws_owned(row):
                continue
            uid = built[0](row) if built else _uid(row, cols.uid if cols else None)
            if uid is None:
                native = row.get(cols.native_id) if cols else row.get("title")
                skipped.append(f"{table}:{native}")
                continue
            config = _normalise(table, row)
            tags = row.get("tags") if isinstance(row.get("tags"), dict) else {}
            native_id, name, vpc = _identity(table, row, uid)
            resource = InventoryResource(
                uid=uid,
                type=table,
                region=row.get("region") or "global",
                native_id=native_id,
                name=name if isinstance(name, str) else None,
                vpc_id=vpc if isinstance(vpc, str) else None,
                tags={str(k): str(v) for k, v in (tags or {}).items()},
                config=config,
                config_hash=config_hash(config),
            )
            rank = _owner_rank(table, row, uid)
            held = chosen.get(uid)
            if held is None or rank < held[0]:
                if held is not None:
                    skipped.append(f"{held[1].type}:{uid} (also in {table})")
                chosen[uid] = (rank, resource)
            else:
                skipped.append(f"{table}:{uid} (also in {held[1].type})")
    complete_types, carry_types = _scope(manifest, frozenset(seen))
    return InventoryBatch(
        resources=[resource for _, resource in chosen.values()],
        tables_seen=frozenset(seen),
        complete=manifest.status == "complete",
        skipped=skipped,
        complete_types=complete_types,
        carry_types=carry_types,
    )


def _scope(
    manifest: Manifest, seen: frozenset[str]
) -> tuple[frozenset[str], frozenset[str] | None]:
    """(types complete in this run, types to carry forward; None = every type). A complete run
    can carry tables too: those not applicable to the account or refused by a resource."""
    incomplete = frozenset(manifest.incomplete_tables)
    if manifest.status == "complete":
        return seen - incomplete, incomplete
    if manifest.status == "partial" and incomplete:
        return seen - incomplete, incomplete
    return frozenset(), None
