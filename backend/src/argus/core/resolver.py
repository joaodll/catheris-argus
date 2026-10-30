"""resource_uid: the one join key across tools (ADR-0004).

On AWS a resource_uid is the resource's ARN. Tools that report a short id (an instance id, a
security group id, a bucket or role name) are resolved here into that ARN from the account,
region and kind. A reference that cannot be resolved returns None; the caller records it in
unresolved_ref so a broken join is visible instead of silently dropped.
"""

import re
from datetime import date

from sqlalchemy import Connection, text

_SHORT_ID = {
    "i": ("ec2", "instance"),
    "sg": ("ec2", "security-group"),
    "subnet": ("ec2", "subnet"),
    "vpc": ("ec2", "vpc"),
    "vol": ("ec2", "volume"),
    "eni": ("ec2", "network-interface"),
    "igw": ("ec2", "internet-gateway"),
    "nat": ("ec2", "natgateway"),
    "sgr": ("ec2", "security-group-rule"),
}
_SHORT_ID_RE = re.compile(r"^(i|sg|subnet|vpc|vol|eni|igw|nat|sgr)-[0-9a-f]{8,17}$")
_ARN_RE = re.compile(r"^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:([0-9]{12})?:.+$")
_NAME_RE = re.compile(r"^[A-Za-z0-9+=,.@_/-]{1,255}$")

# Kinds whose plain names resolve (the tool says what kind of thing it is).
_NAMED = {
    "s3_bucket": lambda name, account, region: f"arn:aws:s3:::{name}",
    "iam_role": lambda name, account, region: f"arn:aws:iam::{account}:role/{name}",
    "lambda_function": lambda name, account, region: (
        f"arn:aws:lambda:{region}:{account}:function:{name}"
    ),
    "rds_db_instance": lambda name, account, region: f"arn:aws:rds:{region}:{account}:db:{name}",
}


def resolve(
    ref: str, *, account_id: str, region: str | None = None, kind: str | None = None
) -> str | None:
    ref = ref.strip()
    if _ARN_RE.match(ref):
        return ref
    if _SHORT_ID_RE.match(ref) and region:
        service, resource = _SHORT_ID[ref.split("-", 1)[0]]
        return f"arn:aws:{service}:{region}:{account_id}:{resource}/{ref}"
    if kind in _NAMED and _NAME_RE.match(ref):
        needs_region = kind in ("lambda_function", "rds_db_instance")
        if needs_region and not region:
            return None
        return _NAMED[kind](ref, account_id, region)
    return None


def record_unresolved(
    conn: Connection,
    *,
    tool: str,
    connection_id: int,
    raw_ref: str,
    reason: str,
    day: date,
    scan_run_id: int | None = None,
) -> None:
    """Keeps a reference that resolved to no resource: first and last seen, and the last run
    that reported it. Never dropped silently (CLAUDE.md, identity)."""
    conn.execute(
        text("""
        INSERT INTO unresolved_ref (tool, connection_id, raw_ref, reason, first_seen, last_seen,
                                    last_scan_run_id)
        VALUES (:tool, :c, :ref, :reason, :d, :d, :run)
        ON CONFLICT (tool, connection_id, raw_ref) DO UPDATE
          SET last_seen = :d,
              last_scan_run_id = COALESCE(EXCLUDED.last_scan_run_id,
                                          unresolved_ref.last_scan_run_id)
    """),
        {
            "tool": tool,
            "c": connection_id,
            "ref": raw_ref,
            "reason": reason,
            "d": day,
            "run": scan_run_id,
        },
    )
