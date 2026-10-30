"""AWS sessions for Argus's own calls. Our code calls a cloud only to authenticate, to
discover accounts and to write raw output to the operator's bucket (CLAUDE.md, read-only).

Credentials come from the platform identity (Settings -> Identity, ADR-0024): the ambient
chain (instance role, Pod Identity) or an access key stored for local tests.
"""

import re
from dataclasses import dataclass, field
from typing import cast

import boto3
from botocore.config import Config

from argus.core.rawstore import S3Client

# Every call has a timeout; adaptive retries back off when AWS throttles.
CLIENT_CONFIG = Config(
    connect_timeout=10, read_timeout=60, retries={"mode": "adaptive", "max_attempts": 5}
)

# AKIA: a long-lived IAM user key. ASIA: a temporary key (SSO, STS), which AWS accepts only
# together with its session token.
ACCESS_KEY_ID_PATTERN = r"^(AKIA|ASIA)[A-Z0-9]{16}$"
MAX_SESSION_TOKEN_CHARS = 8192


@dataclass(frozen=True)
class SessionCredentials:
    """A key pair, plus a session token when temporary. Never printed: repr hides all three."""

    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    session_token: str | None = field(default=None, repr=False)


def check_access_key(
    access_key_id: str | None, secret_access_key: str | None, session_token: str | None
) -> None:
    """Refuse a key set AWS would reject: raises ValueError naming the field, never its value."""
    if not access_key_id or not re.match(ACCESS_KEY_ID_PATTERN, access_key_id):
        raise ValueError("access_key_id is not an AWS access key id")
    if not secret_access_key or len(secret_access_key) < 30:
        raise ValueError("secret_access_key is required")
    if access_key_id.startswith("ASIA"):
        if not session_token:
            raise ValueError("a temporary key (ASIA...) needs its session_token")
        if len(session_token) > MAX_SESSION_TOKEN_CHARS:
            raise ValueError("session_token is too long")
    elif session_token:
        raise ValueError("a long-lived key (AKIA...) takes no session_token")


def _session(credentials: SessionCredentials | None, region: str | None) -> boto3.Session:
    if credentials is None:
        return boto3.Session(region_name=region)
    return boto3.Session(
        aws_access_key_id=credentials.access_key_id,
        aws_secret_access_key=credentials.secret_access_key,
        aws_session_token=credentials.session_token,
        region_name=region,
    )


def s3_client(*, region: str, credentials: SessionCredentials | None) -> S3Client:
    """An S3 client as the platform identity: its stored key, or the ambient chain (None)."""
    return cast(S3Client, _session(credentials, region).client("s3", config=CLIENT_CONFIG))


def assume_role(
    *,
    role_arn: str,
    external_id: str,
    session_name: str,
    credentials: SessionCredentials | None,
    duration_seconds: int = 3600,
) -> SessionCredentials:
    """sts:AssumeRole as the platform identity: its stored key, or the ambient chain (None)."""
    sts = _session(credentials, None).client("sts", region_name="us-east-1", config=CLIENT_CONFIG)
    answer = sts.assume_role(
        RoleArn=role_arn,
        ExternalId=external_id,
        RoleSessionName=session_name,
        DurationSeconds=duration_seconds,
    )["Credentials"]
    return SessionCredentials(
        answer["AccessKeyId"], answer["SecretAccessKey"], answer["SessionToken"]
    )


def caller_identity(credentials: SessionCredentials | None) -> tuple[str, str]:
    """sts:GetCallerIdentity: the account and ARN AWS says these credentials sign in as. Needs
    no permission; it proves the credentials work (Test connection, ADR-0024)."""
    sts = _session(credentials, None).client("sts", region_name="us-east-1", config=CLIENT_CONFIG)
    answer = sts.get_caller_identity()
    return str(answer["Account"]), str(answer["Arn"])
