"""AWS sessions for Argus's own calls. Our code calls a cloud only to authenticate, to
discover accounts, to write raw output to the operator's bucket, and to write and read reports in
its reports/ folder (CLAUDE.md, read-only; ADR-0047).

Credentials come from the platform identity (Settings -> Identity, ADR-0024): the ambient
chain (instance role, Pod Identity) or an access key stored for local tests. Reports never use
it: the API and the report Job each have their own IRSA role, reached by web identity only.
"""

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

import boto3
import botocore.session
from botocore.config import Config

from argus.core.rawstore import S3Client

# Every call has a timeout; adaptive retries back off when AWS throttles.
CLIENT_CONFIG = Config(
    connect_timeout=10, read_timeout=60, retries={"mode": "adaptive", "max_attempts": 5}
)

# Reports' S3 calls: a download is waiting on them, so they give up sooner.
REPORTS_CLIENT_CONFIG = Config(
    connect_timeout=5, read_timeout=30, retries={"mode": "standard", "max_attempts": 3}
)
# The one credential provider a reports client may use: the pod's IRSA token (ADR-0047).
WEB_IDENTITY_METHOD = "assume-role-with-web-identity"

# AKIA: a long-lived IAM user key. ASIA: a temporary key (SSO, STS), which AWS accepts only
# together with its session token.
ACCESS_KEY_ID_PATTERN = r"^(AKIA|ASIA)[A-Z0-9]{16}$"
MAX_SESSION_TOKEN_CHARS = 8192
# What a stored credential may hold: printable ASCII with no space. Every part of a real key fits,
# and each one ends up on a line of its own in a file the tools parse.
_ONE_WORD = re.compile(r"[!-~]+")


def is_one_word(value: str) -> bool:
    return _ONE_WORD.fullmatch(value) is not None


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
    if not access_key_id or not re.fullmatch(ACCESS_KEY_ID_PATTERN, access_key_id):
        raise ValueError("access_key_id is not an AWS access key id")
    if not secret_access_key or len(secret_access_key) < 30:
        raise ValueError("secret_access_key is required")
    if not is_one_word(secret_access_key):
        raise ValueError("secret_access_key holds a space or a character AWS keys never have")
    if access_key_id.startswith("ASIA"):
        if not session_token:
            raise ValueError("a temporary key (ASIA...) needs its session_token")
        if len(session_token) > MAX_SESSION_TOKEN_CHARS:
            raise ValueError("session_token is too long")
        if not is_one_word(session_token):
            raise ValueError("session_token holds a space or a character AWS tokens never have")
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
    external_id: str | None,
    session_name: str,
    credentials: SessionCredentials | None,
    duration_seconds: int = 3600,
) -> SessionCredentials:
    """sts:AssumeRole as the platform identity: its stored key, or the ambient chain (None).
    The ExternalId is sent only when the connection has one: a role whose trust asks for none
    is assumed without it (owner, 2026-11-05)."""
    sts = _session(credentials, None).client("sts", region_name="us-east-1", config=CLIENT_CONFIG)
    external = {"ExternalId": external_id} if external_id else {}
    answer = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=duration_seconds,
        **external,
    )["Credentials"]
    return SessionCredentials(
        answer["AccessKeyId"], answer["SecretAccessKey"], answer["SessionToken"]
    )


def caller_identity(credentials: SessionCredentials | None) -> tuple[str, str]:
    """sts:GetCallerIdentity: the account and ARN AWS says these credentials sign in as. Needs
    no permission; it proves the credentials work (Test connection, ADR-0024) and whose they are
    (before every AWS run)."""
    sts = _session(credentials, None).client("sts", region_name="us-east-1", config=CLIENT_CONFIG)
    answer = sts.get_caller_identity()
    return str(answer["Account"]), str(answer["Arn"])


class NoWebIdentityError(RuntimeError):
    """This pod has no IRSA identity: no role ARN, or no token file."""


def web_identity_available() -> bool:
    """Whether the pod carries an IRSA identity: EKS's webhook sets both variables and mounts
    the token when the pod's ServiceAccount names a role."""
    role_arn = os.environ.get("AWS_ROLE_ARN")
    token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
    return bool(role_arn) and bool(token_file) and Path(str(token_file)).is_file()


@lru_cache(maxsize=8)
def web_identity_s3_client(region: str) -> Any:
    """An S3 client signed by this pod's IRSA role and nothing else (review SA-2): every other
    provider of the default chain is removed, so a pod whose ServiceAccount lost its annotation
    gets an error, never the node's instance role or a key in the environment. Credentials
    refresh themselves, so one client per region serves the process. Raises NoWebIdentityError."""
    if not web_identity_available():
        raise NoWebIdentityError("no IRSA identity in this pod")
    core = botocore.session.Session()
    resolver = core.get_component("credential_provider")
    resolver.providers = [
        p for p in resolver.providers if getattr(p, "METHOD", None) == WEB_IDENTITY_METHOD
    ]
    if not resolver.providers:
        raise NoWebIdentityError("this botocore has no web identity provider")
    session = boto3.Session(botocore_session=core, region_name=region)
    return session.client("s3", config=REPORTS_CLIENT_CONFIG)
