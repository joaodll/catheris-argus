"""Runs Test connection for the worker (ADR-0024, amended 2026-10-07).

A connection test signs in as the connection does for a scan: it assumes the role with its
ExternalId (or uses its access key), then asks AWS who that is (sts:GetCallerIdentity). It
passes when the account is the connection's. The platform identity test signs in as the
identity, then writes one small marker object to each tool's folder of the raw output bucket,
which is all the identity is allowed to do there, and reports the encryption S3 applied.

No call reads or changes anything in a scanned account (CLAUDE.md, read-only): STS calls only
authenticate, and the only write goes to Argus's own bucket. Every AWS call happens outside a
database transaction.
"""

import logging
from datetime import UTC, datetime

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import Engine

from argus import connections
from argus.collection import access_for
from argus.connections import checks
from argus.core import aws
from argus.settings import read_identity_credentials, read_raw_storage

log = logging.getLogger("argus.worker")
MARKER = "_argus/connection-test.txt"


class _Failed(Exception):
    """The test failed with a message for the administrator."""


def run_pending(engine: Engine) -> bool:
    """Runs the oldest queued test, if any. Returns True when one ran. Tests no one answered
    are expired by maintenance.maintain(), every minute."""
    with engine.begin() as conn:
        test = checks.claim_test(conn)
    if test is None:
        return False
    try:
        if test.target == "connection" and test.connection_id is not None:
            caller, message = _test_connection(engine, test.connection_id, test.id)
        else:
            caller, message = _test_identity(engine)
        passed = True
    except _Failed as exc:
        caller, message, passed = None, str(exc), False
    except (BotoCoreError, ClientError) as exc:
        caller, message, passed = None, f"AWS refused: {_aws_error(exc)}", False
    except Exception as exc:  # the test must end, whatever went wrong
        log.exception("connection test failed", extra={"test_id": test.id})
        caller, message, passed = None, f"{type(exc).__name__}: {exc}", False
    with engine.begin() as conn:
        checks.finish_test(conn, test.id, passed=passed, message=message, caller_arn=caller)
    log.info("connection test finished", extra={"test_id": test.id, "passed": passed})
    return True


def _aws_error(exc: BotoCoreError | ClientError) -> str:
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        return f"{error.get('Code', 'Error')}: {error.get('Message', '')}".strip()
    return str(exc)


def _test_connection(engine: Engine, connection_id: int, test_id: int) -> tuple[str, str]:
    with engine.connect() as conn:
        connection = connections.get(conn, connection_id)
        if connection is None:
            raise _Failed("The connection no longer exists.")
        if connection.kind != "aws":
            raise _Failed("A Demo connection has nothing to test.")
        access = access_for(conn, connection)
    try:
        credentials = access.credentials(session_name=f"argus-test-{test_id}")
    except (BotoCoreError, ClientError) as exc:
        how = "use the access key" if access.auth.method == "access_key" else "assume the role"
        raise _Failed(f"Could not {how}: {_aws_error(exc)}") from exc
    account, arn = aws.caller_identity(credentials)
    if account != connection.account_id:
        raise _Failed(
            f"Signed in, but to account {account}, not the connection's {connection.account_id}."
        )
    how = "the access key" if access.auth.method == "access_key" else "the role"
    return arn, f"Signed in to account {account} with {how}."


def _test_identity(engine: Engine) -> tuple[str, str]:
    with engine.connect() as conn:
        credentials = read_identity_credentials(conn)
        storage = read_raw_storage(conn)
    _account, arn = aws.caller_identity(credentials)
    if storage.bucket is None or storage.region is None:
        return arn, "Signed in. No raw output bucket is set: AWS runs cannot start until one is."
    s3 = aws.s3_client(region=storage.region, credentials=credentials)
    stamp = datetime.now(UTC).isoformat(timespec="seconds")
    encryption: set[str] = set()
    for prefix in storage.prefixes.model_dump().values():
        key = f"{prefix}/{MARKER}"
        try:
            answer = s3.put_object(
                Bucket=storage.bucket,
                Key=key,
                Body=f"Argus connection test, {stamp}\n".encode(),
                ContentType="text/plain",
            )
        except (BotoCoreError, ClientError) as exc:
            raise _Failed(
                f"Signed in, but could not write s3://{storage.bucket}/{key}: {_aws_error(exc)}"
            ) from exc
        encryption.add(str(answer.get("ServerSideEncryption") or "none"))
    kms = encryption <= {"aws:kms", "aws:kms:dsse"}
    return arn, (
        f"Signed in, and wrote a test object to each tool's folder in s3://{storage.bucket} "
        f"(encryption: {', '.join(sorted(encryption))}"
        f"{'' if kms else '; SSE-KMS is recommended'})."
    )
