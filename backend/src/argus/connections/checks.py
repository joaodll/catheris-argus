"""Test connection (ADR-0024, amended 2026-10-07): the queue of tests and their results.

The API asks (request_test) and reads the answer (get_test); the worker claims a test, runs it
outside any transaction and writes the result (claim_test, finish_test). Owns the
`connection_test` table. One open test per target: asking again returns the open one, so a
button pressed twice runs one test.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy import Connection, text

from argus.core import audit
from argus.core.redaction import redact_text

TestTarget = Literal["connection", "identity"]
TestStatus = Literal["queued", "running", "passed", "failed"]
# A test the worker has not finished by then failed: the worker is down or was restarted.
QUEUED_FOR = "2 minutes"
RUNNING_FOR = "5 minutes"


@dataclass(frozen=True)
class TestView:
    id: int
    target: TestTarget
    connection_id: int | None
    status: TestStatus
    requested_by: str
    requested_at: datetime
    finished_at: datetime | None
    caller_arn: str | None
    message: str | None


@dataclass(frozen=True)
class ClaimedTest:
    id: int
    target: TestTarget
    connection_id: int | None


_VIEW = (
    "id, target, connection_id, status, requested_by, requested_at, finished_at, caller_arn, "
    "message"
)


def request_test(
    conn: Connection,
    *,
    target: TestTarget,
    connection_id: int | None,
    actor: str,
    client_ip: str | None = None,
) -> int:
    """Queues a test of a connection or of the platform identity and returns its id, or the
    id of the test of the same target still open. Audited."""
    new_id = conn.execute(
        text("""
        INSERT INTO connection_test (target, connection_id, requested_by)
        VALUES (:t, :c, :a)
        ON CONFLICT (target, coalesce(connection_id, 0)) WHERE status IN ('queued', 'running')
        DO NOTHING
        RETURNING id
    """),
        {"t": target, "c": connection_id, "a": actor},
    ).scalar_one_or_none()
    if new_id is None:
        open_id: int = conn.execute(
            text("""
            SELECT id FROM connection_test
            WHERE target = :t AND coalesce(connection_id, 0) = coalesce(:c, 0)
              AND status IN ('queued', 'running')
        """),
            {"t": target, "c": connection_id},
        ).scalar_one()
        return open_id
    audit.record(
        conn,
        actor=actor,
        action=f"{target}.test",
        target_type=target,
        target_id=str(connection_id) if connection_id is not None else None,
        client_ip=client_ip,
        detail={"test_id": new_id},
    )
    return int(new_id)


def get_test(conn: Connection, test_id: int) -> TestView | None:
    row = conn.execute(
        text(f"SELECT {_VIEW} FROM connection_test WHERE id = :i"),  # noqa: S608 - constant
        {"i": test_id},
    ).one_or_none()
    return TestView(*row) if row else None


def claim_test(conn: Connection) -> ClaimedTest | None:
    """The oldest queued test, now running; None when there is none."""
    row = conn.execute(
        text("""
        UPDATE connection_test SET status = 'running', started_at = now()
        WHERE id = (SELECT id FROM connection_test WHERE status = 'queued'
                    ORDER BY requested_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
        RETURNING id, target, connection_id
    """)
    ).one_or_none()
    return ClaimedTest(row.id, row.target, row.connection_id) if row else None


def finish_test(
    conn: Connection, test_id: int, *, passed: bool, message: str, caller_arn: str | None = None
) -> None:
    conn.execute(
        text("""
        UPDATE connection_test SET status = :s, finished_at = now(), caller_arn = :arn,
          message = :m
        WHERE id = :i AND status = 'running'
    """),
        {
            "i": test_id,
            "s": "passed" if passed else "failed",
            "arn": caller_arn[:2048] if caller_arn else None,
            # AWS error messages can quote a principal or a policy: redacted like any output.
            "m": redact_text(message)[:2000],
        },
    )


def queued_tests(conn: Connection) -> int:
    """Tests waiting for a worker (on Kubernetes, for a scan Job to start)."""
    count: int = conn.execute(
        text("SELECT count(*) FROM connection_test WHERE status = 'queued'")
    ).scalar_one()
    return count


def expire_tests(conn: Connection) -> int:
    """Fails tests the worker never finished, so the UI stops waiting. Returns how many."""
    expired: int = conn.execute(
        text(f"""
        UPDATE connection_test SET status = 'failed', finished_at = now(),
          message = 'The worker did not finish this test. Check that it is running, '
                    'then test again.'
        WHERE (status = 'queued' AND requested_at < now() - interval '{QUEUED_FOR}')
           OR (status = 'running' AND started_at < now() - interval '{RUNNING_FOR}')
    """)  # noqa: S608 - constants only
    ).rowcount
    return expired
