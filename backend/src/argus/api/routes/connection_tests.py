"""Test connection (ADR-0024, amended 2026-10-07): can Argus reach an account, and can it sign
in and write raw output as the platform identity? The API queues the test (it has no route
out, ADR-0019); the worker runs it within seconds; the UI polls the result."""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Request, status
from pydantic import BaseModel

from argus import connections
from argus.api.deps import Admin, Db, Operator, client_ip
from argus.connections import checks

router = APIRouter(tags=["connections"])


class TestQueued(BaseModel):
    id: int


class TestOut(BaseModel):
    id: int
    target: Literal["connection", "identity"]
    connection_id: int | None
    # queued and running: the UI keeps polling; passed or failed: `message` says what.
    status: Literal["queued", "running", "passed", "failed"]
    requested_by: str
    requested_at: datetime
    finished_at: datetime | None
    # Who AWS says Argus signed in as.
    caller_arn: str | None
    message: str | None


@router.post("/connections/{connection_id}/test", status_code=status.HTTP_202_ACCEPTED)
def test_connection(connection_id: int, conn: Db, user: Operator, request: Request) -> TestQueued:
    """Queues a test of an AWS connection (a Demo connection has nothing to test: 422). Asking
    while one is open returns the open one."""
    connection = connections.get(conn, connection_id)
    if connection is None:
        raise LookupError(connection_id)
    if connection.kind != "aws":
        raise connections.ConnectionError("a Demo connection has nothing to test")
    test_id = checks.request_test(
        conn,
        target="connection",
        connection_id=connection_id,
        actor=user,
        client_ip=client_ip(request),
    )
    conn.commit()
    return TestQueued(id=test_id)


@router.post("/settings/identity/test", status_code=status.HTTP_202_ACCEPTED)
def test_identity(conn: Db, user: Admin, request: Request) -> TestQueued:
    """Queues a test of the platform identity: sign in, then write a marker to each tool's
    folder of the raw output bucket."""
    test_id = checks.request_test(
        conn, target="identity", connection_id=None, actor=user, client_ip=client_ip(request)
    )
    conn.commit()
    return TestQueued(id=test_id)


@router.get("/connection-tests/{test_id}")
def get_test(test_id: int, conn: Db, _user: Operator) -> TestOut:
    view = checks.get_test(conn, test_id)
    if view is None:
        raise LookupError(test_id)
    return TestOut.model_validate(view, from_attributes=True)
