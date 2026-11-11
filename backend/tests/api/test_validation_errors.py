"""A request the contract refuses answers 422 with where and why, never what was sent
(reviews/8c306e53, 2026-11-10): FastAPI's default answer carried each error's input, so a
connection body with a missing field echoed its secret access key to the sender."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from tests.api.conftest import csrf

pytestmark = pytest.mark.db
SECRET = "argus-test-only-not-a-real-secret-access-key"  # a fake, low-entropy value
TOKEN = "argus-test-only-not-a-real-session-token-" + "t" * 40  # a fake, low-entropy value


def _assert_no_echo(response: Any, field: str) -> None:
    assert response.status_code == 422, response.text
    assert SECRET not in response.text and TOKEN not in response.text
    detail = response.json()["detail"]
    assert detail and all(set(item) == {"type", "loc", "msg"} for item in detail)
    assert field in detail[0]["loc"]  # where, for the form to point at


def test_a_malformed_new_connection_does_not_echo_its_secret(signed_in: TestClient) -> None:
    refused = signed_in.post(
        "/api/v1/connections",
        headers=csrf(signed_in),
        json={
            "kind": "aws",
            "name": "local",
            "auth_method": "access_key",
            "access_key_id": "AKIA" + "Z" * 16,
            "secret_access_key": SECRET,
            "session_token": TOKEN,
        },
    )
    _assert_no_echo(refused, "account_id")


def test_a_malformed_replacement_key_does_not_echo_its_secret(signed_in: TestClient) -> None:
    created = signed_in.post(
        "/api/v1/connections",
        headers=csrf(signed_in),
        json={
            "kind": "aws",
            "name": "prod",
            "account_id": "210987654321",
            "auth_method": "assume_role",
            "role_arn": "arn:aws:iam::210987654321:role/ArgusScanner",
        },
    )
    assert created.status_code == 201, created.text
    refused = signed_in.patch(
        f"/api/v1/connections/{created.json()['id']}",
        headers=csrf(signed_in),
        json={
            "auth_method": "access_key",
            "access_key": {"secret_access_key": SECRET, "session_token": TOKEN},
        },
    )
    _assert_no_echo(refused, "access_key_id")
