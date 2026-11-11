"""Switch a connection's sign-in method (owner, 2026-11-09; palace decisions/95605c67, round 7):
Edit connection moves an AWS connection between assume role and an access key. The new method's
whole set comes with the switch, the old method's credentials are deleted in the same UPDATE,
the account never changes, and the audit row names the methods, never a value."""

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from tests.api.conftest import csrf

from argus import connections

pytestmark = pytest.mark.db
ACCOUNT = "210987654321"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/ArgusScanner"
EXTERNAL_ID = "argus-external-id-0042"
SECRET = "argus-test-only-not-a-real-secret-access-key"  # a fake, low-entropy value
TOKEN = "argus-test-only-not-a-real-session-token-" + "t" * 40  # a fake, low-entropy value
KEY = {"access_key_id": "AKIA" + "Z" * 16, "secret_access_key": SECRET}
# What an access key leaves in the row; all of it goes when the connection switches to a role.
KEY_COLUMNS = (
    "access_key_id",
    "secret_ciphertext",
    "secret_key_id",
    "session_token_ciphertext",
    "secret_set_at",
)


def _create(client: TestClient, **auth: Any) -> int:
    response = client.post(
        "/api/v1/connections",
        headers=csrf(client),
        json={"kind": "aws", "name": "prod", "account_id": ACCOUNT, **auth},
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def _patch(client: TestClient, connection_id: int, body: dict[str, Any]) -> Any:
    return client.patch(f"/api/v1/connections/{connection_id}", headers=csrf(client), json=body)


def _stored(owner: Engine) -> dict[str, Any]:
    with owner.connect() as conn:
        row = conn.execute(
            text(
                "SELECT auth_method, role_arn, external_id, access_key_id, secret_ciphertext, "
                "secret_key_id, session_token_ciphertext, secret_set_at FROM connection"
            )
        ).one()
    return dict(row._mapping)


def _updates(owner: Engine) -> list[dict[str, Any]]:
    with owner.connect() as conn:
        return list(
            conn.execute(
                text("SELECT detail FROM audit_log WHERE action = 'connection.update' ORDER BY id")
            ).scalars()
        )


def test_an_assume_role_connection_switches_to_an_access_key(
    signed_in: TestClient, owner: Engine
) -> None:
    cid = _create(signed_in, auth_method="assume_role", role_arn=ROLE, external_id=EXTERNAL_ID)
    switched = _patch(
        signed_in,
        cid,
        {
            "auth_method": "access_key",
            "access_key": {**KEY, "access_key_id": "ASIA" + "Z" * 16, "session_token": TOKEN},
        },
    )
    assert switched.status_code == 200, switched.text
    out = switched.json()
    assert out["auth_method"] == "access_key" and out["account_id"] == ACCOUNT
    assert out["role_arn"] is None and out["external_id_set"] is False
    assert out["access_key_id_hint"] == "…ZZZZ" and out["secret_set_at"] is not None
    assert SECRET not in switched.text and TOKEN not in switched.text
    stored = _stored(owner)
    # The role and its ExternalId are gone: no unused credential stays stored.
    assert stored["role_arn"] is None and stored["external_id"] is None
    assert stored["secret_ciphertext"] is not None and stored["session_token_ciphertext"]
    assert SECRET.encode() not in bytes(stored["secret_ciphertext"])
    with owner.connect() as conn:  # what the next run opens
        row = connections.get(conn, cid)
        assert row is not None
        auth = connections.open_auth(conn, row)
    assert (auth.method, auth.secret_access_key, auth.session_token) == (
        "access_key",
        SECRET,
        TOKEN,
    )
    assert _updates(owner) == [
        {
            "fields": ["auth_method"],
            "auth_method_before": "assume_role",
            "auth_method_after": "access_key",
        }
    ]


def test_an_access_key_connection_switches_to_assume_role_and_its_secret_is_gone(
    signed_in: TestClient, owner: Engine
) -> None:
    cid = _create(signed_in, auth_method="access_key", **KEY)
    switched = _patch(
        signed_in,
        cid,
        {
            "auth_method": "assume_role",
            "assume_role": {"role_arn": ROLE, "external_id": EXTERNAL_ID},
        },
    )
    assert switched.status_code == 200, switched.text
    out = switched.json()
    assert out["auth_method"] == "assume_role" and out["role_arn"] == ROLE
    assert out["external_id_set"] is True and EXTERNAL_ID not in switched.text
    assert out["access_key_id_hint"] is None and out["secret_set_at"] is None
    stored = _stored(owner)
    # No ciphertext, key id or date of the old key is left behind.
    assert {k: stored[k] for k in KEY_COLUMNS} == dict.fromkeys(KEY_COLUMNS)
    assert (stored["role_arn"], stored["external_id"]) == (ROLE, EXTERNAL_ID)
    details = _updates(owner)
    assert details == [
        {
            "fields": ["auth_method"],
            "auth_method_before": "access_key",
            "auth_method_after": "assume_role",
            "external_id": True,
        }
    ]
    assert EXTERNAL_ID not in json.dumps(details)


def test_a_switch_to_assume_role_may_have_no_external_id(
    signed_in: TestClient, owner: Engine
) -> None:
    cid = _create(signed_in, auth_method="access_key", **KEY)
    switched = _patch(
        signed_in, cid, {"auth_method": "assume_role", "assume_role": {"role_arn": ROLE}}
    )
    assert switched.status_code == 200, switched.text
    assert _stored(owner)["external_id"] is None
    assert _updates(owner)[-1]["external_id"] is False


@pytest.mark.parametrize(
    ("start", "body", "expected"),
    [
        ("role", {"auth_method": "access_key"}, "needs the access key"),
        (
            "role",
            {
                "auth_method": "access_key",
                "access_key": KEY,
                "assume_role": {"role_arn": ROLE},
            },
            "needs the access key, and only it",
        ),
        ("key", {"auth_method": "assume_role"}, "needs the role"),
        (
            "key",
            {"auth_method": "assume_role", "assume_role": {"external_id": EXTERNAL_ID}},
            "needs a role_arn",
        ),
        (
            "key",
            {
                "auth_method": "assume_role",
                "assume_role": {"role_arn": ROLE, "clear_external_id": True},
            },
            "needs a role_arn",
        ),
        (
            "key",
            {
                "auth_method": "assume_role",
                "assume_role": {"role_arn": "arn:aws:iam::111111111111:role/ArgusScanner"},
            },
            "the connection's account",
        ),
        (
            "key",
            {
                "auth_method": "assume_role",
                "assume_role": {"role_arn": ROLE, "external_id": "short"},
            },
            "16 or more",
        ),
        (
            "role",
            {
                "auth_method": "access_key",
                "access_key": {**KEY, "secret_access_key": SECRET + "\nregion = x"},
            },
            "",
        ),
    ],
    ids=[
        "to-key-without-key",
        "to-key-with-a-role-too",
        "to-role-without-role",
        "to-role-without-arn",
        "to-role-clearing",
        "to-role-in-another-account",
        "to-role-short-external-id",
        "to-key-not-one-word",
    ],
)
def test_a_half_or_bad_switch_is_refused_and_changes_nothing(
    signed_in: TestClient, owner: Engine, start: str, body: dict[str, Any], expected: str
) -> None:
    cid = (
        _create(signed_in, auth_method="assume_role", role_arn=ROLE)
        if start == "role"
        else _create(signed_in, auth_method="access_key", **KEY)
    )
    before = _stored(owner)
    refused = _patch(signed_in, cid, body)
    assert refused.status_code == 422, refused.text
    assert expected in refused.json()["detail"]
    assert SECRET not in refused.text and EXTERNAL_ID not in refused.text
    assert _stored(owner) == before
    assert _updates(owner) == []


def test_the_stored_method_is_not_a_switch(signed_in: TestClient, owner: Engine) -> None:
    """auth_method equal to the stored one changes nothing by itself: a rename stays a rename."""
    cid = _create(signed_in, auth_method="assume_role", role_arn=ROLE)
    renamed = _patch(signed_in, cid, {"auth_method": "assume_role", "name": "prod-2"})
    assert renamed.status_code == 200 and renamed.json()["name"] == "prod-2"
    assert _stored(owner)["role_arn"] == ROLE
    assert _updates(owner) == [{"fields": ["name"]}]


def test_a_demo_connection_has_no_sign_in_method_to_switch(
    signed_in: TestClient, owner: Engine
) -> None:
    demo = signed_in.post(
        "/api/v1/connections",
        headers=csrf(signed_in),
        json={"kind": "demo", "name": "demo", "seed": 3, "backfill_days": 1},
    )
    assert demo.status_code == 201, demo.text
    refused = _patch(
        signed_in,
        demo.json()["id"],
        {"auth_method": "access_key", "access_key": KEY},
    )
    assert refused.status_code == 422
    assert "only AWS connections" in refused.json()["detail"]


def test_open_auth_follows_a_switch_made_after_the_row_was_read(
    signed_in: TestClient, owner: Engine
) -> None:
    """A run or a test reads the connection, then opens its credentials: a switch committed in
    between must not pair the old method with the new credentials."""
    cid = _create(signed_in, auth_method="assume_role", role_arn=ROLE)
    with owner.connect() as conn:
        stale = connections.get(conn, cid)
    assert stale is not None and stale.auth_method == "assume_role"
    assert (
        _patch(signed_in, cid, {"auth_method": "access_key", "access_key": KEY}).status_code == 200
    )
    with owner.connect() as conn:
        auth = connections.open_auth(conn, stale)
    assert (auth.method, auth.access_key_id, auth.secret_access_key, auth.role_arn) == (
        "access_key",
        KEY["access_key_id"],
        SECRET,
        None,
    )


def test_a_change_checked_against_the_old_method_is_refused_after_a_switch(
    signed_in: TestClient, owner: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A role edit that loses a race to a switch to an access key leaves no unused ExternalId."""
    cid = _create(signed_in, auth_method="assume_role", role_arn=ROLE)
    with owner.connect() as conn:
        stale = connections.get(conn, cid)
    assert (
        _patch(signed_in, cid, {"auth_method": "access_key", "access_key": KEY}).status_code == 200
    )
    # The losing request read the connection before the switch committed.
    monkeypatch.setattr(connections, "get", lambda _conn, _id: stale)
    with owner.connect() as conn, pytest.raises(connections.ConnectionError, match="changed while"):
        connections.update(
            conn,
            connection_id=cid,
            actor="racer",
            role=connections.RoleChange(role_arn=ROLE, external_id=EXTERNAL_ID),
        )
    stored = _stored(owner)
    assert stored["auth_method"] == "access_key" and stored["external_id"] is None
