"""Invariants the application relies on, proven against the real schema."""

from collections.abc import Iterator

import pytest
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError

pytestmark = pytest.mark.db


@pytest.fixture
def conn(migrated: Engine) -> Iterator[Connection]:
    with migrated.connect() as connection:
        tx = connection.begin()
        yield connection
        tx.rollback()


def _demo(conn: Connection, name: str = "demo", account: str = "111111111111") -> int:
    return int(
        conn.execute(
            text(
                "INSERT INTO connection (name, kind, account_id, auth_method, created_by, "
                "updated_by) VALUES (:n, 'demo', :a, 'none', 'test', 'test') RETURNING id"
            ),
            {"n": name, "a": account},
        ).scalar_one()
    )


def _fails(conn: Connection, statement: str, params: dict[str, object] | None = None) -> str:
    savepoint = conn.begin_nested()
    with pytest.raises(DBAPIError) as exc:
        conn.execute(text(statement), params or {})
    savepoint.rollback()
    return str(exc.value.orig)


# --------------------------------------------------------------- connection credentials
@pytest.mark.parametrize(
    ("columns", "values"),
    [
        ("kind, auth_method", "'aws', 'assume_role'"),  # role ARN and ExternalId missing
        ("kind, auth_method, access_key_id", "'aws', 'access_key', 'AKIDEXAMPLE'"),  # no secret
        ("kind, auth_method", "'demo', 'access_key'"),  # demo never authenticates
        ("kind, auth_method", "'aws', 'none'"),  # aws always authenticates
    ],
)
def test_credential_fields_must_match_auth_method(
    conn: Connection, columns: str, values: str
) -> None:
    error = _fails(
        conn,
        # Parametrised test constants above, not input.
        f"INSERT INTO connection (name, account_id, created_by, updated_by, {columns}) "  # noqa: S608
        f"VALUES ('x', '222222222222', 't', 't', {values})",
    )
    assert "violates check constraint" in error


def test_account_id_must_be_twelve_digits(conn: Connection) -> None:
    assert "violates check constraint" in _fails(
        conn,
        "INSERT INTO connection (name, kind, account_id, auth_method, created_by, updated_by) "
        "VALUES ('x', 'demo', '1234', 'none', 't', 't')",
    )


def test_api_can_write_a_secret_but_never_read_it(conn: Connection) -> None:
    conn.execute(text("SET LOCAL ROLE argus_api"))
    conn.execute(
        text(
            "INSERT INTO connection (name, kind, account_id, auth_method, access_key_id, "
            "secret_ciphertext, secret_key_id, created_by, updated_by) VALUES ('local', 'aws', "
            "'333333333333', 'access_key', 'AKIDEXAMPLE', '\\x01', 'k1', 'admin', 'admin')"
        )
    )
    assert conn.execute(text("SELECT name FROM connection")).scalar_one() == "local"
    assert "permission denied" in _fails(conn, "SELECT secret_ciphertext FROM connection")


def test_api_can_write_a_session_token_but_never_read_it(conn: Connection) -> None:
    conn.execute(text("SET LOCAL ROLE argus_api"))
    conn.execute(
        text(
            "INSERT INTO connection (name, kind, account_id, auth_method, access_key_id, "
            "secret_ciphertext, session_token_ciphertext, secret_key_id, created_by, updated_by) "
            "VALUES ('sso', 'aws', '333333333334', 'access_key', 'ASIDEXAMPLE', '\\x01', '\\x02', "
            "'k1', 'admin', 'admin')"
        )
    )
    conn.execute(
        text(
            "INSERT INTO platform_setting (topic, value, secret_ciphertext, "
            "session_token_ciphertext, secret_key_id, updated_by) "
            "VALUES ('identity', '{}', '\\x01', '\\x02', 'k1', 'admin')"
        )
    )
    for table in ("connection", "platform_setting"):
        assert "permission denied" in _fails(
            conn,
            f"SELECT session_token_ciphertext FROM {table}",  # noqa: S608 - constant above
        )


@pytest.mark.parametrize(
    ("statement"),
    [
        "INSERT INTO connection (name, kind, account_id, auth_method, role_arn, external_id, "
        "session_token_ciphertext, created_by, updated_by) VALUES ('x', 'aws', '222222222222', "
        "'assume_role', 'arn:aws:iam::222222222222:role/R', 'external-id-0123456789', '\\x02', "
        "'t', 't')",
        "INSERT INTO platform_setting (topic, value, session_token_ciphertext, updated_by) "
        "VALUES ('identity', '{}', '\\x02', 't')",
    ],
    ids=["connection-assume-role", "identity-without-secret"],
)
def test_a_session_token_needs_an_access_key_secret(conn: Connection, statement: str) -> None:
    assert "violates check constraint" in _fails(conn, statement)


def test_api_sees_whether_an_external_id_is_set_never_its_value(conn: Connection) -> None:
    conn.execute(text("SET LOCAL ROLE argus_api"))
    conn.execute(
        text(
            "INSERT INTO connection (name, kind, account_id, auth_method, role_arn, external_id, "
            "created_by, updated_by) VALUES ('prod', 'aws', '444444444444', 'assume_role', "
            "'arn:aws:iam::444444444444:role/ArgusScanner', 'external-id-0123456789', 'a', 'a')"
        )
    )
    assert conn.execute(text("SELECT external_id_set FROM connection")).scalar_one() is True
    assert "permission denied" in _fails(conn, "SELECT external_id FROM connection")
    assert "permission denied" in _fails(conn, "SELECT * FROM connection")


def test_api_cannot_delete_a_connection(conn: Connection) -> None:
    _demo(conn)
    conn.execute(text("SET LOCAL ROLE argus_api"))
    assert "permission denied" in _fails(conn, "DELETE FROM connection")


def test_worker_can_read_the_secret(conn: Connection) -> None:
    _demo(conn)
    conn.execute(text("SET LOCAL ROLE argus_worker"))
    conn.execute(text("SELECT secret_ciphertext, session_token_ciphertext FROM connection"))
    conn.execute(text("SELECT secret_ciphertext, session_token_ciphertext FROM platform_setting"))


# --------------------------------------------------------------- run requests
def test_only_one_claimed_request_per_connection(conn: Connection) -> None:
    cid = _demo(conn)
    insert = (
        "INSERT INTO run_request (connection_id, tool, reason, status, claimed_at, claimed_by, "
        "requested_by) VALUES (:c, :t, 'manual', 'claimed', now(), 'w1', 'admin')"
    )
    conn.execute(text(insert), {"c": cid, "t": "steampipe"})
    assert "run_request_one_claimed_per_connection" in _fails(
        conn, insert, {"c": cid, "t": "prowler"}
    )


def test_one_request_per_schedule_occurrence_and_tool(conn: Connection) -> None:
    cid = _demo(conn)
    sid = conn.execute(
        text(
            "INSERT INTO schedule (name, tools, cron, updated_by) "
            "VALUES ('nightly', ARRAY['steampipe', 'prowler'], '0 2 * * *', 'admin') RETURNING id"
        )
    ).scalar_one()
    insert = (
        "INSERT INTO run_request (connection_id, tool, reason, schedule_id, occurrence_at, "
        "requested_by) VALUES (:c, :t, 'schedule', :s, '2026-10-02 02:00Z', 'scheduler')"
    )
    conn.execute(text(insert), {"c": cid, "s": sid, "t": "steampipe"})
    conn.execute(text(insert), {"c": cid, "s": sid, "t": "prowler"})  # same occurrence
    assert "run_request_one_per_occurrence" in _fails(
        conn, insert, {"c": cid, "s": sid, "t": "prowler"}
    )


@pytest.mark.parametrize(
    "tools",
    ["ARRAY[]::text[]", "ARRAY['prowler', 'prowler']", "ARRAY['nmap']"],
    ids=["none", "duplicate", "unknown"],
)
def test_a_schedule_names_each_known_tool_once(conn: Connection, tools: str) -> None:
    assert "schedule_tools_valid" in _fails(
        conn,
        # Parametrised constants above, not input.
        f"INSERT INTO schedule (name, tools, cron, updated_by) "  # noqa: S608
        f"VALUES ('x', {tools}, '0 2 * * *', 'admin')",
    )


def test_api_can_only_cancel_requests(conn: Connection) -> None:
    cid = _demo(conn)
    conn.execute(text("SET LOCAL ROLE argus_api"))
    rid = conn.execute(
        text(
            "INSERT INTO run_request (connection_id, tool, reason, requested_by) "
            "VALUES (:c, 'cloudfox', 'manual', 'admin') RETURNING id"
        ),
        {"c": cid},
    ).scalar_one()
    conn.execute(
        text("UPDATE run_request SET status = 'cancelled', finished_at = now() WHERE id = :r"),
        {"r": rid},
    )
    assert "permission denied" in _fails(
        conn, "UPDATE run_request SET claimed_by = 'api' WHERE id = :r", {"r": rid}
    )


# --------------------------------------------------------------- history and roles
def test_a_day_without_a_partition_fails_loudly(conn: Connection) -> None:
    assert "no partition" in _fails(
        conn,
        "INSERT INTO metric_daily (snapshot_date, connection_id, metric, value) "
        "VALUES ('2001-01-01', 0, 'assets', 1)",
    )


def test_worker_creates_and_drops_partitions_api_cannot(conn: Connection) -> None:
    conn.execute(text("SET LOCAL ROLE argus_worker"))
    created = conn.execute(
        text("SELECT argus_ensure_partitions('2001-01-01', '2001-01-31')")
    ).scalar_one()
    assert created == 8  # one per partitioned table
    dropped = set(conn.execute(text("SELECT argus_drop_partitions_before('2001-02-01')")).scalars())
    assert {"metric_daily_200101", "compliance_rollup_200101", "flow_snapshot_200101"} <= dropped

    conn.execute(text("RESET ROLE"))
    conn.execute(text("SET LOCAL ROLE argus_api"))
    assert "permission denied" in _fails(
        conn, "SELECT argus_ensure_partitions('2001-01-01', '2001-01-31')"
    )


def test_api_role_has_a_statement_timeout(conn: Connection) -> None:
    config = conn.execute(
        text("SELECT rolconfig FROM pg_roles WHERE rolname = 'argus_api'")
    ).scalar_one()
    assert "statement_timeout=5s" in config


def test_api_cannot_write_history(conn: Connection) -> None:
    conn.execute(text("SET LOCAL ROLE argus_api"))
    assert "permission denied" in _fails(
        conn,
        "INSERT INTO metric_daily (snapshot_date, connection_id, metric, value) "
        "VALUES (current_date, 0, 'assets', 1)",
    )


def test_audit_log_is_append_only_for_application_roles(conn: Connection) -> None:
    conn.execute(text("SET LOCAL ROLE argus_api"))
    conn.execute(text("INSERT INTO audit_log (actor, action) VALUES ('admin', 'login')"))
    assert "permission denied" in _fails(conn, "DELETE FROM audit_log")
    assert "permission denied" in _fails(conn, "UPDATE audit_log SET actor = 'x'")
