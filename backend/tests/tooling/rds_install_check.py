"""Install Argus the way docs/runbook-kubernetes.md says to on RDS, and check the result.

    docker compose --profile rds-check run --rm rds-check
    docker compose rm -sf rds-check-postgres

The image's superuser appears only to make `rds_master`, a role with CREATEROLE and CREATEDB and no
superuser, like an RDS master user. Everything after that runs without a superuser, which the rest
of the test suite never does: Compose and kind connect as the image's POSTGRES_USER. So a migration
that needs a superuser fails here, not on the first real install.

It is an approximation: rds_master has no rds_superuser, and RDS's own parameters are not set.

It needs its own Postgres, because roles belong to the whole cluster and the shared test database
already has Argus's. Every password is generated here and dies with the run.
"""

import os
import secrets
import subprocess
import sys
from collections.abc import Callable

import psycopg
from psycopg import errors, sql

HOST = os.environ["ARGUS_DB_HOST"]
ALEMBIC_INI = "/app/alembic.ini"
OWNER = "argus_owner"
DATABASE = "argus"


def password() -> str:
    return secrets.token_urlsafe(24)


MASTER_PASSWORD = password()
OWNER_PASSWORD = password()
ROLE_PASSWORDS = {
    "argus_api": password(),
    "argus_worker": password(),
    "argus_scheduler": password(),
}
ROLE_PASSWORD_ENV = {
    "argus_api": "ARGUS_API_DB_PASSWORD",
    "argus_worker": "ARGUS_WORKER_DB_PASSWORD",
    "argus_scheduler": "ARGUS_SCHEDULER_DB_PASSWORD",
}
# A password replaced during the run: it must not be in the server's log either.
ROTATED_PASSWORDS: dict[str, str] = {}

Check = Callable[[], None]
Conn = psycopg.Connection[tuple[object, ...]]


def connect(user: str, secret: str, dbname: str = DATABASE) -> Conn:
    return psycopg.connect(
        host=HOST, user=user, password=secret, dbname=dbname, autocommit=True, connect_timeout=5
    )


def superuser(dbname: str = DATABASE) -> Conn:
    return connect("postgres", os.environ["RDS_CHECK_SUPERUSER_PASSWORD"], dbname)


def master() -> Conn:
    return connect("rds_master", MASTER_PASSWORD, "postgres")


def role(name: str) -> Conn:
    return connect(name, ROLE_PASSWORDS[name])


def statement(text: str) -> sql.SQL:
    """Our own fixed text, typed for psycopg."""
    return sql.SQL(text)


def create_owner_and_database(conn: Conn, name: str) -> None:
    """The runbook's script after CREATE ROLE, as the master user."""
    conn.execute(statement(f"GRANT {OWNER} TO rds_master"))
    conn.execute(statement(f"CREATE DATABASE {name} OWNER {OWNER}"))
    conn.execute(statement(f"REVOKE {OWNER} FROM rds_master"))


def run_migrate(database: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "ARGUS_DB_HOST": HOST,
        "ARGUS_DB_NAME": database,
        "ARGUS_DB_USER": OWNER,
        "ARGUS_DB_PASSWORD": OWNER_PASSWORD,
        "ARGUS_BOOTSTRAP_ADMIN_USERNAME": "admin",
        "ARGUS_BOOTSTRAP_ADMIN_PASSWORD": password(),
    }
    env |= {ROLE_PASSWORD_ENV[name]: value for name, value in ROLE_PASSWORDS.items()}
    return subprocess.run(  # noqa: S603 - our own interpreter and module
        [sys.executable, "-m", "argus.entrypoints.migrate", "--config", ALEMBIC_INI],
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def migrate_or_die(database: str) -> None:
    done = run_migrate(database)
    if done.returncode != 0:
        print(done.stdout, done.stderr, sep="\n")
        raise SystemExit(f"FAIL: migrate exited {done.returncode} on {database}")


def refused(conn: Conn, text: str) -> None:
    try:
        conn.execute(statement(text))
    except errors.InsufficientPrivilege:
        return
    raise AssertionError(f"{conn.info.user} was allowed: {text}")


def one(conn: Conn, text: str) -> object:
    row = conn.execute(statement(text)).fetchone()
    assert row is not None, text
    return row[0]


def one_with(conn: Conn, text: str, value: str) -> object:
    row = conn.execute(statement(text), (value,)).fetchone()
    assert row is not None, text
    return row[0]


def check_owner_is_not_a_superuser() -> None:
    with superuser() as conn:
        assert one(conn, "SELECT rolsuper FROM pg_roles WHERE rolname = 'argus_owner'") is False
        assert one(conn, "SELECT rolsuper FROM pg_roles WHERE rolname = 'rds_master'") is False


def check_the_owner_owns_everything() -> None:
    with superuser() as conn:
        others = conn.execute(
            statement("""
            SELECT c.relname, pg_get_userbyid(c.relowner) FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
              AND pg_get_userbyid(c.relowner) <> 'argus_owner'
            """)
        ).fetchall()
    assert not others, f"tables with another owner: {others}"


def check_extension_and_collation() -> None:
    with superuser() as conn:
        assert one(conn, "SELECT count(*) FROM pg_extension WHERE extname = 'pg_trgm'") == 1
        assert one(conn, "SELECT count(*) FROM pg_collation WHERE collname = 'argus_natural'") == 1


def check_role_limits() -> None:
    with role("argus_api") as conn:
        assert one(conn, "SHOW statement_timeout") == "5s"
        assert one(conn, "SHOW idle_in_transaction_session_timeout") == "30s"
    with role("argus_worker") as conn:
        assert one(conn, "SHOW idle_in_transaction_session_timeout") == "5min"
    with role("argus_scheduler") as conn:
        assert one(conn, "SHOW statement_timeout") == "30s"
        assert one(conn, "SHOW idle_in_transaction_session_timeout") == "1min"


def check_passwords_are_scram() -> None:
    with superuser() as conn:
        rows = conn.execute(
            statement("""
            SELECT rolname, rolpassword FROM pg_authid
            WHERE rolname IN ('argus_owner', 'argus_api', 'argus_worker', 'argus_scheduler')
            """)
        ).fetchall()
    assert len(rows) == 4, rows
    for name, stored in rows:
        assert str(stored).startswith("SCRAM-SHA-256$"), f"{name} has no SCRAM password"


def check_passwords_never_reach_the_server_log() -> None:
    """RDS can send statements to CloudWatch (log_statement, pgaudit), and migrate runs on every
    upgrade. Migrate hashes the three role passwords first, so none of them is ever in a log."""
    with superuser() as conn:
        files = conn.execute(statement("SELECT name FROM pg_ls_logdir()")).fetchall()
        logged = "".join(
            str(one_with(conn, "SELECT pg_read_file(%s)", f"log/{row[0]}")) for row in files
        )
    assert "ALTER ROLE argus_api" in logged, "the server did not log migrate's statements"
    for name, secret in [*ROLE_PASSWORDS.items(), *ROTATED_PASSWORDS.items()]:
        assert secret not in logged, f"the plain password of {name} is in the server log"


def check_the_worker_makes_partitions_the_owner_owns() -> None:
    with role("argus_worker") as conn:
        one(conn, "SELECT argus_ensure_partitions('2035-01-01', '2035-01-31')")
    with superuser() as conn:
        rows = conn.execute(
            statement("""
            SELECT c.relname, pg_get_userbyid(c.relowner) FROM pg_class c
            WHERE c.relispartition AND c.relkind = 'r' AND c.relname LIKE '%2035%'
            """)
        ).fetchall()
    assert rows, "no partition for 2035"
    wrong = [row for row in rows if row[1] != OWNER]
    assert not wrong, f"partitions with another owner: {wrong}"


def check_the_api_cannot_read_secrets() -> None:
    with role("argus_api") as conn:
        one(conn, "SELECT count(id) FROM connection")
        refused(conn, "SELECT secret_ciphertext FROM connection")
        refused(conn, "SELECT external_id FROM connection")
        refused(conn, "SELECT secret_ciphertext FROM platform_setting")


def check_the_audit_log_is_append_only() -> None:
    for name in ROLE_PASSWORDS:
        with role(name) as conn:
            refused(conn, "UPDATE audit_log SET action = action")
            refused(conn, "DELETE FROM audit_log")


def check_each_role_stays_in_its_lane() -> None:
    with role("argus_worker") as conn:
        refused(conn, "SELECT count(*) FROM app_user")
        refused(conn, "SELECT count(*) FROM user_session")
        refused(conn, "SELECT count(*) FROM audit_log")
    with role("argus_scheduler") as conn:
        refused(conn, "SELECT secret_ciphertext FROM connection")
        refused(conn, "SELECT count(*) FROM resource")
    for name in ROLE_PASSWORDS:
        with role(name) as conn:
            refused(conn, "CREATE TABLE public.not_allowed (id integer)")


CHECKS: dict[str, Check] = {
    "neither the owner nor the master is a superuser": check_owner_is_not_a_superuser,
    "the owner owns every table and partition": check_the_owner_owns_everything,
    "pg_trgm and the collation exist": check_extension_and_collation,
    "each role has its limits": check_role_limits,
    "passwords are stored as SCRAM": check_passwords_are_scram,
    "no plain password reaches the server's log": check_passwords_never_reach_the_server_log,
    "the worker makes partitions the owner owns": check_the_worker_makes_partitions_the_owner_owns,
    "the api cannot read stored secrets": check_the_api_cannot_read_secrets,
    "the audit log is append-only": check_the_audit_log_is_append_only,
    "each role stays in its lane": check_each_role_stays_in_its_lane,
}


def check_rotating_a_password() -> None:
    """A second run changes roles that already exist, as every upgrade does."""
    old = ROLE_PASSWORDS["argus_api"]
    ROTATED_PASSWORDS["argus_api"] = old
    ROLE_PASSWORDS["argus_api"] = password()
    migrate_or_die(DATABASE)
    role("argus_api").close()
    try:
        connect("argus_api", old).close()
    except psycopg.OperationalError:
        return
    raise AssertionError("the old argus_api password still signs in")


def check_precreated_roles_fail() -> None:
    """The runbook says not to create the application roles yourself. Prove why: the owner has no
    admin right on a role someone else created, so migrate cannot change it."""
    with master() as conn:
        conn.execute(statement("CREATE ROLE argus_api NOLOGIN"))
        create_owner_and_database(conn, "argus_precreated")
    done = run_migrate("argus_precreated")
    assert done.returncode != 0, "migrate succeeded on a role the owner did not create"
    assert "permission denied" in done.stdout + done.stderr, done.stdout + done.stderr
    with connect(OWNER, OWNER_PASSWORD, "postgres") as conn:
        conn.execute(statement("DROP DATABASE argus_precreated"))
    with master() as conn:
        conn.execute(statement("DROP ROLE argus_api"))


def print_grants() -> None:
    with superuser() as conn:
        tables = conn.execute(
            statement("""
            SELECT grantee, table_name, string_agg(privilege_type, ', ' ORDER BY privilege_type)
            FROM information_schema.role_table_grants
            WHERE table_schema = 'public' AND grantee LIKE 'argus\\_%' AND grantee <> 'argus_owner'
              AND table_name NOT IN (
                SELECT relname FROM pg_class WHERE relispartition)
            GROUP BY grantee, table_name ORDER BY grantee, table_name
            """)
        ).fetchall()
        columns = conn.execute(
            statement("""
            SELECT grantee, table_name, privilege_type,
                   string_agg(column_name, ', ' ORDER BY column_name)
            FROM information_schema.column_privileges c
            WHERE table_schema = 'public' AND grantee LIKE 'argus\\_%' AND grantee <> 'argus_owner'
              AND NOT EXISTS (
                SELECT 1 FROM information_schema.role_table_grants t
                WHERE t.table_schema = 'public' AND t.table_name = c.table_name
                  AND t.grantee = c.grantee AND t.privilege_type = c.privilege_type)
              AND table_name NOT IN (SELECT relname FROM pg_class WHERE relispartition)
            GROUP BY grantee, table_name, privilege_type ORDER BY grantee, table_name
            """)
        ).fetchall()
        functions = conn.execute(
            statement("""
            SELECT grantee, routine_name FROM information_schema.role_routine_grants
            WHERE routine_schema = 'public' AND grantee LIKE 'argus\\_%'
              AND grantee <> 'argus_owner' ORDER BY grantee, routine_name
            """)
        ).fetchall()
    print("\n== grants, read from the database")
    for grantee, table, privileges in tables:
        print(f"{grantee}\t{table}\t{privileges}")
    print("\n== column grants")
    for grantee, table, privilege, names in columns:
        print(f"{grantee}\t{table}\t{privilege}\t{names}")
    print("\n== function grants")
    for grantee, routine in functions:
        print(f"{grantee}\t{routine}")


def main() -> int:
    with superuser("postgres") as conn:
        conn.execute(
            sql.SQL("CREATE ROLE rds_master LOGIN CREATEROLE CREATEDB PASSWORD {}").format(
                sql.Literal(MASTER_PASSWORD)
            )
        )
    with master() as conn:
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN CREATEROLE PASSWORD {}").format(
                sql.Identifier(OWNER), sql.Literal(OWNER_PASSWORD)
            )
        )

    print("== pre-created roles")
    check_precreated_roles_fail()
    print("ok: migrate refuses roles the owner did not create")

    print("\n== the install, as the runbook says")
    with master() as conn:
        create_owner_and_database(conn, DATABASE)
    migrate_or_die(DATABASE)
    print("ok: migrate ran without a superuser, creating the roles")
    check_rotating_a_password()
    print("ok: a second migrate changed existing roles; the old password no longer signs in")

    failures = 0
    for name, check in CHECKS.items():
        try:
            check()
        except (AssertionError, psycopg.Error) as exc:
            failures += 1
            print(f"FAIL: {name}: {exc}")
        else:
            print(f"ok: {name}")

    print_grants()
    if failures:
        print(f"\nrds-check FAILED: {failures} of {len(CHECKS)} checks")
        return 1
    print("\nrds-check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
