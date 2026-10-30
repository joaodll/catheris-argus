"""Schema migration, run once per deploy by the one-shot `migrate` service (a Job on
Kubernetes) as the schema owner.

1. `alembic upgrade head`.
2. Gives the argus_api, argus_worker and argus_scheduler roles LOGIN and the passwords from the
   environment. Passwords are deployment facts: the migration creates the roles, the operator
   owns the secrets. A role whose password variable is unset is left as it is.
3. The first admin (ADR-0041): ARGUS_BOOTSTRAP_ADMIN_USERNAME with ARGUS_BOOTSTRAP_ADMIN_PASSWORD
   or ..._PASSWORD_HASH creates that admin while no active admin exists, and never changes an
   existing user. Before users existed the admin was ARGUS_ADMIN_USERNAME (default "admin") with
   ARGUS_ADMIN_PASSWORD_HASH: an upgrade that still has the hash becomes that admin, so nobody is
   locked out. The operator removes the values after the first sign-in.

All three steps hold an advisory lock, so two migrate runs never interleave.

`--wait` is for the other processes (ADR-0039): it waits until the database is at this image's
head, or at a revision this image does not know (a newer image migrated it), connecting as the
process's own role. A role without LOGIN or grants yet, or a missing table, means "not yet".
"""

import argparse
import logging
import os
import sys
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from argus.auth import bootstrap_admin
from argus.core.config import get_settings
from argus.core.db import get_engine, require_pool
from argus.core.logging import configure_logging

ROLE_PASSWORD_ENV = {
    "argus_api": "ARGUS_API_DB_PASSWORD",
    "argus_worker": "ARGUS_WORKER_DB_PASSWORD",
    "argus_scheduler": "ARGUS_SCHEDULER_DB_PASSWORD",
}
MIGRATE_LOCK = "argus.migrate"
# The migrate lock on one connection, the role passwords on another (Alembic has its own engine).
MIGRATE_CONNECTIONS = 2
WAIT_POLL_SECONDS = 2.0

log = logging.getLogger("argus.migrate")


def upgrade(alembic_ini: Path) -> None:
    command.upgrade(Config(str(alembic_ini)), "head")


def schema_ready(alembic_ini: Path) -> bool:
    """True when the database is at this image's head or past it. False while the database
    is unreachable, the role cannot log in or read alembic_version, or a migration is due."""
    script = ScriptDirectory.from_config(Config(str(alembic_ini)))
    known = {revision.revision for revision in script.walk_revisions()}
    try:
        with get_engine().connect() as conn:
            current = set(conn.execute(text("SELECT version_num FROM alembic_version")).scalars())
    except DBAPIError:
        return False
    return script.get_current_head() in current or bool(current - known)


def wait_for_schema(alembic_ini: Path, *, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if schema_ready(alembic_ini):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(WAIT_POLL_SECONDS)


def set_role_passwords() -> list[str]:
    """Returns the roles whose password was set."""
    updated: list[str] = []
    with get_engine().begin() as conn:
        # psycopg's own cursor: the statement is a Composed with a quoted literal, and is never
        # run through a layer that could treat a % in the password as a placeholder.
        driver = conn.connection.driver_connection
        if driver is None:
            raise RuntimeError("database connection is closed")
        with driver.cursor() as cur:
            for role, env in ROLE_PASSWORD_ENV.items():
                password = os.environ.get(env)
                if not password:
                    continue
                statement = sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(password)
                )
                cur.execute(statement)
                updated.append(role)
    return updated


def bootstrap() -> str | None:
    """The first admin from the environment, or None when nothing asks for one: no username,
    or a username alone (the chart always passes it; the operator removes the password after the
    first sign-in)."""
    username = os.environ.get("ARGUS_BOOTSTRAP_ADMIN_USERNAME")
    password = os.environ.get("ARGUS_BOOTSTRAP_ADMIN_PASSWORD")
    password_hash = os.environ.get("ARGUS_BOOTSTRAP_ADMIN_PASSWORD_HASH")
    if not (password or password_hash) and os.environ.get("ARGUS_ADMIN_PASSWORD_HASH"):
        # Before users (ADR-0041): the environment's admin becomes the first user.
        username = os.environ.get("ARGUS_ADMIN_USERNAME") or username or "admin"
        password_hash = os.environ["ARGUS_ADMIN_PASSWORD_HASH"]
    if not username or not (password or password_hash):
        return None
    with get_engine().begin() as conn:
        return bootstrap_admin(
            conn, username=username, password=password or None, password_hash=password_hash
        )


def migrate(alembic_ini: Path) -> list[str]:
    """Upgrade, passwords, then the first admin, under one advisory lock. Returns the roles
    given LOGIN."""
    with get_engine().connect() as lock:
        lock.execute(text("SELECT pg_advisory_lock(hashtext(:k))"), {"k": MIGRATE_LOCK})
        lock.commit()
        try:
            upgrade(alembic_ini)
            roles = set_role_passwords()
            admin = bootstrap()
            if admin is not None:
                log.info("bootstrap admin", extra={"result": admin})
            return roles
        finally:
            lock.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": MIGRATE_LOCK})
            lock.commit()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply migrations and set role passwords")
    parser.add_argument("--config", type=Path, required=True, help="path to alembic.ini")
    parser.add_argument(
        "--wait", action="store_true", help="only wait until the schema is at this image's head"
    )
    parser.add_argument("--timeout", type=float, default=600.0, help="seconds --wait waits")
    args = parser.parse_args(argv)

    configure_logging(get_settings().log_level)
    if args.wait:
        if wait_for_schema(args.config, timeout_seconds=args.timeout):
            log.info("schema ready")
            return 0
        log.error("schema not ready", extra={"timeout_seconds": args.timeout})
        return 1
    require_pool(MIGRATE_CONNECTIONS, process="migrate")
    roles = migrate(args.config)
    log.info("migrations applied", extra={"roles_with_login": roles})
    return 0


if __name__ == "__main__":
    sys.exit(main())
