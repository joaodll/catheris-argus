"""Users and their roles (ADR-0041): an admin manages them, the migrate step creates the first
admin from the environment once, and admin-tools resets a forgotten password.

Every write here is audited in the caller's transaction, which the caller commits. Writes to
users take one advisory lock, so two admins demoting each other at once cannot leave none.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from argon2 import extract_parameters
from argon2.exceptions import InvalidHashError
from argon2.low_level import Type
from sqlalchemy import Connection, text

from argus.auth.sessions import (
    Role,
    SessionUser,
    TooManyAttemptsError,
    end_sessions,
    hash_password,
    limited,
    password_matches,
    serialize_attempts,
)
from argus.core import audit
from argus.core.config import get_settings

USERNAME = re.compile(r"^[a-z0-9._-]{3,64}$")
MIN_PASSWORD = 12
MAX_PASSWORD = 256
MAX_DISPLAY_NAME = 100
USERS_LOCK = "argus.users"


class UserRuleError(Exception):
    """A change the safety rules refuse. The message is shown to the admin as it is."""


@dataclass(frozen=True)
class UserRow:
    id: int
    username: str
    display_name: str
    role: Role
    is_active: bool
    must_change_password: bool
    locked: bool
    created_at: datetime
    last_sign_in_at: datetime | None


def check_username(username: str) -> str:
    name = username.strip().lower()
    if not USERNAME.match(name):
        raise ValueError(
            "username: 3 to 64 lowercase letters, digits, dots, dashes and underscores"
        )
    return name


def check_password(password: str, username: str) -> None:
    """NIST SP 800-63B: length, not the username, no composition rules."""
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise ValueError(f"password: {MIN_PASSWORD} to {MAX_PASSWORD} characters")
    if password.strip().lower() == username.lower():
        raise ValueError("password: it can't be the username")


def _check_display_name(name: str) -> str:
    if len(name.strip()) > MAX_DISPLAY_NAME:
        raise ValueError(f"display_name: at most {MAX_DISPLAY_NAME} characters")
    return name.strip()


def _lock(conn: Connection) -> None:
    conn.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": USERS_LOCK})


# A username is locked while either sign-in limit holds it: too many failures from one address,
# or from anywhere (auth.sessions.limited).
_LOCKED = """
  EXISTS (SELECT 1 FROM login_failure f
          WHERE f.username = u.username AND f.failed_at > now() - CAST(:w AS interval)
          GROUP BY f.client_ip HAVING count(*) >= :pair)
  OR (SELECT count(*) FROM login_failure f
      WHERE f.username = u.username AND f.failed_at > now() - CAST(:w AS interval)) >= :per_user
"""


def _lock_params() -> dict[str, Any]:
    settings = get_settings()
    return {
        "w": f"{settings.login_lockout_minutes} minutes",
        "pair": settings.login_max_failures,
        "per_user": settings.login_max_failures_per_username,
    }


def list_users(conn: Connection, *, limit: int, offset: int) -> tuple[list[UserRow], int]:
    rows = conn.execute(
        text(f"""
        SELECT u.id, u.username, u.display_name, u.role, u.is_active, u.must_change_password,
               ({_LOCKED}) AS locked, u.created_at, u.last_sign_in_at
        FROM app_user u
        ORDER BY u.is_active DESC, u.username
        LIMIT :limit OFFSET :offset
    """),  # noqa: S608 - a fixed fragment
        {"limit": limit, "offset": offset, **_lock_params()},
    ).all()
    total = conn.execute(text("SELECT count(*) FROM app_user")).scalar_one()
    return [UserRow(**row._mapping) for row in rows], int(total)


def get_user(conn: Connection, user_id: int) -> UserRow:
    row = conn.execute(
        text(f"""
        SELECT u.id, u.username, u.display_name, u.role, u.is_active, u.must_change_password,
               ({_LOCKED}) AS locked, u.created_at, u.last_sign_in_at
        FROM app_user u WHERE u.id = :i
    """),  # noqa: S608 - a fixed fragment
        {"i": user_id, **_lock_params()},
    ).one_or_none()
    if row is None:
        raise LookupError(f"user {user_id}")
    return UserRow(**row._mapping)


def create_user(
    conn: Connection,
    *,
    username: str,
    display_name: str,
    role: Role,
    password: str,
    actor: str,
    client_ip: str | None = None,
) -> UserRow:
    """A new local user, who chooses their own password at the first sign-in. A username that
    exists already raises IntegrityError (409)."""
    name = check_username(username)
    check_password(password, name)
    _lock(conn)
    user_id = conn.execute(
        text("""
        INSERT INTO app_user (username, display_name, password_hash, role, must_change_password,
                              created_by, updated_by)
        VALUES (:u, :d, :h, :r, true, :a, :a) RETURNING id
    """),
        {
            "u": name,
            "d": _check_display_name(display_name),
            "h": hash_password(password),
            "r": role,
            "a": actor,
        },
    ).scalar_one()
    audit.record(
        conn,
        actor=actor,
        action="user.created",
        target_type="user",
        target_id=name,
        detail={"role": role},
        client_ip=client_ip,
    )
    return get_user(conn, int(user_id))


def _active_admins(conn: Connection) -> int:
    return int(
        conn.execute(
            text("SELECT count(*) FROM app_user WHERE role = 'admin' AND is_active")
        ).scalar_one()
    )


def update_user(
    conn: Connection,
    *,
    user_id: int,
    actor: SessionUser,
    display_name: str | None = None,
    role: Role | None = None,
    is_active: bool | None = None,
    client_ip: str | None = None,
) -> UserRow:
    """Changes a user's name, role or active flag. A role change or deactivation ends their
    sessions."""
    _lock(conn)
    before = get_user(conn, user_id)
    changes: dict[str, list[Any]] = {}
    if display_name is not None and _check_display_name(display_name) != before.display_name:
        changes["display_name"] = [before.display_name, _check_display_name(display_name)]
    if role is not None and role != before.role:
        changes["role"] = [before.role, role]
    if is_active is not None and is_active != before.is_active:
        changes["is_active"] = [before.is_active, is_active]
    if not changes:
        return before
    loses_power = "role" in changes or changes.get("is_active") == [True, False]
    if loses_power and user_id == actor.id:
        raise UserRuleError("You can't change your own role or deactivate yourself.")
    stays_admin = (role or before.role) == "admin" and (
        is_active if is_active is not None else before.is_active
    )
    if (
        before.role == "admin"
        and before.is_active
        and not stays_admin
        and _active_admins(conn) <= 1
    ):
        raise UserRuleError("Argus needs at least one active admin.")
    conn.execute(
        text("""
        UPDATE app_user SET display_name = COALESCE(:d, display_name), role = COALESCE(:r, role),
          is_active = COALESCE(:a, is_active), updated_at = now(), updated_by = :by
        WHERE id = :i
    """),
        {
            "i": user_id,
            "d": changes["display_name"][1] if "display_name" in changes else None,
            "r": role,
            "a": is_active,
            "by": actor.username,
        },
    )
    if loses_power:
        end_sessions(conn, user_id)
    deactivated = changes.get("is_active") == [True, False]
    audit.record(
        conn,
        actor=actor.username,
        action="user.deactivated" if deactivated and len(changes) == 1 else "user.updated",
        target_type="user",
        target_id=before.username,
        detail=changes,
        client_ip=client_ip,
    )
    return get_user(conn, user_id)


def set_password(
    conn: Connection, *, user_id: int, password: str, actor: str, client_ip: str | None = None
) -> None:
    """A password another person sets: the user must choose their own at the next sign-in, and
    their sessions end."""
    _lock(conn)
    user = get_user(conn, user_id)
    check_password(password, user.username)
    conn.execute(
        text("""
        UPDATE app_user SET password_hash = :h, must_change_password = true, updated_at = now(),
          updated_by = :by WHERE id = :i
    """),
        {"h": hash_password(password), "by": actor, "i": user_id},
    )
    end_sessions(conn, user_id)
    audit.record(
        conn,
        actor=actor,
        action="user.password_set",
        target_type="user",
        target_id=user.username,
        client_ip=client_ip,
    )


def change_own_password(
    conn: Connection,
    *,
    user: SessionUser,
    current: str,
    new: str,
    keep_token: str,
    client_ip: str | None = None,
) -> None:
    """The signed-in user's own change. A wrong current password counts as a failed sign-in,
    so this cannot be used to guess it past the limits. The user's other sessions end."""
    serialize_attempts(conn, user.username)
    if limited(conn, user.username, client_ip):
        raise TooManyAttemptsError
    stored = conn.execute(
        text("SELECT password_hash FROM app_user WHERE id = :i"), {"i": user.id}
    ).scalar_one()
    if not password_matches(stored, current):
        conn.execute(
            text("INSERT INTO login_failure (username, client_ip) VALUES (:u, CAST(:ip AS inet))"),
            {"u": user.username, "ip": client_ip},
        )
        audit.record(
            conn, actor=user.username, action="user.password_change_failed", client_ip=client_ip
        )
        raise ValueError("current_password: your current password is wrong")
    check_password(new, user.username)
    if new == current:
        raise ValueError("new_password: choose a password other than the current one")
    conn.execute(
        text("""
        UPDATE app_user SET password_hash = :h, must_change_password = false, updated_at = now(),
          updated_by = :u WHERE id = :i
    """),
        {"h": hash_password(new), "u": user.username, "i": user.id},
    )
    end_sessions(conn, user.id, keep_token=keep_token)
    audit.record(
        conn,
        actor=user.username,
        action="user.password_changed",
        target_type="user",
        target_id=user.username,
        client_ip=client_ip,
    )


def unlock(conn: Connection, *, user_id: int, actor: str, client_ip: str | None = None) -> None:
    """Clears the failed sign-ins that hold a username, from every address."""
    user = get_user(conn, user_id)
    conn.execute(text("DELETE FROM login_failure WHERE username = :u"), {"u": user.username})
    audit.record(
        conn,
        actor=actor,
        action="user.unlocked",
        target_type="user",
        target_id=user.username,
        client_ip=client_ip,
    )


def delete_user(
    conn: Connection, *, user_id: int, actor: str, client_ip: str | None = None
) -> None:
    """Only an inactive user is deleted (their sessions go with them); the audit log keeps
    their username."""
    _lock(conn)
    user = get_user(conn, user_id)
    if user.is_active:
        raise UserRuleError("Deactivate the user before deleting them.")
    conn.execute(text("DELETE FROM app_user WHERE id = :i"), {"i": user_id})
    audit.record(
        conn,
        actor=actor,
        action="user.deleted",
        target_type="user",
        target_id=user.username,
        client_ip=client_ip,
    )


def _argon2id(password_hash: str) -> str:
    try:
        if extract_parameters(password_hash).type is not Type.ID:
            raise ValueError
    except (InvalidHashError, ValueError):
        raise ValueError(
            "the bootstrap hash is not an argon2id hash (admin-tools hash-password)"
        ) from None
    return password_hash


def bootstrap_admin(
    conn: Connection, *, username: str, password: str | None, password_hash: str | None
) -> str:
    """The first admin, from the environment, once (ADR-0041): created only while no active
    admin exists, never changing an existing user. Returns what happened, for the log."""
    name = check_username(username)
    if password:
        check_password(password, name)
        stored = hash_password(password)
    elif password_hash:
        stored = _argon2id(password_hash)
    else:
        raise ValueError("a bootstrap admin needs a password or a password hash")
    _lock(conn)
    if _active_admins(conn) > 0:
        return "skipped: an active admin exists"
    if conn.execute(text("SELECT 1 FROM app_user WHERE username = :u"), {"u": name}).one_or_none():
        return "skipped: the user exists and is not an active admin; use reset-password"
    conn.execute(
        text("""
        INSERT INTO app_user (username, password_hash, role, created_by, updated_by)
        VALUES (:u, :h, 'admin', 'bootstrap', 'bootstrap')
    """),
        {"u": name, "h": stored},
    )
    audit.record(
        conn,
        actor="bootstrap",
        action="user.created",
        target_type="user",
        target_id=name,
        detail={"role": "admin"},
    )
    return "created"


def reset_password(conn: Connection, *, username: str, password: str) -> None:
    """admin-tools' recovery for a forgotten password, run where the database is reachable."""
    user_id = conn.execute(
        text("SELECT id FROM app_user WHERE username = :u"), {"u": check_username(username)}
    ).scalar_one_or_none()
    if user_id is None:
        raise LookupError(f"no user {username!r}")
    set_password(conn, user_id=int(user_id), password=password, actor="admin-tools")
