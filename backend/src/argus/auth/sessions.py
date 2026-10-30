import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import Connection, text

from argus.core import audit
from argus.core.config import get_settings

SESSION_TOKEN_BYTES = 32
TOUCH_EVERY = timedelta(seconds=60)

Role = Literal["viewer", "operator", "admin"]
# Each role can do everything the roles before it can (ADR-0041).
ROLES: tuple[Role, ...] = ("viewer", "operator", "admin")


def role_allows(role: Role, needed: Role) -> bool:
    return ROLES.index(role) >= ROLES.index(needed)


@dataclass(frozen=True)
class SessionUser:
    """Who a live session belongs to, read on every request: a deactivated user or a changed
    role takes effect at once."""

    id: int
    username: str
    display_name: str
    role: Role
    must_change_password: bool


class SignInError(Exception):
    """Wrong credentials. The message never says which part was wrong."""


class TooManyAttemptsError(Exception):
    """Locked out or rate-limited; try again later."""


@cache
def _hasher() -> PasswordHasher:
    return PasswordHasher()


@cache
def _dummy_hash() -> str:
    # Verified when the username is wrong, so timing does not reveal valid usernames.
    return _hasher().hash(secrets.token_hex(16))


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def hash_password(password: str) -> str:
    return _hasher().hash(password)


def password_matches(stored: str | None, password: str) -> bool:
    """argon2id verification; with no stored hash (no such user, or not a local one) a dummy
    one is verified anyway, so the time taken does not say whether the user exists."""
    try:
        return _hasher().verify(stored or _dummy_hash(), password) and stored is not None
    except (VerificationError, InvalidHashError):
        return False


def _verify(conn: Connection, username: str, password: str) -> int | None:
    """The id of the active local user these credentials belong to, or None."""
    row = conn.execute(
        text(
            "SELECT id, password_hash FROM app_user "
            "WHERE username = :u AND is_active AND auth_source = 'local'"
        ),
        {"u": username},
    ).one_or_none()
    if not password_matches(row.password_hash if row else None, password):
        return None
    return int(row.id) if row else None


def serialize_attempts(conn: Connection, username: str) -> None:
    """Attempts at one username's password (signing in, or a password change's current one) run
    one at a time until the caller commits, so a parallel burst cannot all pass the limit check
    before any failure is recorded."""
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended('argus.sign_in:' || :u, 0))"),
        {"u": username},
    )


def limited(conn: Connection, username: str, client_ip: str | None) -> bool:
    settings = get_settings()
    counts = conn.execute(
        text("""
        SELECT
          count(*) FILTER (WHERE username = :u
                             AND client_ip IS NOT DISTINCT FROM CAST(:ip AS inet)),
          count(*) FILTER (WHERE client_ip = CAST(:ip AS inet)),
          count(*) FILTER (WHERE username = :u)
        FROM login_failure
        WHERE (username = :u OR client_ip = CAST(:ip AS inet))
          AND failed_at > now() - CAST(:w AS interval)
    """),
        {"u": username, "ip": client_ip, "w": f"{settings.login_lockout_minutes} minutes"},
    ).one()
    by_pair, by_ip, by_user = (int(n) for n in counts)
    return (
        by_pair >= settings.login_max_failures
        or by_ip >= settings.login_max_failures_per_ip
        or by_user >= settings.login_max_failures_per_username
    )


def sign_in(
    conn: Connection, *, username: str, password: str, client_ip: str | None, user_agent: str | None
) -> str:
    """Returns a new session token. Raises TooManyAttemptsError or SignInError. Every attempt
    is audited; the caller commits."""
    # Usernames are lowercase: "Admin" is the same user, and the same sign-in limit.
    username = username.strip().lower()
    serialize_attempts(conn, username)
    if limited(conn, username, client_ip):
        audit.record(conn, actor=username, action="auth.sign_in.limited", client_ip=client_ip)
        raise TooManyAttemptsError
    user_id = _verify(conn, username, password)
    if user_id is None:
        conn.execute(
            text("INSERT INTO login_failure (username, client_ip) VALUES (:u, CAST(:ip AS inet))"),
            {"u": username, "ip": client_ip},
        )
        audit.record(conn, actor=username, action="auth.sign_in.failed", client_ip=client_ip)
        raise SignInError
    settings = get_settings()
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    now = datetime.now(UTC)
    conn.execute(
        text("""
        INSERT INTO user_session (token_hash, user_id, idle_expires_at, absolute_expires_at,
                                  client_ip, user_agent)
        VALUES (:h, :u, :idle, :abs, CAST(:ip AS inet), :ua)
    """),
        {
            "h": _token_hash(token),
            "u": user_id,
            "idle": now + timedelta(minutes=settings.session_idle_minutes),
            "abs": now + timedelta(hours=settings.session_absolute_hours),
            "ip": client_ip,
            "ua": (user_agent or "")[:400],
        },
    )
    # Only this address's failures: someone else's attempts on this username still count.
    conn.execute(
        text(
            "DELETE FROM login_failure WHERE username = :u "
            "AND client_ip IS NOT DISTINCT FROM CAST(:ip AS inet)"
        ),
        {"u": username, "ip": client_ip},
    )
    conn.execute(text("UPDATE app_user SET last_sign_in_at = now() WHERE id = :i"), {"i": user_id})
    audit.record(conn, actor=username, action="auth.sign_in", client_ip=client_ip)
    return token


def session_user(conn: Connection, token: str) -> SessionUser | None:
    """The active user behind a live session; slides the idle expiry (at most once a minute)."""
    settings = get_settings()
    row = conn.execute(
        text("""
        SELECT s.id, s.last_seen_at, u.id AS user_id, u.username, u.display_name, u.role,
               u.must_change_password
        FROM user_session s JOIN app_user u ON u.id = s.user_id
        WHERE s.token_hash = :h AND s.revoked_at IS NULL
          AND s.idle_expires_at > now() AND s.absolute_expires_at > now() AND u.is_active
    """),
        {"h": _token_hash(token)},
    ).one_or_none()
    if row is None:
        return None
    if datetime.now(UTC) - row.last_seen_at > TOUCH_EVERY:
        conn.execute(
            text("""
            UPDATE user_session SET last_seen_at = now(),
              idle_expires_at = LEAST(now() + CAST(:idle AS interval), absolute_expires_at)
            WHERE id = :i
        """),
            {"i": row.id, "idle": f"{settings.session_idle_minutes} minutes"},
        )
    return SessionUser(
        id=row.user_id,
        username=row.username,
        display_name=row.display_name,
        role=row.role,
        must_change_password=row.must_change_password,
    )


def sign_out(conn: Connection, *, token: str, client_ip: str | None) -> None:
    username = conn.execute(
        text("""
        UPDATE user_session s SET revoked_at = now() FROM app_user u
        WHERE s.token_hash = :h AND s.revoked_at IS NULL AND u.id = s.user_id
        RETURNING u.username
    """),
        {"h": _token_hash(token)},
    ).scalar_one_or_none()
    if username:
        audit.record(conn, actor=username, action="auth.sign_out", client_ip=client_ip)


def end_sessions(conn: Connection, user_id: int, *, keep_token: str | None = None) -> int:
    """Ends a user's live sessions, all of them or all but `keep_token`'s. Returns how many."""
    return conn.execute(
        text("""
        UPDATE user_session SET revoked_at = now()
        WHERE user_id = :u AND revoked_at IS NULL
          AND token_hash IS DISTINCT FROM :keep
    """),
        {"u": user_id, "keep": _token_hash(keep_token) if keep_token else None},
    ).rowcount
