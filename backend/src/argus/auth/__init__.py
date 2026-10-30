"""Authentication and users (ADR-0041): users with one of three roles, sessions and the
sign-in limits.

Owns app_user, user_session and login_failure. Public interface:
    sign_in()             verify credentials (with lockout and rate limit), open a session
    session_user()        the user behind a session token, or None (sliding idle expiry)
    sign_out()            revoke a session
    role_allows()         whether a role may do what another role may
    list_users() ...      user management for admins, with the safety rules (users.py)
    bootstrap_admin()     the first admin, from the environment, once (the migrate step)
    reset_password()      admin-tools' recovery for a forgotten password
Every sign-in attempt, sign-out and user change is written to the audit log in the caller's
transaction.
"""

from argus.auth.sessions import (
    ROLES,
    SESSION_TOKEN_BYTES,
    Role,
    SessionUser,
    SignInError,
    TooManyAttemptsError,
    hash_password,
    role_allows,
    session_user,
    sign_in,
    sign_out,
)
from argus.auth.users import (
    MAX_PASSWORD,
    MIN_PASSWORD,
    UserRow,
    UserRuleError,
    bootstrap_admin,
    change_own_password,
    check_password,
    create_user,
    delete_user,
    get_user,
    list_users,
    reset_password,
    set_password,
    unlock,
    update_user,
)

__all__ = [
    "MAX_PASSWORD",
    "MIN_PASSWORD",
    "ROLES",
    "SESSION_TOKEN_BYTES",
    "Role",
    "SessionUser",
    "SignInError",
    "TooManyAttemptsError",
    "UserRow",
    "UserRuleError",
    "bootstrap_admin",
    "change_own_password",
    "check_password",
    "create_user",
    "delete_user",
    "get_user",
    "hash_password",
    "list_users",
    "reset_password",
    "role_allows",
    "session_user",
    "set_password",
    "sign_in",
    "sign_out",
    "unlock",
    "update_user",
]
