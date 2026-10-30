"""Request-scoped dependencies: the database connection, the signed-in user and their role,
CSRF.

Transactions: the connection yielded here commits NOTHING on its own. A handler that writes
calls conn.commit() before it returns. A FastAPI dependency's teardown runs after the response
has been sent, so a commit there would hand out (for example) a session cookie for a row that
is not yet durable (a catheris-lutur-access lesson). Anything uncommitted is rolled back.
"""

import hmac
import ipaddress
from collections.abc import Iterator
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy import Connection

from argus.auth import Role, SessionUser, role_allows, session_user
from argus.core import audit
from argus.core.db import get_engine

SESSION_COOKIE = "argus_session"
CSRF_COOKIE = "argus_csrf"
CSRF_HEADER = "X-Argus-CSRF"
UNSAFE = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def db() -> Iterator[Connection]:
    with get_engine().connect() as conn:
        yield conn


Db = Annotated[Connection, Depends(db)]


def client_ip(request: Request) -> str | None:
    """The caller's address as a valid IP, or None. It is stored as inet and used for the
    per-address sign-in limit, so anything that is not an address is dropped, not trusted."""
    host = request.client.host if request.client else None
    try:
        return str(ipaddress.ip_address(host)) if host else None
    except ValueError:
        return None


def current_user(
    request: Request,
    conn: Db,
    session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE)] = None,
    csrf_header: Annotated[str | None, Header(alias=CSRF_HEADER)] = None,
) -> SessionUser:
    """The signed-in user, whatever their role and even while they must change their password:
    only the session, sign-out and the password change use it directly."""
    if not session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "sign in required")
    user = session_user(conn, session)
    conn.commit()  # the sliding expiry, before anything else happens on this connection
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "sign in required")
    if request.method in UNSAFE and not (
        csrf_cookie and csrf_header and hmac.compare_digest(csrf_cookie, csrf_header)
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "missing or wrong CSRF token")
    return user


CurrentUser = Annotated[SessionUser, Depends(current_user)]


class RoleCheck:
    """A route's least role (ADR-0041). The dependency returns the username, the actor every
    write records. A refusal is audited; a user who must change their password is refused
    everything until they do."""

    def __init__(self, needed: Role) -> None:
        self.needed = needed

    def __call__(self, request: Request, conn: Db, user: CurrentUser) -> str:
        if user.must_change_password:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "password change required")
        if not role_allows(user.role, self.needed):
            audit.record(
                conn,
                actor=user.username,
                action="access_denied",
                detail={
                    "method": request.method,
                    "path": request.url.path[:200],
                    "needed": self.needed,
                    "role": user.role,
                },
                client_ip=client_ip(request),
            )
            conn.commit()
            raise HTTPException(status.HTTP_403_FORBIDDEN, "your role does not allow this")
        return user.username


# Every route but health, readiness and sign-in declares one of these, or CurrentUser
# (tests/api/test_roles.py fails on a route that declares none).
Viewer = Annotated[str, Depends(RoleCheck("viewer"))]
Operator = Annotated[str, Depends(RoleCheck("operator"))]
Admin = Annotated[str, Depends(RoleCheck("admin"))]
