import secrets
from typing import Annotated

from fastapi import APIRouter, Cookie, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from argus.api.deps import CSRF_COOKIE, SESSION_COOKIE, CurrentUser, Db, client_ip
from argus.auth import (
    MAX_PASSWORD,
    Role,
    SignInError,
    TooManyAttemptsError,
    change_own_password,
    sign_in,
    sign_out,
)
from argus.core.config import get_settings

router = APIRouter(prefix="/auth", tags=["auth"])


class SignIn(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=1000)


class Session(BaseModel):
    username: str
    display_name: str
    role: Role
    # An admin set the password: every other route answers 403 until the user changes it.
    must_change_password: bool


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=1000)
    new_password: str = Field(min_length=1, max_length=MAX_PASSWORD)


def _set_cookies(response: Response, token: str) -> None:
    max_age = get_settings().session_absolute_hours * 3600
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max_age,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/api",
    )
    # Readable by the app, sent back as X-Argus-CSRF on every write (double submit).
    response.set_cookie(
        CSRF_COOKIE,
        secrets.token_urlsafe(32),
        max_age=max_age,
        httponly=False,
        secure=True,
        samesite="strict",
        path="/",
    )


@router.post("/sign-in", status_code=status.HTTP_204_NO_CONTENT)
def sign_in_route(body: SignIn, request: Request, response: Response, conn: Db) -> None:
    try:
        token = sign_in(
            conn,
            username=body.username,
            password=body.password,
            client_ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except TooManyAttemptsError:
        conn.commit()  # the audit entry
        minutes = get_settings().login_lockout_minutes
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many attempts",
            headers={"Retry-After": str(minutes * 60)},
        ) from None
    except SignInError:
        conn.commit()  # the failure counter and audit entry
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "wrong username or password") from None
    conn.commit()  # the session row is durable before the cookie leaves
    _set_cookies(response, token)


@router.post("/sign-out", status_code=status.HTTP_204_NO_CONTENT)
def sign_out_route(
    request: Request,
    response: Response,
    conn: Db,
    _user: CurrentUser,
    session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> None:
    if session:
        sign_out(conn, token=session, client_ip=client_ip(request))
        conn.commit()
    response.delete_cookie(
        SESSION_COOKIE, path="/api", secure=True, httponly=True, samesite="strict"
    )
    response.delete_cookie(CSRF_COOKIE, path="/", secure=True, samesite="strict")


@router.get("/session")
def current_session(user: CurrentUser) -> Session:
    return Session(
        username=user.username,
        display_name=user.display_name,
        role=user.role,
        must_change_password=user.must_change_password,
    )


@router.put("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: PasswordChange,
    request: Request,
    conn: Db,
    user: CurrentUser,
    session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> None:
    """The signed-in user's own password. Their other sessions end; this one stays."""
    try:
        change_own_password(
            conn,
            user=user,
            current=body.current_password,
            new=body.new_password,
            keep_token=session or "",
            client_ip=client_ip(request),
        )
    except TooManyAttemptsError:
        minutes = get_settings().login_lockout_minutes
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many attempts",
            headers={"Retry-After": str(minutes * 60)},
        ) from None
    except ValueError:
        conn.commit()  # a wrong current password is a counted, audited failure
        raise
    conn.commit()
