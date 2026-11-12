import secrets
from typing import Annotated
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from argus.api.deps import CSRF_COOKIE, SESSION_COOKIE, CurrentUser, Db, client_ip
from argus.auth import (
    MAX_PASSWORD,
    Role,
    SignInError,
    TooManyAttemptsError,
    UserRuleError,
    change_own_password,
    saml,
    sign_in,
    sign_out,
)
from argus.auth.sessions import AuthSource
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
    # Where they sign in: a password (local) or the identity provider (saml).
    auth_source: AuthSource


class Methods(BaseModel):
    """Which sign-ins this deployment offers (ADR-0048)."""

    local: bool
    sso: bool


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


def _refuse_when_local_is_off() -> None:
    if not get_settings().local_sign_in:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Local sign-in is off.")


@router.get("/methods")
def methods() -> Methods:
    settings = get_settings()
    return Methods(local=settings.local_sign_in, sso=settings.sso)


@router.post("/sign-in", status_code=status.HTTP_204_NO_CONTENT)
def sign_in_route(body: SignIn, request: Request, response: Response, conn: Db) -> None:
    _refuse_when_local_is_off()
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
        auth_source=user.auth_source,
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
    _refuse_when_local_is_off()
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
    except UserRuleError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from None
    except ValueError:
        conn.commit()  # a wrong current password is a counted, audited failure
        raise
    conn.commit()


# ---- SAML (ADR-0048). The browser navigates to these, so every outcome is a redirect: success
# to where the user was going, anything else to the sign-in page with a fixed reason code.


def _to_sign_in(code: str, next_path: str | None = None) -> RedirectResponse:
    query = {"reason": f"sso-{code}"}
    if next_path and next_path != "/":
        query["next"] = next_path
    response = RedirectResponse(f"/sign-in?{urlencode(query)}", status.HTTP_303_SEE_OTHER)
    _drop_state(response)
    return response


def _drop_state(response: Response) -> None:
    response.delete_cookie(
        saml.STATE_COOKIE, path=saml.ACS_PATH, secure=True, httponly=True, samesite="none"
    )


@router.get("/saml/login", status_code=status.HTTP_302_FOUND, response_class=RedirectResponse)
def saml_login(
    next_path: Annotated[str | None, Query(alias="next", max_length=2048)] = None,
) -> RedirectResponse:
    try:
        url, state = saml.start(next_path)
    except saml.SsoRefusedError as exc:
        return _to_sign_in(exc.code, saml.safe_next(next_path))
    response = RedirectResponse(url, status.HTTP_302_FOUND)
    # SameSite=None: the IdP's answer is a cross-site POST, and Strict or Lax cookies don't come
    # with it. It holds no secret of the user's: a signed request id, a path and an expiry.
    response.set_cookie(
        saml.STATE_COOKIE,
        state,
        max_age=saml.STATE_SECONDS,
        httponly=True,
        secure=True,
        samesite="none",
        path=saml.ACS_PATH,
    )
    return response


async def _saml_answer(request: Request) -> str | None:
    """The form's SAMLResponse, or None for a body over the limit or of the wrong shape. Read
    here, under the API's own size limit: nginx's is the first line, not the only one."""
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > saml.MAX_ANSWER_BYTES:
            return None
    try:
        fields = parse_qs(body.decode("ascii"), max_num_fields=4, strict_parsing=False)
    except (UnicodeDecodeError, ValueError):
        return None
    answers = fields.get("SAMLResponse", [])
    return answers[0] if len(answers) == 1 else None


@router.post("/saml/acs", status_code=status.HTTP_303_SEE_OTHER, response_class=RedirectResponse)
def saml_acs(
    request: Request,
    conn: Db,
    answer: Annotated[str | None, Depends(_saml_answer)],
    state: Annotated[str | None, Cookie(alias=saml.STATE_COOKIE)] = None,
) -> RedirectResponse:
    """The IdP's answer. No CSRF header can come with a cross-site POST: the signed state cookie
    and the IdP's signature are what bind it (ADR-0048, section 4)."""
    ip = client_ip(request)
    try:
        if answer is None:
            raise saml.SsoRefusedError("invalid")
        token, next_path = saml.finish(
            conn,
            saml_response=answer,
            state_cookie=state,
            client_ip=ip,
            user_agent=request.headers.get("user-agent"),
        )
    except saml.SsoRefusedError as exc:
        saml.refused(conn, code=exc.code, client_ip=ip)
        conn.commit()  # the audit row, a used assertion, sessions a no-group sign-in ended
        return _to_sign_in(exc.code)
    conn.commit()  # the session row is durable before the cookie leaves
    response = RedirectResponse(next_path, status.HTTP_303_SEE_OTHER)
    _set_cookies(response, token)
    _drop_state(response)
    return response


@router.get("/saml/metadata", response_class=Response)
def saml_metadata() -> Response:
    """Argus's SP metadata, for the IdP's set-up. It holds no secret."""
    config = saml.sso_config()
    if config is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "single sign-on is off")
    return Response(saml.sp_metadata(config), media_type="application/samlmetadata+xml")
