"""Administration -> Users (ADR-0041): who can sign in, with which role. Admin only. A change the
safety rules refuse (your own role, the last active admin, deleting an active user) is 409 with
a message shown as it is."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from argus import auth
from argus.api.deps import Admin, CurrentUser, Db, client_ip

router = APIRouter(prefix="/users", tags=["users"])


class UserOut(BaseModel):
    id: int
    username: str
    display_name: str
    role: auth.Role
    is_active: bool
    must_change_password: bool
    # A sign-in limit holds this username now (too many failures); Unlock clears it.
    locked: bool
    created_at: datetime
    last_sign_in_at: datetime | None


class UserPage(BaseModel):
    items: list[UserOut]
    total: int


class UserIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    display_name: str = Field(default="", max_length=100)
    role: auth.Role
    password: str = Field(min_length=1, max_length=auth.MAX_PASSWORD)


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=100)
    role: auth.Role | None = None
    is_active: bool | None = None


class PasswordIn(BaseModel):
    password: str = Field(min_length=1, max_length=auth.MAX_PASSWORD)


def _out(row: auth.UserRow) -> UserOut:
    return UserOut.model_validate(row, from_attributes=True)


def refused(_: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})


@router.get("")
def list_users(
    conn: Db,
    _user: Admin,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> UserPage:
    rows, total = auth.list_users(conn, limit=limit, offset=offset)
    return UserPage(items=[_out(r) for r in rows], total=total)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_user(body: UserIn, conn: Db, user: Admin, request: Request) -> UserOut:
    created = auth.create_user(
        conn,
        username=body.username,
        display_name=body.display_name,
        role=body.role,
        password=body.password,
        actor=user,
        client_ip=client_ip(request),
    )
    conn.commit()
    return _out(created)


@router.patch("/{user_id}")
def update_user(
    user_id: int, body: UserPatch, conn: Db, _admin: Admin, me: CurrentUser, request: Request
) -> UserOut:
    updated = auth.update_user(
        conn,
        user_id=user_id,
        actor=me,
        display_name=body.display_name,
        role=body.role,
        is_active=body.is_active,
        client_ip=client_ip(request),
    )
    conn.commit()
    return _out(updated)


@router.post("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
def set_password(
    user_id: int, body: PasswordIn, conn: Db, user: Admin, me: CurrentUser, request: Request
) -> None:
    """Another user's password: they choose their own at the next sign-in. Your own is changed
    with PUT /auth/password, which needs the current one."""
    if user_id == me.id:
        raise auth.UserRuleError("Change your own password from your user menu.")
    auth.set_password(
        conn, user_id=user_id, password=body.password, actor=user, client_ip=client_ip(request)
    )
    conn.commit()


@router.post("/{user_id}/unlock", status_code=status.HTTP_204_NO_CONTENT)
def unlock(user_id: int, conn: Db, user: Admin, request: Request) -> None:
    auth.unlock(conn, user_id=user_id, actor=user, client_ip=client_ip(request))
    conn.commit()


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, conn: Db, user: Admin, request: Request) -> None:
    auth.delete_user(conn, user_id=user_id, actor=user, client_ip=client_ip(request))
    conn.commit()
