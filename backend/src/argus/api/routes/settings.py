"""Administration -> Settings. Each topic is validated, and values that bound an
administrator's authority are checked against the environment (422 naming the bound)."""

from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, SecretStr

from argus import settings as platform_settings
from argus.api.deps import Admin, Db, Viewer, client_ip
from argus.core import audit
from argus.core.config import get_settings
from argus.settings import CollectionSettings, RawStorageSettings, RetentionSettings

router = APIRouter(prefix="/settings", tags=["settings"])


class IdentityOut(BaseModel):
    mode: str
    access_key_id: str | None
    secret_set: bool


class Bounds(BaseModel):
    max_history_days: int


class SettingsOut(BaseModel):
    collection: CollectionSettings
    retention: RetentionSettings
    raw_storage: RawStorageSettings
    identity: IdentityOut
    bounds: Bounds


class IdentityIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["ambient", "access_key"]
    access_key_id: str | None = None
    secret_access_key: SecretStr | None = None
    session_token: SecretStr | None = None


def _out(conn: Db) -> SettingsOut:
    identity, secret_set = platform_settings.read_identity(conn)
    env = get_settings()
    return SettingsOut(
        collection=platform_settings.read_collection(conn),
        retention=platform_settings.read_retention(conn),
        raw_storage=platform_settings.read_raw_storage(conn),
        identity=IdentityOut(
            mode=identity.mode, access_key_id=identity.access_key_id, secret_set=secret_set
        ),
        bounds=Bounds(max_history_days=env.max_history_days),
    )


@router.get("")
def read(conn: Db, _user: Viewer) -> SettingsOut:
    return _out(conn)


@router.put("/collection")
def write_collection(
    body: CollectionSettings, conn: Db, user: Admin, request: Request
) -> SettingsOut:
    platform_settings.write_topic(conn, topic="collection", values=body.model_dump(), actor=user)
    audit.record(
        conn,
        actor=user,
        action="settings.collection",
        client_ip=client_ip(request),
        detail=body.model_dump(mode="json"),
    )
    conn.commit()
    return _out(conn)


@router.put("/retention")
def write_retention(
    body: RetentionSettings, conn: Db, user: Admin, request: Request
) -> SettingsOut:
    platform_settings.write_topic(conn, topic="retention", values=body.model_dump(), actor=user)
    audit.record(
        conn,
        actor=user,
        action="settings.retention",
        client_ip=client_ip(request),
        detail=body.model_dump(mode="json"),
    )
    conn.commit()
    return _out(conn)


@router.put("/raw-storage")
def write_raw_storage(
    body: RawStorageSettings, conn: Db, user: Admin, request: Request
) -> SettingsOut:
    platform_settings.write_topic(conn, topic="raw_storage", values=body.model_dump(), actor=user)
    audit.record(
        conn,
        actor=user,
        action="settings.raw_storage",
        client_ip=client_ip(request),
        detail=body.model_dump(mode="json"),
    )
    conn.commit()
    return _out(conn)


@router.put("/identity")
def write_identity(body: IdentityIn, conn: Db, user: Admin, request: Request) -> SettingsOut:
    platform_settings.write_identity(
        conn,
        mode=body.mode,
        access_key_id=body.access_key_id,
        secret_access_key=body.secret_access_key.get_secret_value()
        if body.secret_access_key
        else None,
        session_token=body.session_token.get_secret_value() if body.session_token else None,
        actor=user,
    )
    audit.record(
        conn,
        actor=user,
        action="settings.identity",
        client_ip=client_ip(request),
        detail={"mode": body.mode},
    )  # never the key, the secret or the session token
    conn.commit()
    return _out(conn)
