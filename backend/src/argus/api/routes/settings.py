"""Administration -> Settings. Each topic is validated, and values that bound an
administrator's authority are checked against the environment (422 naming the bound)."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, SecretStr

from argus import settings as platform_settings
from argus.api.deps import Admin, Db, Operator, Viewer, client_ip
from argus.collection import prowler_checks, prowler_services
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
    """An admin's settings. Collection is apart (GET /settings/collection): Schedules reads it at
    every role, and this holds the raw output bucket and the platform's access key id."""

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
        retention=platform_settings.read_retention(conn),
        raw_storage=platform_settings.read_raw_storage(conn),
        identity=IdentityOut(
            mode=identity.mode, access_key_id=identity.access_key_id, secret_set=secret_set
        ),
        bounds=Bounds(max_history_days=env.max_history_days),
    )


@router.get("")
def read(conn: Db, _user: Admin) -> SettingsOut:
    return _out(conn)


@router.get("/collection")
def read_collection(conn: Db, _user: Viewer) -> CollectionSettings:
    return platform_settings.read_collection(conn)


class ProwlerOptions(BaseModel):
    """What Collection settings may skip: the pinned Prowler's AWS services and checks. A
    check's service is the first word of its id."""

    services: list[str]
    checks: list[str]


@router.get("/collection/prowler-options")
def prowler_options(_user: Viewer) -> ProwlerOptions:
    return ProwlerOptions(services=list(prowler_services()), checks=list(prowler_checks()))


def _unknown_skips(body: CollectionSettings) -> list[str]:
    services, checks = set(prowler_services()), set(prowler_checks())
    return sorted(
        {s for s in body.prowler_skip_services if s not in services}
        | {c for c in body.prowler_skip_checks if c not in checks}
    )


@router.put("/collection")
def write_collection(
    body: CollectionSettings, conn: Db, user: Operator, request: Request
) -> CollectionSettings:
    # Only names of the pinned Prowler: settings checks their shape, collection knows them.
    if unknown := _unknown_skips(body):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Prowler has no such service or check: {', '.join(unknown[:10])}",
        )
    platform_settings.write_topic(conn, topic="collection", values=body.model_dump(), actor=user)
    audit.record(
        conn,
        actor=user,
        action="settings.collection",
        client_ip=client_ip(request),
        detail=body.model_dump(mode="json"),
    )
    conn.commit()
    return platform_settings.read_collection(conn)


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
