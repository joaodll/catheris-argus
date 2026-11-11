"""Administration -> Connections. Demo connections backfill history (Docker Compose only: a
deployment bound turns them off on Kubernetes, ADR-0039); AWS connections use
assume role or an access key, the administrator's choice (ADR-0024): a long-lived key, or a
temporary one (ASIA...) with its session token. Secrets and session
tokens are accepted, sealed and never returned."""

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Body, Request, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from argus import connections
from argus.api.deps import Db, Operator, Viewer, client_ip
from argus.connections import AwsAuth, RoleChange
from argus.core.db import get_engine
from argus.scheduling import create_demo_connection

router = APIRouter(prefix="/connections", tags=["connections"])
Name = Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9 ._-]+$")]


class ConnectionOut(BaseModel):
    id: int
    name: str
    kind: str
    account_id: str
    auth_method: str
    role_arn: str | None
    external_id_set: bool
    access_key_id_hint: str | None
    secret_set_at: datetime | None
    enabled: bool
    updated_at: datetime
    updated_by: str


class DemoIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["demo"]
    name: Name
    seed: int = Field(ge=0, le=89)
    backfill_days: int = Field(180, ge=1, le=400)


class AwsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["aws"]
    name: Name
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    auth_method: Literal["assume_role", "access_key"]
    role_arn: str | None = None
    external_id: SecretStr | None = None
    access_key_id: str | None = None
    secret_access_key: SecretStr | None = None
    session_token: SecretStr | None = None


class AccessKeyIn(BaseModel):
    """A replacement access key, whole: a rotated key or a new SSO session changes every part."""

    model_config = ConfigDict(extra="forbid")
    access_key_id: str
    secret_access_key: SecretStr
    session_token: SecretStr | None = None


class RoleIn(BaseModel):
    """A change to an assume-role connection: a role in the same account, a new ExternalId, or
    the ExternalId removed. What is left out keeps its stored value; the ExternalId is never
    returned."""

    model_config = ConfigDict(extra="forbid")
    role_arn: str | None = None
    external_id: SecretStr | None = None
    clear_external_id: bool = False


class ConnectionPatch(BaseModel):
    """What Edit connection changes. `auth_method` other than the connection's own switches its
    sign-in method: it must come with that method's whole set (`access_key`, or `assume_role`
    with a `role_arn`), and the old method's credentials are deleted. The account never changes."""

    model_config = ConfigDict(extra="forbid")
    name: Name | None = None
    enabled: bool | None = None
    auth_method: Literal["assume_role", "access_key"] | None = None
    access_key: AccessKeyIn | None = None
    assume_role: RoleIn | None = None


def _secret(value: SecretStr | None) -> str | None:
    return value.get_secret_value() if value else None


def _view(conn: Db, connection_id: int) -> ConnectionOut:
    view = next(v for v in connections.list_views(conn) if v.id == connection_id)
    return ConnectionOut.model_validate(view, from_attributes=True)


@router.get("")
def list_connections(conn: Db, _user: Viewer) -> list[ConnectionOut]:
    return [
        ConnectionOut.model_validate(v, from_attributes=True) for v in connections.list_views(conn)
    ]


@router.get("/kinds")
def connection_kinds(_user: Viewer) -> list[connections.ConnectionKind]:
    """The kinds the Add connection dialog may offer: no Demo on Kubernetes (ADR-0039)."""
    return list(connections.allowed_kinds())


@router.post("", status_code=status.HTTP_201_CREATED)
def create_connection(
    conn: Db,
    user: Operator,
    request: Request,
    body: Annotated[DemoIn | AwsIn, Body(discriminator="kind")],
) -> ConnectionOut:
    if isinstance(body, DemoIn):
        # Its own transaction (connection + backfill + audit), shared with the seed command.
        created, _ = create_demo_connection(
            get_engine(),
            name=body.name,
            seed=body.seed,
            days=body.backfill_days,
            today=datetime.now(UTC).date(),
            actor=user,
        )
        return _view(conn, created.id)
    auth = AwsAuth(
        method=body.auth_method,
        role_arn=body.role_arn,
        external_id=body.external_id.get_secret_value() if body.external_id else None,
        access_key_id=body.access_key_id,
        secret_access_key=_secret(body.secret_access_key),
        session_token=_secret(body.session_token),
    )
    created_aws = connections.create_aws(
        conn,
        name=body.name,
        account_id=body.account_id,
        auth=auth,
        actor=user,
        client_ip=client_ip(request),
    )
    conn.commit()
    return _view(conn, created_aws.id)


@router.patch("/{connection_id}")
def update_connection(
    connection_id: int, body: ConnectionPatch, conn: Db, user: Operator, request: Request
) -> ConnectionOut:
    connections.update(
        conn,
        connection_id=connection_id,
        actor=user,
        name=body.name,
        enabled=body.enabled,
        auth_method=body.auth_method,
        access_key=(
            AwsAuth(
                "access_key",
                access_key_id=body.access_key.access_key_id,
                secret_access_key=body.access_key.secret_access_key.get_secret_value(),
                session_token=_secret(body.access_key.session_token),
            )
            if body.access_key
            else None
        ),
        role=(
            RoleChange(
                role_arn=body.assume_role.role_arn,
                # An empty one is passed on, so it is refused rather than read as "unchanged".
                external_id=(
                    body.assume_role.external_id.get_secret_value()
                    if body.assume_role.external_id is not None
                    else None
                ),
                clear_external_id=body.assume_role.clear_external_id,
            )
            if body.assume_role
            else None
        ),
        client_ip=client_ip(request),
    )
    conn.commit()
    return _view(conn, connection_id)
