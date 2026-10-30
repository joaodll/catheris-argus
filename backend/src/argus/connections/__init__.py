"""Connections: the accounts Argus collects from, as configured in the UI (ADR-0021, 0024).

Owns the `connection` table. Other modules read connections through this interface only.

AWS connections authenticate one of two ways:
- assume_role: the platform identity assumes the role (role ARN + ExternalId).
- access_key: an access key, either long-lived (AKIA...) or temporary (ASIA..., SSO) with its
  session token. The administrator's choice, like assume_role (ADR-0024, amended 2026-10-24).
Secret access keys and session tokens are sealed (core.secrets) with the row's binding; they
are written here and never read back except by the worker at collection time (open_auth()).
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from sqlalchemy import Connection, text

from argus.core import audit
from argus.core.aws import check_access_key
from argus.core.config import get_settings
from argus.core.secrets import Sealed, seal, unseal

ConnectionKind = Literal["demo", "aws"]
AuthMethod = Literal["assume_role", "access_key"]
_ROLE_ARN_RE = re.compile(r"^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$")
_EXTERNAL_ID_RE = re.compile(r"^[A-Za-z0-9+=,.@:/-]{16,1224}$")


class ConnectionError(ValueError):
    """A connection that cannot be created or changed as asked (the API returns 422)."""


@dataclass(frozen=True)
class AwsAuth:
    """How an AWS connection authenticates. Only the fields of its method are used."""

    method: AuthMethod
    role_arn: str | None = None
    external_id: str | None = None
    access_key_id: str | None = None
    secret_access_key: str | None = field(default=None, repr=False)
    session_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ConnectionRow:
    id: int
    name: str
    kind: ConnectionKind
    account_id: str
    auth_method: str
    demo_seed: int | None
    enabled: bool


@dataclass(frozen=True)
class ConnectionView:
    """What the UI may see: never the secret, only that one is set and when."""

    id: int
    name: str
    kind: ConnectionKind
    account_id: str
    auth_method: str
    role_arn: str | None
    external_id_set: bool
    access_key_id_hint: str | None
    secret_set_at: datetime | None
    enabled: bool
    updated_at: datetime
    updated_by: str


# A module constant interpolated into SQL below; never input (hence the S608 annotations).
_COLUMNS = "id, name, kind, account_id, auth_method, demo_seed, enabled"

# Exported SQL: other modules join this, never the table, for a connection's name or state:
#     ... JOIN ({DIRECTORY_SQL}) c ON c.id = x.connection_id
DIRECTORY_SQL = "SELECT id, name, kind, provider, account_id, enabled FROM connection"


def demo_account_id(seed: int) -> str:
    """Demo accounts get obviously fake ids in the 1000000000xx range."""
    return f"{100000000010 + seed:012d}"


def binding(account_id: str) -> str:
    """Associated data that ties a sealed secret to its connection row."""
    return f"connection:aws:{account_id}"


def _token_binding(account_id: str) -> str:
    """The session token's own binding, so it never opens in the secret's place."""
    return f"{binding(account_id)}:session-token"


def _check_access_key(auth: AwsAuth) -> None:
    try:
        check_access_key(auth.access_key_id, auth.secret_access_key, auth.session_token)
    except ValueError as error:
        raise ConnectionError(str(error)) from error


def _seal_access_key(account_id: str, auth: AwsAuth) -> dict[str, object]:
    """The columns that hold an access key: the id, the sealed secret and the sealed token.
    Both are sealed now, under the current key, so the row's secret_key_id covers both."""
    if auth.secret_access_key is None:  # refused by _check_access_key; this narrows the type
        raise ConnectionError("secret_access_key is required")
    secret = seal(auth.secret_access_key, binding=binding(account_id))
    token = (
        seal(auth.session_token, binding=_token_binding(account_id)) if auth.session_token else None
    )
    return {
        "access_key_id": auth.access_key_id,
        "secret_ciphertext": secret.blob,
        "secret_key_id": secret.key_id,
        "session_token_ciphertext": token.blob if token else None,
    }


def allowed_kinds() -> tuple[ConnectionKind, ...]:
    """The connection kinds this deployment offers: no Demo where the deployment bound turns it
    off (ARGUS_DEMO_CONNECTIONS; the Kubernetes chart, ADR-0039)."""
    return ("aws", "demo") if get_settings().demo_connections else ("aws",)


def create_demo(conn: Connection, *, name: str, seed: int, actor: str) -> ConnectionRow:
    if "demo" not in allowed_kinds():
        raise ConnectionError(
            "Demo connections are for Docker Compose: this deployment offers AWS connections only"
        )
    row = conn.execute(
        text(
            f"INSERT INTO connection (name, kind, account_id, auth_method, demo_seed, "  # noqa: S608
            f"created_by, updated_by) VALUES (:name, 'demo', :account, 'none', :seed, :actor, "
            f":actor) RETURNING {_COLUMNS}"
        ),
        {"name": name, "account": demo_account_id(seed), "seed": seed, "actor": actor},
    ).one()
    return ConnectionRow(*row)


def _check_aws(account_id: str, auth: AwsAuth) -> None:
    if not re.fullmatch(r"[0-9]{12}", account_id):
        raise ConnectionError("account_id must be 12 digits")
    if auth.method == "assume_role":
        if not auth.role_arn or not _ROLE_ARN_RE.match(auth.role_arn):
            raise ConnectionError("role_arn must be an IAM role ARN")
        if f":{account_id}:" not in auth.role_arn:
            raise ConnectionError("role_arn must belong to the connection's account")
        if not auth.external_id or not _EXTERNAL_ID_RE.match(auth.external_id):
            raise ConnectionError("external_id must be 16 or more characters")
    else:
        _check_access_key(auth)


def create_aws(
    conn: Connection,
    *,
    name: str,
    account_id: str,
    auth: AwsAuth,
    actor: str,
    client_ip: str | None = None,
) -> ConnectionRow:
    _check_aws(account_id, auth)
    assume = auth.method == "assume_role"
    key: dict[str, object] = (
        dict.fromkeys(
            ("access_key_id", "secret_ciphertext", "secret_key_id", "session_token_ciphertext")
        )
        if assume
        else _seal_access_key(account_id, auth)
    )
    row = conn.execute(
        text(
            f"INSERT INTO connection (name, kind, account_id, auth_method, role_arn, external_id, "  # noqa: S608
            f"access_key_id, secret_ciphertext, secret_key_id, session_token_ciphertext, "
            f"secret_set_at, created_by, updated_by) VALUES (:n, 'aws', :a, :m, :role, :ext, "
            f":access_key_id, :secret_ciphertext, :secret_key_id, :session_token_ciphertext, "
            f"CASE WHEN CAST(:secret_ciphertext AS bytea) IS NULL THEN NULL ELSE now() END, "
            f":actor, :actor) RETURNING {_COLUMNS}"
        ),
        {
            "n": name,
            "a": account_id,
            "m": auth.method,
            "role": auth.role_arn if assume else None,
            "ext": auth.external_id if assume else None,
            **key,
            "actor": actor,
        },
    ).one()
    created = ConnectionRow(*row)
    audit.record(
        conn,
        actor=actor,
        action="connection.create",
        target_type="connection",
        target_id=str(created.id),
        client_ip=client_ip,
        detail={"kind": "aws", "auth_method": auth.method, "account_id": account_id},
    )
    return created


def update(
    conn: Connection,
    *,
    connection_id: int,
    actor: str,
    name: str | None = None,
    enabled: bool | None = None,
    access_key: AwsAuth | None = None,
    client_ip: str | None = None,
) -> ConnectionRow:
    """Rename, enable or disable, or replace an access key. A replacement is the whole set
    (key id, secret, session token): a rotated IAM key or a new SSO session changes all three.
    Connections are disabled, not deleted: their history references them."""
    current = get(conn, connection_id)
    if current is None:
        raise LookupError(connection_id)
    changes: dict[str, object] = {}
    if name is not None:
        changes["name"] = name
    if enabled is not None:
        changes["enabled"] = enabled
    if access_key is not None:
        if current.auth_method != "access_key":
            raise ConnectionError("only access-key connections have an access key to replace")
        _check_access_key(access_key)
        changes.update(_seal_access_key(current.account_id, access_key))
    if not changes:
        return current
    assignments = ", ".join(f"{column} = :{column}" for column in changes)
    if "secret_ciphertext" in changes:
        assignments += ", secret_set_at = now()"
    row = conn.execute(
        text(
            f"UPDATE connection SET {assignments}, updated_by = :actor, updated_at = now() "  # noqa: S608
            f"WHERE id = :id RETURNING {_COLUMNS}"
        ),
        {**changes, "actor": actor, "id": connection_id},
    ).one()
    audit.record(
        conn,
        actor=actor,
        action="connection.update",
        target_type="connection",
        target_id=str(connection_id),
        client_ip=client_ip,
        detail={
            "fields": sorted(
                {"name", "enabled"} & changes.keys() | ({"access_key"} if access_key else set())
            )
        },
    )
    return ConnectionRow(*row)


def open_auth(conn: Connection, connection: ConnectionRow) -> AwsAuth:
    """How the worker reaches an AWS account, secret and session token included, at the
    moment it collects: the worker's single way to the plaintext."""
    row = conn.execute(
        text(
            "SELECT role_arn, external_id, access_key_id, secret_ciphertext, secret_key_id, "
            "session_token_ciphertext FROM connection WHERE id = :i"
        ),
        {"i": connection.id},
    ).one()
    if connection.auth_method == "assume_role":
        return AwsAuth("assume_role", role_arn=row.role_arn, external_id=row.external_id)
    key_id = row.secret_key_id
    return AwsAuth(
        "access_key",
        access_key_id=row.access_key_id,
        secret_access_key=unseal(
            Sealed(key_id=key_id, blob=bytes(row.secret_ciphertext)),
            binding=binding(connection.account_id),
        ),
        session_token=(
            unseal(
                Sealed(key_id=key_id, blob=bytes(row.session_token_ciphertext)),
                binding=_token_binding(connection.account_id),
            )
            if row.session_token_ciphertext is not None
            else None
        ),
    )


def by_name(conn: Connection, name: str) -> ConnectionRow | None:
    row = conn.execute(
        text(f"SELECT {_COLUMNS} FROM connection WHERE name = :n"),  # noqa: S608
        {"n": name},
    ).one_or_none()
    return ConnectionRow(*row) if row else None


def get(conn: Connection, connection_id: int) -> ConnectionRow | None:
    row = conn.execute(
        text(f"SELECT {_COLUMNS} FROM connection WHERE id = :i"),  # noqa: S608
        {"i": connection_id},
    ).one_or_none()
    return ConnectionRow(*row) if row else None


def enabled(conn: Connection) -> list[ConnectionRow]:
    rows = conn.execute(
        text(f"SELECT {_COLUMNS} FROM connection WHERE enabled ORDER BY id")  # noqa: S608
    )
    return [ConnectionRow(*r) for r in rows]


def list_views(conn: Connection) -> list[ConnectionView]:
    """Every connection as the UI may see it (the API role cannot SELECT the secret column)."""
    rows = conn.execute(
        text("""
        SELECT id, name, kind, account_id, auth_method, role_arn, external_id_set,
               CASE WHEN access_key_id IS NULL THEN NULL
                    ELSE '…' || right(access_key_id, 4) END,
               secret_set_at, enabled, updated_at, updated_by
        FROM connection ORDER BY name
    """)
    )
    return [ConnectionView(*r) for r in rows]
