import json
import logging
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import Connection, text

from argus.core.aws import ACCESS_KEY_ID_PATTERN, SessionCredentials, check_access_key
from argus.core.config import get_settings
from argus.core.secrets import Sealed, seal, unseal

log = logging.getLogger("argus.settings")


class SettingsBoundError(ValueError):
    """A value beyond the bound the operator set in the environment."""


class CollectionSettings(BaseModel):
    """Throttling-aware collection, layer 1 (ADR-0022)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_parallel_runs: int = Field(2, ge=1, le=16)
    stagger_window_minutes: int = Field(180, ge=0, le=720)
    run_now_cooldown_minutes: int = Field(60, ge=0, le=1440)
    # Delay before the first and the second retry of a failed run (claims.retry).
    retry_delays_minutes: list[Annotated[int, Field(ge=1, le=1440)]] = Field(
        default_factory=lambda: [30, 120], min_length=2, max_length=2
    )
    synthetic_throttle_share: float = Field(0.05, ge=0, le=1)
    cloudfox_max_goroutines: int = Field(5, ge=1, le=30)
    # Steampipe tables exported at once in one run (argus_v8: ~400 tables, one at a time is
    # hours). Each export calls one service; more at once is faster and throttles sooner.
    steampipe_parallel_tables: int = Field(4, ge=1, le=8)
    # AWS regions Prowler and Steampipe scan (CloudFox has no region option). Empty: every
    # region enabled in the account.
    aws_regions: list[Annotated[str, Field(pattern=r"^[a-z]{2}(-[a-z]+)+-[0-9]$")]] = Field(
        default_factory=list, max_length=40
    )
    schedule_min_interval_minutes: int = Field(60, ge=15, le=1440)


class RetentionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    history_days: int = Field(180, ge=30)
    demo_raw_days: int = Field(7, ge=1, le=30)

    def bounded(self) -> "RetentionSettings":
        limit = get_settings().max_history_days
        if self.history_days <= limit:
            return self
        log.warning(
            "history_days above ARGUS_MAX_HISTORY_DAYS, clamped",
            extra={"stored": self.history_days, "bound": limit},
        )
        return self.model_copy(update={"history_days": limit})


# An S3 key prefix: path segments of safe characters, no slash at either end, no "..".
KeyPrefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$", max_length=200)]


class ToolPrefixes(BaseModel):
    """Each tool's folder in the bucket. The defaults are the design's layout, raw/<tool>."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    steampipe: KeyPrefix = "raw/steampipe"
    prowler: KeyPrefix = "raw/prowler"
    cloudfox: KeyPrefix = "raw/cloudfox"
    vulnerabilities: KeyPrefix = "raw/vulnerabilities"


class RawStorageSettings(BaseModel):
    """Where AWS runs keep their raw output: an S3 bucket the operator owns, encrypted by its
    default SSE-KMS key, with a folder per tool. Demo connections always use the local volume.
    While no bucket is set, AWS runs cannot start: raw output of a real account never lands
    on the unencrypted local volume (SA-8)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket: str | None = Field(None, pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    region: str | None = Field(None, pattern=r"^[a-z]{2}(-[a-z]+)+-[0-9]$")
    prefixes: ToolPrefixes = Field(default_factory=ToolPrefixes)

    @model_validator(mode="after")
    def _bucket_with_region(self) -> "RawStorageSettings":
        if (self.bucket is None) != (self.region is None):
            raise ValueError("bucket and region are set together")
        return self


TOPICS: dict[str, type[BaseModel]] = {
    "collection": CollectionSettings,
    "retention": RetentionSettings,
    "raw_storage": RawStorageSettings,
}


def _stored(conn: Connection, topic: str) -> dict[str, Any]:
    value = conn.execute(
        text("SELECT value FROM platform_setting WHERE topic = :t"), {"t": topic}
    ).scalar_one_or_none()
    return dict(value or {})


def read_collection(conn: Connection) -> CollectionSettings:
    return CollectionSettings.model_validate(_stored(conn, "collection"))


def read_retention(conn: Connection) -> RetentionSettings:
    return RetentionSettings.model_validate(_stored(conn, "retention")).bounded()


def read_raw_storage(conn: Connection) -> RawStorageSettings:
    return RawStorageSettings.model_validate(_stored(conn, "raw_storage"))


def write_topic(conn: Connection, *, topic: str, values: dict[str, Any], actor: str) -> BaseModel:
    """Validates and stores a whole topic. Raises SettingsBoundError naming the environment
    bound when a value exceeds it (the API turns this into a 422)."""
    model = TOPICS[topic].model_validate(values)
    if (
        isinstance(model, RetentionSettings)
        and model.history_days > get_settings().max_history_days
    ):
        raise SettingsBoundError(
            f"history_days may not exceed ARGUS_MAX_HISTORY_DAYS "
            f"({get_settings().max_history_days})"
        )
    conn.execute(
        text("""
        INSERT INTO platform_setting (topic, value, updated_by) VALUES (:t, CAST(:v AS jsonb), :a)
        ON CONFLICT (topic) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by,
          updated_at = now()
    """),
        {"t": topic, "v": json.dumps(model.model_dump(mode="json")), "a": actor},
    )
    return model


class IdentitySettings(BaseModel):
    """The platform identity that assumes connection roles (ADR-0024): the ambient identity
    (Pod Identity, instance role) in production, or a stored access key for local tests."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["ambient", "access_key"] = "ambient"
    access_key_id: str | None = Field(None, pattern=ACCESS_KEY_ID_PATTERN)


IDENTITY_BINDING = "setting:identity"
IDENTITY_TOKEN_BINDING = "setting:identity:session-token"  # noqa: S105 - associated data


def read_identity(conn: Connection) -> tuple[IdentitySettings, bool]:
    """The identity and whether a secret is stored (the API cannot read the secret itself)."""
    row = conn.execute(
        text("SELECT value, secret_key_id FROM platform_setting WHERE topic = 'identity'")
    ).one_or_none()
    if row is None:
        return IdentitySettings(), False
    return IdentitySettings.model_validate(row.value), row.secret_key_id is not None


def write_identity(
    conn: Connection,
    *,
    mode: str,
    access_key_id: str | None,
    secret_access_key: str | None,
    session_token: str | None,
    actor: str,
) -> IdentitySettings:
    """Set the identity. An access key is a long-lived key (AKIA...) or a temporary one
    (ASIA..., SSO) with its session token; both are sealed now, under the current key."""
    model = IdentitySettings.model_validate({"mode": mode, "access_key_id": access_key_id})
    secret = token = None
    # The update sets the secrets from the parameters, not EXCLUDED: reading EXCLUDED.<column>
    # needs SELECT on it, and the API role must never be able to read a sealed column.
    if model.mode == "access_key":
        check_access_key(model.access_key_id, secret_access_key, session_token)
        if secret_access_key is None:  # refused above; this narrows the type
            raise ValueError("secret_access_key is required")
        secret = seal(secret_access_key, binding=IDENTITY_BINDING)
        if session_token:
            token = seal(session_token, binding=IDENTITY_TOKEN_BINDING)
    conn.execute(
        text("""
        INSERT INTO platform_setting (topic, value, secret_ciphertext, secret_key_id,
          session_token_ciphertext, updated_by)
        VALUES ('identity', CAST(:v AS jsonb), :blob, :kid, :token, :a)
        ON CONFLICT (topic) DO UPDATE SET value = EXCLUDED.value,
          secret_ciphertext = :blob, secret_key_id = :kid, session_token_ciphertext = :token,
          updated_by = EXCLUDED.updated_by, updated_at = now()
    """),
        {
            "v": json.dumps(model.model_dump(mode="json")),
            "blob": secret.blob if secret else None,
            "kid": secret.key_id if secret else None,
            "token": token.blob if token else None,
            "a": actor,
        },
    )
    return model


def read_identity_credentials(conn: Connection) -> SessionCredentials | None:
    """The identity's access key, for the worker at the moment it builds an AWS session; None
    for the ambient identity. The API role cannot read the sealed columns, so this works in
    the worker only."""
    row = conn.execute(
        text(
            "SELECT value, secret_ciphertext, secret_key_id, session_token_ciphertext "
            "FROM platform_setting WHERE topic = 'identity'"
        )
    ).one_or_none()
    if row is None or row.secret_key_id is None:
        return None
    identity = IdentitySettings.model_validate(row.value)
    if identity.mode != "access_key" or identity.access_key_id is None:
        return None
    return SessionCredentials(
        identity.access_key_id,
        unseal(
            Sealed(key_id=row.secret_key_id, blob=bytes(row.secret_ciphertext)),
            binding=IDENTITY_BINDING,
        ),
        unseal(
            Sealed(key_id=row.secret_key_id, blob=bytes(row.session_token_ciphertext)),
            binding=IDENTITY_TOKEN_BINDING,
        )
        if row.session_token_ciphertext is not None
        else None,
    )
