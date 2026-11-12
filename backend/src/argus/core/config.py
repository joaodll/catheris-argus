"""Process configuration, read from the environment (prefix ARGUS_)."""

import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARGUS_", extra="forbid")

    db_host: str = "postgres"
    db_port: int = 5432
    db_name: str = "argus"
    db_user: str = "argus"
    db_password: SecretStr
    # TLS to Postgres: verify-full and a CA bundle for a managed database (ADR-0040). Unset, the
    # driver's default applies: Compose and the in-cluster StatefulSet are on private networks.
    db_sslmode: Literal["disable", "prefer", "require", "verify-ca", "verify-full"] | None = None
    db_sslrootcert: Path | None = None
    # The most connections this process opens to Postgres, a hard cap (a deployment fact): the
    # chart adds every pod's cap and refuses values Postgres cannot hold. A process whose own
    # peak is higher refuses to start (core.db.require_pool).
    db_pool_max: int = Field(default=10, ge=1, le=50)
    log_level: str = "INFO"
    # Credential encryption keyring: "k2:<base64 32 bytes>,k1:<...>". secret_key_id names the
    # key new secrets are sealed with; older keys stay to unseal rows not yet re-sealed.
    secret_keys: SecretStr | None = None
    secret_key_id: str | None = None
    # Users live in the database (ADR-0041). The first admin comes from ARGUS_BOOTSTRAP_ADMIN_*,
    # read by the migrate step only (entrypoints/migrate.py), never by a running process.
    # Session and sign-in limits bound every user's exposure, so they are operator-owned.
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    # Failures within the lockout window. A username from one address locks first; an address
    # alone limits spraying across usernames; a username alone (from any address) only at a
    # far higher count, so one attacker cannot keep the single administrator locked out.
    login_max_failures: int = 5
    login_lockout_minutes: int = 15
    login_max_failures_per_ip: int = 20
    login_max_failures_per_username: int = 100
    # Bound on an administrator's authority: the longest history the UI may configure.
    max_history_days: int = 400
    # Worker threads in one worker process (a deployment fact). How many runs may execute at
    # once across all workers is the administration setting "max parallel runs".
    worker_threads: int = 2
    # Kubernetes (ADR-0039), deployment facts: the scheduler starts at most this many scan Jobs
    # for AWS scans, below the administration setting "max parallel runs", and this many more
    # while connection tests wait. A scan Job never runs more scans at once than max_run_jobs.
    max_run_jobs: int = 4
    max_test_jobs: int = 1
    # A bound (ADR-0023): Demo connections are for Docker Compose. The chart turns them off, so
    # a Kubernetes deployment offers real connections only (ADR-0039).
    demo_connections: bool = True
    # The scheduler's fixed Job templates, mounted from the chart's ConfigMap.
    job_templates_dir: Path = Path("/etc/argus/jobs")
    # A scan Job's work, set by its template (ADR-0046): test, steampipe, prowler or cloudfox.
    # The Job refuses to start without one.
    job_work: str = ""
    # Addresses whose X-Forwarded-For the API believes: the reverse proxy in front of it.
    trusted_proxies: str = "127.0.0.1"
    # Deployment layout (operator-owned paths, not administration settings).
    raw_root: Path = Path("/var/lib/argus")
    # Where a run destined for S3 is staged before upload: a volume mounted in the worker
    # only, owner-only, emptied after each run and at start (ADR-0032).
    raw_staging_root: Path = Path("/var/lib/argus-staging")
    rules_dir: Path = Path("/opt/argus/rules")
    # Where reports are kept (ADR-0047), a deployment fact, never a setting. Docker Compose sets
    # reports_root: a volume the worker writes and the API reads only, Demo connections only. The
    # chart sets reports_store "s3" on IRSA installs: the reports/ folder of the raw-output
    # bucket, written by the report Job and read by the API, each with its own role. Neither
    # means this install keeps no reports: the API refuses requests and the screen says why.
    reports_root: Path | None = None
    reports_store: Literal["s3"] | None = None
    # Kubernetes: the most report Jobs the scheduler runs at once (a deployment fact).
    max_report_jobs: int = Field(default=1, ge=1, le=3)
    # Sign-in (ADR-0048). Set in the deployment, never in the UI: whoever could change the IdP
    # could choose who is Admin. SSO is on when the IdP's metadata file is set. Compose passes
    # every one from .env, empty when unused.
    # The URL people use to reach Argus. Argus's SAML entity id and ACS URL come from it, never
    # from request headers.
    public_url: str | None = None
    # The IdP's metadata, a file the deployment provides. Never fetched from a URL.
    saml_idp_metadata_file: Path | None = None
    # Which attribute of the IdP's answer carries the groups, the email (empty: the NameID) and
    # the display name (empty: none).
    saml_groups_attribute: str = ""
    saml_email_attribute: str = ""
    saml_name_attribute: str = ""
    # JSON: the exact group string the IdP sends -> viewer, operator or admin. The highest wins.
    saml_group_roles: Annotated[dict[str, Literal["viewer", "operator", "admin"]], NoDecode] = {}
    # Password sign-in, the break-glass path. Off, nobody signs in with a password.
    local_sign_in: bool = True

    @field_validator("public_url", "saml_idp_metadata_file", "reports_store", mode="before")
    @classmethod
    def _empty_is_unset(cls, value: Any) -> Any:
        return None if value == "" else value

    @field_validator("saml_group_roles", mode="before")
    @classmethod
    def _group_roles_json(cls, value: Any) -> Any:
        if isinstance(value, str):
            return json.loads(value) if value.strip() else {}
        return value

    @model_validator(mode="after")
    def _sign_in_is_whole(self) -> "Settings":
        """A half-configured sign-in refuses to start, rather than starting without a way in or
        with checks it can't make."""
        if self.public_url is not None:
            url = urlsplit(self.public_url)
            local = url.hostname in ("localhost", "127.0.0.1")
            if url.scheme != "https" and not (url.scheme == "http" and local):
                raise ValueError("ARGUS_PUBLIC_URL must be https (http only on localhost)")
            if not url.hostname or url.path not in ("", "/") or url.query or url.fragment:
                raise ValueError(
                    "ARGUS_PUBLIC_URL is a scheme and host, like https://argus.example"
                )
        if self.saml_idp_metadata_file is not None:
            if self.public_url is None:
                raise ValueError("SSO needs ARGUS_PUBLIC_URL")
            if not self.saml_groups_attribute:
                raise ValueError("SSO needs ARGUS_SAML_GROUPS_ATTRIBUTE")
            if not self.saml_group_roles:
                raise ValueError("SSO needs ARGUS_SAML_GROUP_ROLES: at least one group")
            if self.secret_keys is None or not self.secret_key_id:
                raise ValueError(
                    "SSO needs the keyring (ARGUS_SECRET_KEYS): it signs sign-in state"
                )
        elif not self.local_sign_in:
            raise ValueError("ARGUS_LOCAL_SIGN_IN off needs SSO: nobody could sign in")
        return self

    @model_validator(mode="after")
    def _one_reports_store(self) -> "Settings":
        if self.reports_root is not None and self.reports_store is not None:
            raise ValueError("set ARGUS_REPORTS_ROOT or ARGUS_REPORTS_STORE, not both")
        return self

    @property
    def sso(self) -> bool:
        return self.saml_idp_metadata_file is not None

    def database_url(self) -> URL:
        # URL.create keeps the password out of string formatting and repr(). TLS goes in the
        # query, so Alembic's own engine (migrations/env.py) gets it too.
        query: dict[str, str] = {}
        if self.db_sslmode is not None:
            query["sslmode"] = self.db_sslmode
        if self.db_sslrootcert is not None:
            query["sslrootcert"] = str(self.db_sslrootcert)
        return URL.create(
            "postgresql+psycopg",
            username=self.db_user,
            password=self.db_password.get_secret_value(),
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
            query=query,
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
