"""Process configuration, read from the environment (prefix ARGUS_)."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
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
    # Addresses whose X-Forwarded-For the API believes: the reverse proxy in front of it.
    trusted_proxies: str = "127.0.0.1"
    # Deployment layout (operator-owned paths, not administration settings).
    raw_root: Path = Path("/var/lib/argus")
    # Where a run destined for S3 is staged before upload: a volume mounted in the worker
    # only, owner-only, emptied after each run and at start (ADR-0032).
    raw_staging_root: Path = Path("/var/lib/argus-staging")
    rules_dir: Path = Path("/opt/argus/rules")

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
