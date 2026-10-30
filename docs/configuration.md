# Configuration

**Owner:** `backend-engineer` (settings and variables) · `cloud-native-platform-engineer` (chart)
· `documentation-writer` (document)
**Applies to:** Argus 0.1.0 (2026-10-25)

Argus has three places for configuration, and each kind of value has exactly one home
([ADR-0023](adr/0023-configuration-split.md)):

| Where | What goes there | Changed by |
| --- | --- | --- |
| **Administration → Settings** | Every setting an administrator should change: collection and throttling, retention, raw output storage, the platform identity | The administrator, in the UI; stored in the database, audited, applied without a restart |
| **Environment variables** | Only what is needed before the database is reachable, secrets, and **bounds** on what an administrator may set | The operator: `.env` on Compose, the chart's values and Secret on Kubernetes |
| **Helm values** | How the chart deploys Argus on Kubernetes | The operator, at install and upgrade |

A bound exists so that a control an administrator could widen is not the only control: for
example, the longest history the UI may set is capped by `ARGUS_MAX_HISTORY_DAYS`.

## Administration settings

Each card under **Administration → Settings** is saved on its own, checked before saving, and
written to the audit log.

**Collection and throttling**

| Setting | Default | Range |
| --- | --- | --- |
| Max parallel runs, across all accounts | 2 | 1–16 |
| Start window: scheduled runs start spread over this many minutes | 180 | 0–720 |
| Run now cooldown: a tool is not run again on an account within this many minutes | 60 | 0–1440 |
| Retry delays: first retry and second retry of a failed run (minutes) | 30, 120 | 1–1440 each |
| AWS regions to scan (Prowler and Steampipe; CloudFox scans every region) | every enabled region | up to 40 |
| Steampipe tables at once | 4 | 1–8 |
| CloudFox concurrency | 5 | 1–30 |
| Minimum schedule interval (minutes) | 60 | 15–1440 |
| Synthetic throttling share: Demo runs that report throttling (%) | 5 | 0–100 |

**Retention**

| Setting | Default | Range |
| --- | --- | --- |
| History (days) | 180 | 30 – `ARGUS_MAX_HISTORY_DAYS` |
| Demo raw files (days) | 7 | 1–30 |

**Raw output storage**: the S3 bucket and region AWS runs write to, and a folder per tool
(default `raw/steampipe`, `raw/prowler`, `raw/cloudfox`). AWS runs cannot start until a bucket is
set. See [Connecting AWS accounts](connect-aws.md#1-the-raw-output-bucket).

**Platform identity**: **Ambient** (the role the environment gives the scanning process: IRSA on
Kubernetes) or **Access key** (a key, or temporary credentials with a session token). See
[Connecting AWS accounts](connect-aws.md#how-argus-signs-in).

## Environment variables

Every variable starts with `ARGUS_`. On Compose they come from `.env` (start from
[`.env.example`](../.env.example)); on Kubernetes the chart sets them from its values and the
Secret ([runbook](runbook-kubernetes.md#the-secret)). Each process reads only what it needs.

**Secrets**: never commit them; generate them with the commands shown.

| Variable | What it is |
| --- | --- |
| `ARGUS_BOOTSTRAP_ADMIN_PASSWORD` | First start only, read by `migrate`: the first admin's password. Remove it after the first sign-in ([ADR-0041](adr/0041-users-and-roles.md)) |
| `ARGUS_BOOTSTRAP_ADMIN_PASSWORD_HASH` | Instead of the password, its argon2id hash: `docker compose run --rm admin-tools hash-password` |
| `ARGUS_SECRET_KEYS` | The keyring that seals stored credentials, `k2:<base64>,k1:<base64>`: `docker compose run --rm admin-tools new-secret-key` |
| `ARGUS_SECRET_KEY_ID` | The keyring entry new secrets are sealed with, for example `k1` |
| `ARGUS_DB_PASSWORD` | The database password of the process's own role |
| `ARGUS_API_DB_PASSWORD`, `ARGUS_WORKER_DB_PASSWORD`, `ARGUS_SCHEDULER_DB_PASSWORD` | Read by the migration step only: it gives each application role its password |

**The database**

| Variable | Default | What it is |
| --- | --- | --- |
| `ARGUS_DB_HOST` | `postgres` | Host |
| `ARGUS_DB_PORT` | `5432` | Port |
| `ARGUS_DB_NAME` | `argus` | Database |
| `ARGUS_DB_USER` | `argus` | The role this process connects as (`argus_api`, `argus_worker`, `argus_scheduler`, or the schema owner for migrations) |
| `ARGUS_DB_SSLMODE` | unset | `verify-full` for a managed database; unset uses the driver's default |
| `ARGUS_DB_SSLROOTCERT` | unset | Path to the CA bundle for `verify-full` |

**Sign-in, history and connection bounds**: limits on what the administrator may set, or on
exposure.

| Variable | Default | What it bounds |
| --- | --- | --- |
| `ARGUS_SESSION_IDLE_MINUTES` | `30` | A session ends after this long without use |
| `ARGUS_SESSION_ABSOLUTE_HOURS` | `12` | A session ends after this long, used or not |
| `ARGUS_LOGIN_MAX_FAILURES` | `5` | Failures for one username from one address before it is locked |
| `ARGUS_LOGIN_LOCKOUT_MINUTES` | `15` | The window failures are counted in |
| `ARGUS_LOGIN_MAX_FAILURES_PER_IP` | `20` | Failures from one address, any username |
| `ARGUS_LOGIN_MAX_FAILURES_PER_USERNAME` | `100` | Failures for one username, any address |
| `ARGUS_MAX_HISTORY_DAYS` | `400` | The longest history the Retention setting may keep |
| `ARGUS_DEMO_CONNECTIONS` | `true` | Whether Demo connections may be added. The Kubernetes chart sets `false`: the API refuses them, the Add connection dialog offers AWS only and `seed` refuses ([ADR-0039](adr/0039-kubernetes-scheduler-and-run-jobs.md)) |

**Deployment facts**

| Variable | Default | What it is |
| --- | --- | --- |
| `ARGUS_BOOTSTRAP_ADMIN_USERNAME` | `admin` | `migrate`: the first admin's username, created with the bootstrap password while no active admin exists. Users are managed in **Administration → Users** after that |
| `ARGUS_LOG_LEVEL` | `INFO` | Log level; logs are JSON lines on stdout, redacted |
| `ARGUS_TRUSTED_PROXIES` | `127.0.0.1` | Addresses or ranges whose `X-Forwarded-For` the API believes: the web server only |
| `ARGUS_WORKER_THREADS` | `2` | Compose: runs one worker process executes at once (below **Max parallel runs**) |
| `ARGUS_DB_POOL_MAX` | `10` | The most connections this process opens to Postgres, a hard cap (1 to 50). A process refuses to start below its own peak: a scan Job 3; migrate, rederive and retention 2; the Compose worker 3 per run thread plus 3 (`compose.yaml` sets 9 for two threads). The API uses one per request in progress; a request that waits 10 seconds for one gets 503. On Kubernetes the chart sets it per pod from `database.pools` |
| `ARGUS_MAX_RUN_JOBS` | `4` | Kubernetes: AWS scans at once, below **Max parallel runs**; read by the scheduler and by each scan Job |
| `ARGUS_MAX_TEST_JOBS` | `1` | Kubernetes: scan Jobs the scheduler may start beyond that while connection tests wait |
| `ARGUS_JOB_TEMPLATES_DIR` | `/etc/argus/jobs` | Kubernetes: where the scheduler reads its fixed scan Job template, `scan.json` |
| `ARGUS_RAW_ROOT` | `/var/lib/argus` | Where Demo raw output is kept |
| `ARGUS_RAW_STAGING_ROOT` | `/var/lib/argus-staging` | Where an AWS run is staged before upload |
| `ARGUS_RULES_DIR` | `/opt/argus/rules` | The relationship and attack-path rules |

**Compose only**, read by `compose.yaml` rather than by Argus:

- `ARGUS_DEV_DB_PASSWORD`, `ARGUS_DEV_API_DB_PASSWORD`, `ARGUS_DEV_WORKER_DB_PASSWORD`: optional
  development passwords. Without them `compose.yaml` uses fixed ones, fine on a laptop and nowhere
  else.
- `ARGUS_E2E_PASSWORD`: the admin password, for the browser walk only.
- With `compose.single-instance.yaml` (a shared host), the development defaults are refused: set
  `ARGUS_DB_PASSWORD`, `ARGUS_API_DB_PASSWORD` and `ARGUS_WORKER_DB_PASSWORD`
  ([runbook](runbook.md#single-instance)).

## Helm values

The [chart README](../charts/argus/README.md) says what the chart creates and which values matter.
[`charts/argus/values.yaml`](../charts/argus/values.yaml) documents every value in place, and
[`values.schema.json`](../charts/argus/values.schema.json) refuses an install with a missing
required value, an image by tag, or an unknown key. The values you must set, and why, are in
[runbook-kubernetes.md, Values](runbook-kubernetes.md#values).
