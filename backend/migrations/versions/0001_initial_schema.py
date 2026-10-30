"""Initial schema: administration, runs, canonical models, daily history.

Revision ID: 0001
Revises:
Create Date: 2026-10-02

Design rules this schema encodes (docs/design.md, "Canonical data models" and "Database load
and query rules"):

- Dimension tables (resource, resource_config, edge, finding, compliance_requirement) hold
  uids, names, tags and configuration once. Snapshot rows hold integer ids and small codes
  only, so six months of daily history stays near 8 GB at 100,000 resources.
- Snapshot, event and metric tables are partitioned by month on their date. There is no
  DEFAULT partition: a row for a month whose partition does not exist fails loudly instead of
  landing somewhere that blocks retention. argus_ensure_partitions() creates them.
- Invariants the worker relies on are constraints, not application code: one claimed request
  per connection (throttling layer 1), one request per schedule occurrence, credential fields
  matching the auth method.
- Two roles: argus_api (reads data, writes only administration rows, 5 s statement timeout,
  cannot SELECT stored secrets) and argus_worker (collection and ingest). Both are NOLOGIN
  here; the migrate entrypoint gives them LOGIN and passwords from the environment.

Small codes used in snapshot rows (documented once, here):
  severity: 1 critical, 2 high, 3 medium, 4 low, 5 informational
  finding status: 1 FAIL, 2 MANUAL (PASS findings are not stored; pass counts live in metric_daily)
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

PARTITIONED = (
    "resource_snapshot",
    "edge_snapshot",
    "finding_snapshot",
    "finding_event",
    "compliance_snapshot",
    "metric_daily",
)

UPGRADE = r"""
-- ---------------------------------------------------------------- roles
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_api') THEN
    CREATE ROLE argus_api NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_worker') THEN
    CREATE ROLE argus_worker NOLOGIN;
  END IF;
END $$;
ALTER ROLE argus_api SET statement_timeout = '5s';
ALTER ROLE argus_api SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE argus_worker SET idle_in_transaction_session_timeout = '5min';

-- ---------------------------------------------------------------- administration
CREATE TABLE connection (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name                text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100),
  kind                text NOT NULL CHECK (kind IN ('demo', 'aws')),
  provider            text NOT NULL DEFAULT 'aws' CHECK (provider = 'aws'),
  account_id          text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
  auth_method         text NOT NULL CHECK (auth_method IN ('none', 'assume_role', 'access_key')),
  role_arn            text,
  external_id         text,
  access_key_id       text,
  secret_ciphertext   bytea,
  secret_key_id       text,
  secret_set_at       timestamptz,
  demo_seed           integer,
  enabled             boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  created_by          text NOT NULL,
  updated_at          timestamptz NOT NULL DEFAULT now(),
  updated_by          text NOT NULL,
  UNIQUE (provider, account_id),
  CONSTRAINT connection_auth_matches_kind CHECK (
    (kind = 'demo' AND auth_method = 'none')
    OR (kind = 'aws' AND auth_method IN ('assume_role', 'access_key'))
  ),
  CONSTRAINT connection_assume_role_fields CHECK (
    auth_method <> 'assume_role'
    OR (role_arn IS NOT NULL AND external_id IS NOT NULL AND secret_ciphertext IS NULL)
  ),
  CONSTRAINT connection_access_key_fields CHECK (
    auth_method <> 'access_key'
    OR (access_key_id IS NOT NULL AND secret_ciphertext IS NOT NULL AND secret_key_id IS NOT NULL)
  ),
  CONSTRAINT connection_demo_has_no_credentials CHECK (
    kind <> 'demo'
    OR (role_arn IS NULL AND access_key_id IS NULL AND secret_ciphertext IS NULL)
  )
);

-- One row per settings topic (collection, retention, identity, ...). Values are validated by
-- the application against their environment bounds; the secret of the platform identity is
-- stored encrypted next to its topic, never inside the JSON.
CREATE TABLE platform_setting (
  topic               text PRIMARY KEY CHECK (topic ~ '^[a-z_]+$'),
  value               jsonb NOT NULL,
  secret_ciphertext   bytea,
  secret_key_id       text,
  updated_at          timestamptz NOT NULL DEFAULT now(),
  updated_by          text NOT NULL
);

CREATE TABLE schedule (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name                text NOT NULL UNIQUE,
  tool                text NOT NULL CHECK (tool IN ('steampipe', 'prowler', 'cloudfox')),
  cron                text NOT NULL,
  all_connections     boolean NOT NULL DEFAULT true,
  enabled             boolean NOT NULL DEFAULT true,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  updated_by          text NOT NULL
);

-- Used only when schedule.all_connections is false.
CREATE TABLE schedule_connection (
  schedule_id         bigint NOT NULL REFERENCES schedule (id) ON DELETE CASCADE,
  connection_id       bigint NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
  PRIMARY KEY (schedule_id, connection_id)
);

-- ---------------------------------------------------------------- runs
CREATE TABLE scan_run (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_uid             uuid NOT NULL UNIQUE,
  connection_id       bigint NOT NULL REFERENCES connection (id),
  tool                text NOT NULL CHECK (tool IN ('steampipe', 'prowler', 'cloudfox')),
  tool_version        text NOT NULL,
  source              text NOT NULL CHECK (source IN ('synthetic', 'aws')),
  snapshot_date       date NOT NULL,
  region_scope        text[] NOT NULL DEFAULT '{}',
  status              text NOT NULL CHECK (status IN ('running', 'complete', 'partial', 'failed')),
  started_at          timestamptz NOT NULL,
  finished_at         timestamptz,
  raw_path            text NOT NULL,
  exit_code           integer,
  throttle_events     integer NOT NULL DEFAULT 0 CHECK (throttle_events >= 0),
  api_regions         integer,
  log_tail            text,
  ingested_at         timestamptz,
  CHECK (finished_at IS NULL OR finished_at >= started_at)
);
-- "Last run per tool and account", and the history behind the Runs tab.
CREATE INDEX scan_run_connection_tool_date ON scan_run (connection_id, tool, snapshot_date DESC);

CREATE TABLE run_request (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  connection_id       bigint NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
  tool                text NOT NULL CHECK (tool IN ('steampipe', 'prowler', 'cloudfox')),
  reason              text NOT NULL CHECK (reason IN ('schedule', 'manual', 'retry', 'backfill')),
  schedule_id         bigint REFERENCES schedule (id) ON DELETE SET NULL,
  occurrence_at       timestamptz,
  snapshot_date       date,
  not_before          timestamptz NOT NULL DEFAULT now(),
  attempt             smallint NOT NULL DEFAULT 1 CHECK (attempt BETWEEN 1 AND 3),
  retry_of            bigint REFERENCES run_request (id) ON DELETE SET NULL,
  status              text NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'claimed', 'finished', 'cancelled')),
  claimed_by          text,
  claimed_at          timestamptz,
  finished_at         timestamptz,
  scan_run_id         bigint REFERENCES scan_run (id) ON DELETE SET NULL,
  requested_by        text NOT NULL,
  requested_at        timestamptz NOT NULL DEFAULT now(),
  CHECK ((status = 'claimed') = (claimed_at IS NOT NULL AND finished_at IS NULL)
         OR status IN ('finished', 'cancelled'))
);
-- Throttling layer 1: at most one claimed request per connection, enforced by the database so
-- two workers can never run two tools against the same account at once.
CREATE UNIQUE INDEX run_request_one_claimed_per_connection
  ON run_request (connection_id) WHERE status = 'claimed';
-- One request per schedule occurrence per connection, however many workers tick.
CREATE UNIQUE INDEX run_request_one_per_occurrence
  ON run_request (schedule_id, connection_id, occurrence_at)
  WHERE schedule_id IS NOT NULL AND occurrence_at IS NOT NULL;
-- The claim query: queued requests whose time has come, oldest first.
CREATE INDEX run_request_claimable ON run_request (not_before, id) WHERE status = 'queued';
-- Cooldown and "is something already queued for this account and tool".
CREATE INDEX run_request_connection_tool ON run_request (connection_id, tool, requested_at DESC);

CREATE TABLE unresolved_ref (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tool                text NOT NULL,
  connection_id       bigint NOT NULL REFERENCES connection (id),
  raw_ref             text NOT NULL,
  reason              text NOT NULL,
  first_seen          date NOT NULL,
  last_seen           date NOT NULL,
  last_scan_run_id    bigint REFERENCES scan_run (id) ON DELETE SET NULL,
  UNIQUE (tool, connection_id, raw_ref)
);

-- ---------------------------------------------------------------- dimensions
CREATE TABLE resource_config (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  config_hash         bytea NOT NULL UNIQUE CHECK (length(config_hash) = 32),
  config              jsonb NOT NULL,
  created_on          date NOT NULL
);

CREATE TABLE resource (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  resource_uid        text NOT NULL UNIQUE,
  connection_id       bigint NOT NULL REFERENCES connection (id),
  provider            text NOT NULL DEFAULT 'aws',
  region              text NOT NULL,
  type                text NOT NULL,
  native_id           text NOT NULL,
  name                text,
  vpc_id              text,
  tags                jsonb NOT NULL DEFAULT '{}',
  config_id           bigint REFERENCES resource_config (id),
  first_seen          date NOT NULL,
  last_seen           date NOT NULL,
  deleted_on          date,
  CHECK (last_seen >= first_seen)
);
-- UI filters (account, region, type, VPC) are plain indexed columns; JSONB is never filtered by
-- the API.
CREATE INDEX resource_connection_type ON resource (connection_id, type);
CREATE INDEX resource_region ON resource (region);
CREATE INDEX resource_vpc ON resource (vpc_id) WHERE vpc_id IS NOT NULL;

CREATE TABLE edge (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  edge_key            bytea NOT NULL UNIQUE CHECK (length(edge_key) = 32),
  source_uid          text NOT NULL,
  target_uid          text NOT NULL,
  source_resource_id  bigint REFERENCES resource (id),
  target_resource_id  bigint REFERENCES resource (id),
  type                text NOT NULL,
  origin              text NOT NULL
                        CHECK (origin ~ '^(rule:[a-z0-9_.-]+@[0-9]+|cloudfox|manual|probe)$'),
  attributes          jsonb NOT NULL DEFAULT '{}',
  first_seen          date NOT NULL,
  last_seen           date NOT NULL,
  author              text,
  reason              text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  stale               boolean NOT NULL DEFAULT false,
  CONSTRAINT edge_manual_has_author CHECK (
    origin <> 'manual' OR (author IS NOT NULL AND reason IS NOT NULL)
  )
);
CREATE INDEX edge_source ON edge (source_resource_id);
CREATE INDEX edge_target ON edge (target_resource_id);

CREATE TABLE finding (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  finding_uid         text NOT NULL UNIQUE,
  tool                text NOT NULL CHECK (tool IN ('prowler', 'cloudfox')),
  check_id            text NOT NULL,
  connection_id       bigint NOT NULL REFERENCES connection (id),
  region              text NOT NULL,
  resource_uid        text NOT NULL,
  resource_id         bigint REFERENCES resource (id),
  severity            text NOT NULL
                        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
  status              text NOT NULL CHECK (status IN ('FAIL', 'MANUAL')),
  muted               boolean NOT NULL DEFAULT false,
  title               text NOT NULL,
  remediation_text    text,
  remediation_url     text,
  compliance          jsonb NOT NULL DEFAULT '{}',
  state               text NOT NULL
                        CHECK (state IN ('open', 'resolved', 'reopened', 'accepted_risk')),
  first_seen          date NOT NULL,
  last_seen           date NOT NULL,
  resolved_on         date,
  accepted_until      date,
  CHECK ((state = 'resolved') = (resolved_on IS NOT NULL))
);
-- Lifecycle: "open findings of this tool and account" when a complete run arrives.
CREATE INDEX finding_connection_tool_state ON finding (connection_id, tool, state);
CREATE INDEX finding_resource ON finding (resource_id) WHERE resource_id IS NOT NULL;

CREATE TABLE compliance_requirement (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  framework           text NOT NULL,
  framework_version   text NOT NULL,
  requirement_id      text NOT NULL,
  description         text,
  UNIQUE (framework, framework_version, requirement_id)
);

CREATE TABLE attack_path (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  path_id             bytea NOT NULL UNIQUE CHECK (length(path_id) = 32),
  rule_id             text NOT NULL,
  rule_version        integer NOT NULL,
  category            text NOT NULL,
  severity            text NOT NULL
                        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
  connection_id       bigint NOT NULL REFERENCES connection (id),
  entry_uid           text NOT NULL,
  target_uid          text NOT NULL,
  node_uids           text[] NOT NULL,
  edge_ids            bigint[] NOT NULL,
  state               text NOT NULL CHECK (state IN ('open', 'resolved')),
  first_seen          date NOT NULL,
  last_seen           date NOT NULL,
  resolved_on         date,
  CHECK ((state = 'resolved') = (resolved_on IS NOT NULL))
);
CREATE INDEX attack_path_connection_state ON attack_path (connection_id, state);

-- ---------------------------------------------------------------- daily history (partitioned)
CREATE TABLE resource_snapshot (
  snapshot_date       date NOT NULL,
  resource_id         bigint NOT NULL REFERENCES resource (id),
  config_id           bigint NOT NULL REFERENCES resource_config (id),
  PRIMARY KEY (snapshot_date, resource_id)
) PARTITION BY RANGE (snapshot_date);

CREATE TABLE edge_snapshot (
  snapshot_date       date NOT NULL,
  edge_id             bigint NOT NULL REFERENCES edge (id),
  PRIMARY KEY (snapshot_date, edge_id)
) PARTITION BY RANGE (snapshot_date);

CREATE TABLE finding_snapshot (
  snapshot_date       date NOT NULL,
  finding_id          bigint NOT NULL REFERENCES finding (id),
  status              smallint NOT NULL CHECK (status IN (1, 2)),
  severity            smallint NOT NULL CHECK (severity BETWEEN 1 AND 5),
  muted               boolean NOT NULL,
  PRIMARY KEY (snapshot_date, finding_id)
) PARTITION BY RANGE (snapshot_date);

CREATE TABLE finding_event (
  occurred_on         date NOT NULL,
  id                  bigint GENERATED ALWAYS AS IDENTITY,
  finding_id          bigint NOT NULL REFERENCES finding (id),
  event               text NOT NULL
                        CHECK (event IN ('opened', 'resolved', 'reopened', 'accepted',
                                         'unaccepted')),
  scan_run_id         bigint REFERENCES scan_run (id) ON DELETE SET NULL,
  recorded_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (occurred_on, id)
) PARTITION BY RANGE (occurred_on);

CREATE TABLE compliance_snapshot (
  snapshot_date       date NOT NULL,
  connection_id       bigint NOT NULL REFERENCES connection (id),
  requirement_id      bigint NOT NULL REFERENCES compliance_requirement (id),
  scan_run_id         bigint NOT NULL REFERENCES scan_run (id),
  status              smallint NOT NULL CHECK (status IN (1, 2, 3)),  -- 1 FAIL, 2 MANUAL, 3 PASS
  passed_checks       integer NOT NULL CHECK (passed_checks >= 0),
  failed_checks       integer NOT NULL CHECK (failed_checks >= 0),
  PRIMARY KEY (snapshot_date, connection_id, requirement_id)
) PARTITION BY RANGE (snapshot_date);

-- Pre-aggregated rows behind every chart. connection_id 0 means "all connections".
CREATE TABLE metric_daily (
  snapshot_date       date NOT NULL,
  connection_id       bigint NOT NULL,
  metric              text NOT NULL,
  dimension           text NOT NULL DEFAULT '',
  value               double precision NOT NULL,
  PRIMARY KEY (snapshot_date, connection_id, metric, dimension)
) PARTITION BY RANGE (snapshot_date);

-- Creates the monthly partitions covering [from_date, to_date] for every partitioned table.
-- Idempotent; called by migrations, by ingest before loading a day, and by retention.
-- SECURITY DEFINER: partitions belong to the schema owner whoever creates them, so retention
-- can drop any of them. EXECUTE is revoked from PUBLIC below and granted to the worker only.
CREATE FUNCTION argus_ensure_partitions(from_date date, to_date date) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
DECLARE
  parent text;
  month_start date;
  created integer := 0;
  part text;
BEGIN
  FOREACH parent IN ARRAY ARRAY[
    'resource_snapshot', 'edge_snapshot', 'finding_snapshot',
    'finding_event', 'compliance_snapshot', 'metric_daily'
  ] LOOP
    month_start := date_trunc('month', from_date)::date;
    WHILE month_start <= to_date LOOP
      part := format('%s_%s', parent, to_char(month_start, 'YYYYMM'));
      IF to_regclass(part) IS NULL THEN
        EXECUTE format(
          'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
          part, parent, month_start, (month_start + interval '1 month')::date
        );
        created := created + 1;
      END IF;
      month_start := (month_start + interval '1 month')::date;
    END LOOP;
  END LOOP;
  RETURN created;
END
$fn$;

-- Drops every monthly partition that ends on or before cutoff. Returns the dropped names.
-- Orphaned resource_config rows are deleted by the retention job afterwards.
CREATE FUNCTION argus_drop_partitions_before(cutoff date) RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
DECLARE
  rec record;
BEGIN
  FOR rec IN
    SELECT c.relname AS part
    FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_class p ON p.oid = i.inhparent
    WHERE p.relname IN ('resource_snapshot', 'edge_snapshot', 'finding_snapshot',
                        'finding_event', 'compliance_snapshot', 'metric_daily')
      AND c.relname ~ '_[0-9]{6}$'
      AND (to_date(right(c.relname, 6), 'YYYYMM') + interval '1 month')::date <= cutoff
  LOOP
    EXECUTE format('DROP TABLE %I', rec.part);
    RETURN NEXT rec.part;
  END LOOP;
END
$fn$;

-- Partitions for the default six months of history plus the next two months.
SELECT argus_ensure_partitions((current_date - interval '7 months')::date,
                               (current_date + interval '2 months')::date);

-- ---------------------------------------------------------------- authentication and audit
CREATE TABLE admin_session (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  token_hash          bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  username            text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  idle_expires_at     timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at          timestamptz,
  client_ip           inet,
  user_agent          text
);
CREATE INDEX admin_session_username ON admin_session (username) WHERE revoked_at IS NULL;

CREATE TABLE login_failure (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username            text NOT NULL,
  client_ip           inet,
  failed_at           timestamptz NOT NULL DEFAULT now()
);
-- Lockout and rate limit: failures for a username, or from an address, in the last window.
CREATE INDEX login_failure_username ON login_failure (username, failed_at DESC);
CREATE INDEX login_failure_ip ON login_failure (client_ip, failed_at DESC);

-- Append-only: no role but the owner may UPDATE or DELETE it.
CREATE TABLE audit_log (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at         timestamptz NOT NULL DEFAULT now(),
  actor               text NOT NULL,
  action              text NOT NULL,
  target_type         text,
  target_id           text,
  detail              jsonb NOT NULL DEFAULT '{}',
  client_ip           inet
);
CREATE INDEX audit_log_occurred ON audit_log (occurred_at DESC);

-- ---------------------------------------------------------------- grants
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO argus_api, argus_worker;

-- API: reads data; writes administration rows only. Partitions inherit nothing, so reads go
-- through the parent tables, which is also what keeps queries pruned.
GRANT SELECT ON scan_run, unresolved_ref, resource, resource_config, edge, finding,
  compliance_requirement, attack_path, resource_snapshot, edge_snapshot, finding_snapshot,
  finding_event, compliance_snapshot, metric_daily, schedule, schedule_connection, run_request
  TO argus_api;
-- Connections: every column except the stored secret, which the API may write but never read.
GRANT SELECT (id, name, kind, provider, account_id, auth_method, role_arn, external_id,
  access_key_id, secret_key_id, secret_set_at, demo_seed, enabled, created_at, created_by,
  updated_at, updated_by) ON connection TO argus_api;
GRANT INSERT, UPDATE, DELETE ON connection TO argus_api;
GRANT SELECT (topic, value, secret_key_id, updated_at, updated_by) ON platform_setting TO argus_api;
GRANT INSERT, UPDATE ON platform_setting TO argus_api;
GRANT INSERT, UPDATE, DELETE ON schedule, schedule_connection TO argus_api;
GRANT INSERT ON run_request TO argus_api;
GRANT UPDATE (status, finished_at) ON run_request TO argus_api;   -- cancel only
GRANT SELECT, INSERT, UPDATE ON admin_session TO argus_api;
GRANT SELECT, INSERT, DELETE ON login_failure TO argus_api;
GRANT SELECT, INSERT ON audit_log TO argus_api;
GRANT UPDATE (state, accepted_until) ON finding TO argus_api;     -- accept a risk (later phases)

-- Worker: collection, ingest, scheduling, retention. No sessions, no login data.
GRANT SELECT ON connection, platform_setting, schedule, schedule_connection TO argus_worker;
GRANT SELECT, INSERT, UPDATE ON run_request, scan_run, unresolved_ref, resource,
  resource_config, edge, finding, compliance_requirement, attack_path TO argus_worker;
GRANT DELETE ON resource_config TO argus_worker;                  -- orphan cleanup in retention
GRANT SELECT, INSERT, UPDATE, DELETE ON resource_snapshot, edge_snapshot, finding_snapshot,
  compliance_snapshot, metric_daily TO argus_worker;               -- a re-run replaces its day
GRANT SELECT, INSERT ON finding_event TO argus_worker;
GRANT INSERT ON audit_log TO argus_worker;
REVOKE EXECUTE ON FUNCTION argus_ensure_partitions(date, date) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION argus_drop_partitions_before(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION argus_ensure_partitions(date, date) TO argus_worker;
GRANT EXECUTE ON FUNCTION argus_drop_partitions_before(date) TO argus_worker;
"""

DOWNGRADE = r"""
DROP TABLE IF EXISTS audit_log, login_failure, admin_session,
  metric_daily, compliance_snapshot, finding_event, finding_snapshot, edge_snapshot,
  resource_snapshot, attack_path, compliance_requirement, finding, edge, resource,
  resource_config, unresolved_ref, run_request, scan_run, schedule_connection, schedule,
  platform_setting, connection CASCADE;
DROP FUNCTION IF EXISTS argus_ensure_partitions(date, date);
DROP FUNCTION IF EXISTS argus_drop_partitions_before(date);
-- The roles are kept: they may own sessions or grants outside this schema. 0001 recreates
-- them idempotently.
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
