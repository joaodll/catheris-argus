"""Risk: the resources where facts from different tools add up (ADR-0049, owner 2026-11-12).

Revision ID: 0051
Revises: 0050
Create Date: 2026-11-12

Both tables are owned by the `risk` module and are current-state read models, rewritten by the
worker after each ingest of a connection (risk.refresh). History is in metric_daily
(`risk.resources`), never here.

- **`resource_risk`**: one row per resource that matches at least one named combination (the
  Risk list is one row per resource). The facts are plain columns, so the API reads no JSONB.
  `sort_key` holds the list's order (tier, number of combinations, CVEs with a public exploit,
  highest EPSS, worst misconfiguration), computed by the module; ties fall to the resource id.
  `provider` and `resource_type` are copied from the connection and the resource (neither ever
  changes) so the list's Provider and Type filters need no join.
  `door_held_since` is set while the resource's internet door has turned `unknown` (data the
  verdict needs is missing): missing data never removes a row (ADR-0049 section 5).
- **`risk_load`**: one row per connection, the day of its last refresh and the combination set
  it used (a SHA-256 of every combination's id and version). It is `data_through`, and its
  absence is "not computed yet", never "nothing at risk". A set that differs refreshes the
  connection at the next start.

Both key on the resource or connection with ON DELETE CASCADE: a connection deleted, or a
resource purged by retention, takes its rows along (referential actions run as the table's owner,
so neither the API nor retention needs a grant here).

Grants: the API reads; the worker (Compose worker, scan and re-derive Jobs) writes.

New, empty tables: no lock on anything else.
"""

from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE resource_risk (
          resource_id             bigint PRIMARY KEY REFERENCES resource (id) ON DELETE CASCADE,
          connection_id           bigint NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
          provider                text NOT NULL CHECK (provider IN ('aws', 'gcp', 'oci')),
          resource_type           text NOT NULL CHECK (length(resource_type) BETWEEN 1 AND 200),
          tier                    text NOT NULL CHECK (tier IN ('critical', 'high', 'medium')),
          combinations            text[] NOT NULL CHECK (
                                    cardinality(combinations) BETWEEN 1 AND 32
                                    AND array_position(combinations, NULL) IS NULL
                                  ),
          sort_key                bigint NOT NULL CHECK (sort_key >= 0),
          first_seen              date NOT NULL,
          door_held_since         date,
          door                    boolean NOT NULL,
          admin                   boolean NOT NULL,
          env_secret              boolean NOT NULL,
          credential_kinds        text[] NOT NULL DEFAULT '{}' CHECK (
                                    array_position(credential_kinds, NULL) IS NULL
                                  ),
          exploitable_cves        integer NOT NULL CHECK (exploitable_cves >= 0),
          high_cves               integer NOT NULL CHECK (high_cves >= 0),
          max_epss                real CHECK (max_epss BETWEEN 0 AND 1),
          high_misconfigurations  integer NOT NULL CHECK (high_misconfigurations >= 0),
          worst_misconfiguration  text CHECK (
                                    worst_misconfiguration IN
                                      ('critical', 'high', 'medium', 'low', 'informational')
                                  ),
          CONSTRAINT resource_risk_held CHECK (door_held_since IS NULL OR door)
        );
        -- The list for all accounts, worst first.
        CREATE INDEX resource_risk_order ON resource_risk (sort_key DESC, resource_id);
        -- The list for one account, and a refresh's read of its connection's rows.
        CREATE INDEX resource_risk_connection
          ON resource_risk (connection_id, sort_key DESC, resource_id);
        -- The Combination filter.
        CREATE INDEX resource_risk_combinations ON resource_risk USING gin (combinations);

        CREATE TABLE risk_load (
          connection_id    bigint PRIMARY KEY REFERENCES connection (id) ON DELETE CASCADE,
          refreshed_on     date NOT NULL,
          combination_set  text NOT NULL CHECK (combination_set ~ '^[0-9a-f]{64}$'),
          refreshed_at     timestamptz NOT NULL DEFAULT now()
        );

        GRANT SELECT ON resource_risk, risk_load TO argus_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON resource_risk, risk_load TO argus_worker;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE risk_load; DROP TABLE resource_risk;")
