"""Reports: the queue of requested exports (ADR-0047, owner 2026-11-11).

Revision ID: 0047
Revises: 0046
Create Date: 2026-11-11

`report_request` is owned by the `reports` module. An Operator or Admin asks for a report through
the API; the worker claims it, builds the file into the reports store and records where it is.

- `filters` is the list screen's filters, validated by the API and read back by the worker.
  `connection_ids` is the scope resolved at request time (an empty connection filter means every
  connection, as the list shows them), so the builder never widens it. No foreign key: a
  connection deleted later simply contributes nothing.
- `requested_by_id` keys ownership (a user can be deleted and the username reused, so the name
  alone cannot). Deleting a user keeps their reports, unowned, for an Admin to see: the foreign
  key sets NULL, and Postgres runs that action as the table's owner, so the API (which deletes
  users) needs no UPDATE here. `requested_by` keeps the name for display.
- Expiry is fixed at 7 days from the moment the file is ready and is computed at read time
  (`expires_at <= now()`); nothing writes an "expired" status. `file_deleted_at` records that
  retention removed the file.
- `storage_key` has one shape, `reports/<id>-<32 hex>.csv`, so no stored key can name a path
  outside the reports folder whatever wrote it.

Grants: the API reads every column and inserts only the request's own columns, so it cannot
mark a report ready or point it at a file. The worker writes the build's columns only, never
the request, the scope or the owner. The scheduler has none: on Kubernetes nothing builds
reports until round 5.

A new, empty table: no lock on anything else.
"""

from alembic import op

revision = "0047"
down_revision = "0046"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE report_request (
          id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          kind             text NOT NULL CHECK (kind IN ('misconfigurations', 'vulnerabilities')),
          format           text NOT NULL CHECK (format IN ('csv')),
          filters          jsonb NOT NULL CHECK (
                             jsonb_typeof(filters) = 'object' AND length(filters::text) <= 16384
                           ),
          connection_ids   bigint[] NOT NULL CHECK (
                             cardinality(connection_ids) BETWEEN 1 AND 10000
                             AND array_position(connection_ids, NULL) IS NULL
                           ),
          requested_by_id  bigint REFERENCES app_user (id) ON DELETE SET NULL,
          requested_by     text NOT NULL CHECK (length(requested_by) BETWEEN 1 AND 320),
          status           text NOT NULL DEFAULT 'queued'
                             CHECK (status IN ('queued', 'building', 'ready', 'failed')),
          requested_at     timestamptz NOT NULL DEFAULT now(),
          started_at       timestamptz,
          finished_at      timestamptz,
          expires_at       timestamptz,
          file_deleted_at  timestamptz,
          storage_key      text CHECK (storage_key ~ '^reports/[0-9]+-[0-9a-f]{32}\\.csv$'),
          size_bytes       bigint CHECK (size_bytes >= 0),
          sha256           text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
          row_count        bigint CHECK (row_count >= 0),
          truncated        boolean NOT NULL DEFAULT false,
          data_through     jsonb
                             CHECK (data_through IS NULL OR jsonb_typeof(data_through) = 'object'),
          error            text CHECK (length(error) <= 2000),
          CONSTRAINT report_request_started CHECK ((status = 'queued') = (started_at IS NULL)),
          CONSTRAINT report_request_finished
            CHECK ((status IN ('ready', 'failed')) = (finished_at IS NOT NULL)),
          CONSTRAINT report_request_ready CHECK (
            (status = 'ready') = (
              storage_key IS NOT NULL AND size_bytes IS NOT NULL AND sha256 IS NOT NULL
              AND row_count IS NOT NULL AND expires_at IS NOT NULL AND data_through IS NOT NULL
            )
          ),
          CONSTRAINT report_request_failed CHECK ((status = 'failed') = (error IS NOT NULL)),
          CONSTRAINT report_request_file_deleted
            CHECK (file_deleted_at IS NULL OR status = 'ready')
        );
        -- The worker's claim: the oldest queued request.
        CREATE INDEX report_request_queued ON report_request (requested_at, id)
          WHERE status = 'queued';
        -- An Operator's own list, newest first, and their count of open requests.
        CREATE INDEX report_request_owner
          ON report_request (requested_by_id, requested_at DESC, id DESC);
        -- An Admin's list of every request, newest first.
        CREATE INDEX report_request_recent ON report_request (requested_at DESC, id DESC);
        -- Retention: ready files past their expiry that are still on disk.
        CREATE INDEX report_request_expiring ON report_request (expires_at)
          WHERE status = 'ready' AND file_deleted_at IS NULL;

        GRANT SELECT,
              INSERT (kind, format, filters, connection_ids, requested_by_id, requested_by)
          ON report_request TO argus_api;
        GRANT SELECT,
              UPDATE (status, started_at, finished_at, expires_at, file_deleted_at, storage_key,
                      size_bytes, sha256, row_count, truncated, data_through, error)
          ON report_request TO argus_worker;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE report_request;")
