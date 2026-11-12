"""Users who sign in with SAML, and the assertions already used (ADR-0048).

Revision ID: 0049
Revises: 0048
Create Date: 2026-11-11

app_user gains a second source. A local user keeps a password hash and a username of the old shape;
an SSO user has no password, the IdP's NameID as external_id, and their email as username and email.
Local usernames can't hold "@" and SSO usernames must, so the two kinds never share a username, and
the unique email index keeps an SSO user from taking a local user's address. role_group names the
IdP group that granted an SSO user's role, for Users to show.

saml_assertion_seen remembers each accepted assertion id until it expires, so an answer can't be
used twice. A row is written only after the IdP's signature has been checked, so nobody without the
IdP's key can grow it. The API inserts and reads; only the purge function, run by retention as the
worker, deletes.

The partial index serves the refused-SSO deduplication: one auth.sso.refused row per address and
reason per window, like 0041's index for refused password sign-ins.

app_user is a small table of people: the new CHECKs validate under a short lock. Downgrade refuses
while SSO users exist, since the old CHECKs can't hold them; deactivate and delete them first.
"""

from alembic import op

revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE app_user
          ADD COLUMN external_id text,
          ADD COLUMN role_group text,
          ALTER COLUMN password_hash DROP NOT NULL,
          DROP CONSTRAINT app_user_auth_source_check,
          DROP CONSTRAINT app_user_username_check,
          ADD CONSTRAINT app_user_auth_source_check CHECK (auth_source IN ('local', 'saml')),
          ADD CONSTRAINT app_user_username_check CHECK (
            CASE auth_source
              WHEN 'local' THEN username ~ '^[a-z0-9._-]{3,64}$'
              ELSE length(username) <= 254
                AND username ~ '^[a-z0-9._%+''-]+@[a-z0-9-]+(\\.[a-z0-9-]+)+$'
            END),
          ADD CONSTRAINT app_user_password_iff_local
            CHECK ((auth_source = 'local') = (password_hash IS NOT NULL)),
          ADD CONSTRAINT app_user_sso_fields CHECK (
            CASE auth_source
              WHEN 'saml' THEN external_id IS NOT NULL AND length(external_id) <= 512
                AND email = username AND must_change_password = false
              ELSE external_id IS NULL AND role_group IS NULL
            END),
          ADD CONSTRAINT app_user_role_group_length CHECK (length(role_group) <= 256);
        CREATE UNIQUE INDEX app_user_external_id ON app_user (external_id);

        CREATE TABLE saml_assertion_seen (
          assertion_id text PRIMARY KEY CHECK (length(assertion_id) BETWEEN 1 AND 256),
          expires_at timestamptz NOT NULL
        );
        GRANT SELECT, INSERT ON saml_assertion_seen TO argus_api;

        CREATE OR REPLACE FUNCTION argus_purge_sign_in_rows() RETURNS bigint
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
        DECLARE
          failures bigint;
          sessions bigint;
          assertions bigint;
        BEGIN
          DELETE FROM login_failure WHERE failed_at < now() - interval '30 days';
          GET DIAGNOSTICS failures = ROW_COUNT;
          DELETE FROM user_session WHERE absolute_expires_at < now() - interval '30 days';
          GET DIAGNOSTICS sessions = ROW_COUNT;
          DELETE FROM saml_assertion_seen WHERE expires_at < now();
          GET DIAGNOSTICS assertions = ROW_COUNT;
          RETURN failures + sessions + assertions;
        END
        $fn$;

        CREATE INDEX audit_log_sso_refused
          ON audit_log (client_ip, (detail ->> 'reason'), occurred_at DESC)
          WHERE action = 'auth.sso.refused';
    """)


def downgrade() -> None:
    op.execute("""
        DO $check$
        BEGIN
          IF EXISTS (SELECT 1 FROM app_user WHERE auth_source <> 'local') THEN
            RAISE EXCEPTION 'SSO users exist: deactivate and delete them before downgrading';
          END IF;
        END
        $check$;

        DROP INDEX audit_log_sso_refused;

        CREATE OR REPLACE FUNCTION argus_purge_sign_in_rows() RETURNS bigint
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
        DECLARE
          failures bigint;
          sessions bigint;
        BEGIN
          DELETE FROM login_failure WHERE failed_at < now() - interval '30 days';
          GET DIAGNOSTICS failures = ROW_COUNT;
          DELETE FROM user_session WHERE absolute_expires_at < now() - interval '30 days';
          GET DIAGNOSTICS sessions = ROW_COUNT;
          RETURN failures + sessions;
        END
        $fn$;

        DROP TABLE saml_assertion_seen;
        DROP INDEX app_user_external_id;
        ALTER TABLE app_user
          DROP CONSTRAINT app_user_role_group_length,
          DROP CONSTRAINT app_user_sso_fields,
          DROP CONSTRAINT app_user_password_iff_local,
          DROP CONSTRAINT app_user_username_check,
          DROP CONSTRAINT app_user_auth_source_check,
          ADD CONSTRAINT app_user_auth_source_check CHECK (auth_source IN ('local')),
          ADD CONSTRAINT app_user_username_check CHECK (username ~ '^[a-z0-9._-]{3,64}$'),
          ALTER COLUMN password_hash SET NOT NULL,
          DROP COLUMN role_group,
          DROP COLUMN external_id;
    """)
