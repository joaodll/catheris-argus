"""Keep unauthenticated sign-in attempts from growing the database.

Revision ID: 0041
Revises: 0040
Create Date: 2026-11-05

Nothing ever deleted login_failure or user_session rows, and anyone who can reach the sign-in page
adds to the first, so retention purges both. The worker runs retention and by design holds no
grant on these tables (0001: "No sessions, no login data"), so it calls one function that can only
delete old rows. The age is fixed in the function, not an argument: a worker that could pass 0
could clear every sign-in limit. 30 days is longer than any lockout window the chart allows.

The partial index serves one question, asked on every refused sign-in: has this address already
got an auth.sign_in.limited row in this window? audit_log itself is never purged. It holds few
rows of that action, so the index stays small, and building it is a short lock on a table the API
only appends to.
"""

from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE FUNCTION argus_purge_sign_in_rows() RETURNS bigint
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
        REVOKE EXECUTE ON FUNCTION argus_purge_sign_in_rows() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION argus_purge_sign_in_rows() TO argus_worker;

        CREATE INDEX audit_log_sign_in_limited ON audit_log (client_ip, occurred_at DESC)
          WHERE action = 'auth.sign_in.limited';
    """)


def downgrade() -> None:
    op.execute("""
        DROP INDEX audit_log_sign_in_limited;
        DROP FUNCTION argus_purge_sign_in_rows();
    """)
