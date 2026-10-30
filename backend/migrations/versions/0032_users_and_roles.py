"""Users and three roles in the database (ADR-0041, 2026-10-28).

Revision ID: 0032
Revises: 0031
Create Date: 2026-10-28

`app_user` holds every person who can sign in, with one role: viewer, operator or admin. The
username is lowercase by its check, so its unique index is case-insensitive by construction.
`auth_source` is `local` only: the seam for SSO. `admin_session` becomes `user_session`, keyed
by the user: every session open now ends (they belonged to the one environment admin, who is
created again by the migrate step's bootstrap). The audit log keeps usernames as text, so its
history outlives a deleted user.

The API reads and writes users (an admin manages them; sign-in reads the hash). It never
deletes a session: deleting a user deletes theirs by the foreign key.
"""

from alembic import op

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE app_user (
          id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          username              text NOT NULL CHECK (username ~ '^[a-z0-9._-]{3,64}$'),
          display_name          text NOT NULL DEFAULT '' CHECK (length(display_name) <= 100),
          password_hash         text NOT NULL,
          role                  text NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
          auth_source           text NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local')),
          is_active             boolean NOT NULL DEFAULT true,
          must_change_password  boolean NOT NULL DEFAULT false,
          created_at            timestamptz NOT NULL DEFAULT now(),
          created_by            text NOT NULL,
          updated_at            timestamptz NOT NULL DEFAULT now(),
          updated_by            text NOT NULL,
          last_sign_in_at       timestamptz
        );
        CREATE UNIQUE INDEX app_user_username ON app_user (username);

        DELETE FROM admin_session;
        ALTER TABLE admin_session RENAME TO user_session;
        ALTER TABLE user_session DROP COLUMN username;  -- and its index
        ALTER TABLE user_session
          ADD COLUMN user_id bigint NOT NULL REFERENCES app_user (id) ON DELETE CASCADE;
        CREATE INDEX user_session_user ON user_session (user_id) WHERE revoked_at IS NULL;

        GRANT SELECT, INSERT, UPDATE, DELETE ON app_user TO argus_api;
    """)


def downgrade() -> None:
    op.execute("""
        DELETE FROM user_session;
        DROP INDEX user_session_user;
        ALTER TABLE user_session DROP COLUMN user_id;
        ALTER TABLE user_session ADD COLUMN username text NOT NULL;
        ALTER TABLE user_session RENAME TO admin_session;
        CREATE INDEX admin_session_username ON admin_session (username) WHERE revoked_at IS NULL;
        DROP TABLE app_user;
    """)
