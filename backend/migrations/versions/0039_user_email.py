"""An optional email address on each user.

Revision ID: 0039
Revises: 0038
Create Date: 2026-11-03

Set by an admin, and nothing sends mail to it (owner, 2026-10-31 and 2026-11-03). Sign-in stays by
username. It is the seam for single sign-on, which will match people by email, so it is unique.
It is lowercase by its check, so like the username its unique index is case-insensitive by
construction. NULLs do not collide, so any number of users can have none.

The shape is the one auth.users.check_email enforces. app_user is a small table of people, so the
check validating its rows under the lock is nothing to plan around. The table-level grant from 0032
already covers the column.
"""

from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE app_user ADD COLUMN email text CHECK (
          length(email) <= 254
          AND email ~ '^[a-z0-9._%+''-]+@[a-z0-9-]+(\\.[a-z0-9-]+)+$'
        );
        CREATE UNIQUE INDEX app_user_email ON app_user (email);
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE app_user DROP COLUMN email;")  # and its index and check
