"""Add indexes on sessions (user_id, expires_at) idempotently

Revision ID: 0003_add_session_indexes
Revises: 0002_add_password_updated_at
Create Date: 2026-09-20 00:10:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_add_session_indexes"
down_revision: str | None = "0002_add_password_updated_at"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_indexes = {item["name"] for item in inspector.get_indexes("sessions")}

    if "ix_sessions_user_id" not in existing_indexes:
        op.create_index(
            op.f("ix_sessions_user_id"), "sessions", ["user_id"], unique=False
        )

    if "ix_sessions_expires_at" not in existing_indexes:
        op.create_index(
            op.f("ix_sessions_expires_at"), "sessions", ["expires_at"], unique=False
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_indexes = {item["name"] for item in inspector.get_indexes("sessions")}

    if "ix_sessions_expires_at" in existing_indexes:
        op.drop_index(op.f("ix_sessions_expires_at"), table_name="sessions")

    if "ix_sessions_user_id" in existing_indexes:
        op.drop_index(op.f("ix_sessions_user_id"), table_name="sessions")
