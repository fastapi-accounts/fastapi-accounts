"""Add credential_version with check constraint to sessions table

Revision ID: 0005_add_session_credential_version
Revises: 0004_add_credential_version
Create Date: 2026-09-22 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_add_session_credential_version"
down_revision: str | None = "0004_add_credential_version"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {item["name"] for item in inspector.get_columns("sessions")}

    if "credential_version" in existing_columns:
        raise RuntimeError(
            "Schema drift detected: column 'credential_version' already exists in sessions table."
        )

    with op.batch_alter_table("sessions") as batch_op:
        batch_op.add_column(
            sa.Column(
                "credential_version",
                sa.Integer(),
                nullable=True,
                server_default="1",
            )
        )

    # Backfill sessions.credential_version from password_credentials for the corresponding user, defaulting to 1
    if bind.dialect.name == "sqlite":
        op.execute(
            """
            UPDATE sessions
            SET credential_version = COALESCE(
                (SELECT credential_version FROM password_credentials WHERE password_credentials.user_id = sessions.user_id),
                1
            )
            """
        )
    else:
        op.execute(
            """
            UPDATE sessions
            SET credential_version = COALESCE(
                password_credentials.credential_version,
                1
            )
            FROM users
            LEFT JOIN password_credentials ON password_credentials.user_id = users.id
            WHERE sessions.user_id = users.id
            """
        )

    with op.batch_alter_table("sessions") as batch_op:
        batch_op.alter_column(
            "credential_version",
            nullable=False,
            server_default="1",
            type_=sa.Integer(),
        )
        batch_op.create_check_constraint(
            "ck_sessions_credential_version_positive",
            "credential_version >= 1",
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {item["name"] for item in inspector.get_columns("sessions")}

    if "credential_version" in existing_columns:
        with op.batch_alter_table("sessions") as batch_op:
            batch_op.drop_constraint(
                "ck_sessions_credential_version_positive",
                type_="check",
            )
            batch_op.drop_column("credential_version")
