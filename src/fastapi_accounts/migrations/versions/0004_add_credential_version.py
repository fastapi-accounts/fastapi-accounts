"""Add credential_version with check constraint to password_credentials

Revision ID: 0004_add_credential_version
Revises: 0003_add_session_indexes
Create Date: 2026-09-20 23:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_add_credential_version"
down_revision: str | None = "0003_add_session_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {
        item["name"] for item in inspector.get_columns("password_credentials")
    }

    if "credential_version" not in existing_columns:
        with op.batch_alter_table("password_credentials") as batch_op:
            batch_op.add_column(
                sa.Column(
                    "credential_version",
                    sa.Integer(),
                    nullable=True,
                    server_default="1",
                )
            )

        op.execute(
            "UPDATE password_credentials SET credential_version = 1 WHERE credential_version IS NULL"
        )

        with op.batch_alter_table("password_credentials") as batch_op:
            batch_op.alter_column(
                "credential_version",
                nullable=False,
                server_default="1",
                type_=sa.Integer(),
            )
            batch_op.create_check_constraint(
                "ck_password_credentials_credential_version_positive",
                "credential_version >= 1",
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {
        item["name"] for item in inspector.get_columns("password_credentials")
    }

    if "credential_version" in existing_columns:
        with op.batch_alter_table("password_credentials") as batch_op:
            batch_op.drop_constraint(
                "ck_password_credentials_credential_version_positive",
                type_="check",
            )
            batch_op.drop_column("credential_version")
