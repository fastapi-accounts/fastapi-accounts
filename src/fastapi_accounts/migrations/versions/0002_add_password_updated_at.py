"""Add password_updated_at to password_credentials (expand/backfill/constrain)

Revision ID: 0002_add_password_updated_at
Revises: 0001_initial_schema
Create Date: 2026-09-20 00:05:00.000000

"""

from collections.abc import Sequence
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision: str = "0002_add_password_updated_at"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Expand: Add column as nullable
    with op.batch_alter_table("password_credentials") as batch_op:
        batch_op.add_column(
            sa.Column(
                "password_updated_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )

    # 2. Backfill: Populate existing rows with current timestamp
    now = datetime.now(timezone.utc)
    op.execute(
        sa.text(
            "UPDATE password_credentials SET password_updated_at = :now WHERE password_updated_at IS NULL"
        ).bindparams(now=now)
    )

    # 3. Constrain: Set column to NOT NULL
    with op.batch_alter_table("password_credentials") as batch_op:
        batch_op.alter_column(
            "password_updated_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("password_credentials") as batch_op:
        batch_op.drop_column("password_updated_at")
