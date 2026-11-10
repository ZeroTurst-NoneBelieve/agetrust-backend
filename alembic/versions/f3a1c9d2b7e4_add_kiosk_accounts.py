"""add KIOSK accounts: role, optional phone, temporary password state

Issue #66. Administrators create KIOSK accounts, and those accounts have no
phone number. USER and ADMIN accounts still require a verified phone number,
enforced by ck_users_phone_required_except_kiosk.

must_change_password / temp_password_expires_at hold the administrator-issued
temporary password state. token_version is bumped on suspension, password
reset and password change so that previously issued tokens stop working.

Revision ID: f3a1c9d2b7e4
Revises: e2b88d76c3a1
"""

from alembic import op
import sqlalchemy as sa


revision = "f3a1c9d2b7e4"
down_revision = "e2b88d76c3a1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_users_platform_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_platform_role", "users", "platform_role IN ('USER', 'ADMIN', 'KIOSK')"
    )

    op.alter_column("users", "phone_number", existing_type=sa.String(length=30), nullable=True)
    op.alter_column("users", "phone_verified_at", existing_type=sa.TIMESTAMP(timezone=True), nullable=True)
    op.create_check_constraint(
        "ck_users_phone_required_except_kiosk",
        "users",
        "platform_role = 'KIOSK' OR (phone_number IS NOT NULL AND phone_verified_at IS NOT NULL)",
    )

    op.add_column(
        "users", sa.Column("must_change_password", sa.Boolean(), server_default=sa.false(), nullable=False)
    )
    op.add_column("users", sa.Column("temp_password_expires_at", sa.TIMESTAMP(timezone=True), nullable=True))
    op.add_column("users", sa.Column("token_version", sa.Integer(), server_default="0", nullable=False))


def downgrade() -> None:
    # KIOSK 계정은 전화번호가 없어 이전 스키마로 되돌릴 수 없다. 조용히 지우지 않고 멈춘다.
    bind = op.get_bind()
    has_kiosk_accounts = bind.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM users WHERE platform_role = 'KIOSK' OR phone_number IS NULL)")
    ).scalar()
    if has_kiosk_accounts:
        raise RuntimeError(
            "KIOSK accounts (or users without a phone number) exist. Remove them before downgrading."
        )

    op.drop_column("users", "token_version")
    op.drop_column("users", "temp_password_expires_at")
    op.drop_column("users", "must_change_password")

    op.drop_constraint("ck_users_phone_required_except_kiosk", "users", type_="check")
    op.alter_column("users", "phone_verified_at", existing_type=sa.TIMESTAMP(timezone=True), nullable=False)
    op.alter_column("users", "phone_number", existing_type=sa.String(length=30), nullable=False)

    op.drop_constraint("ck_users_platform_role", "users", type_="check")
    op.create_check_constraint("ck_users_platform_role", "users", "platform_role IN ('USER', 'ADMIN')")
