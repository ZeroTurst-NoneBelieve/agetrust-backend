"""split kiosk API keys into a one-to-many table

ADR-0010 requires independently revocable keys and overlapping keys during rotation.
Legacy hashes cannot reveal the first eight characters of their raw keys, so valid,
uniquely assigned legacy hashes use the reserved ``legacy__`` prefix. The authenticator
must look up that prefix by full hash until those keys are rotated.

Duplicate legacy hashes are deliberately not copied: the old authenticator rejected
every member of such a group rather than choosing an arbitrary kiosk. Malformed hashes
are also not copied because they could never match a SHA-256 hex digest. Kiosk rows are
preserved and can receive newly issued keys.

Revision ID: e2b88d76c3a1
Revises: d4f8a2b16c07
"""

from alembic import op
import sqlalchemy as sa


revision = "e2b88d76c3a1"
down_revision = "d4f8a2b16c07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kiosk_api_keys",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("kiosk_id", sa.BigInteger(), nullable=False),
        sa.Column("key_prefix", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=30), server_default="ACTIVE", nullable=False),
        sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('ACTIVE', 'REVOKED')", name="ck_kiosk_api_keys_status"),
        sa.ForeignKeyConstraint(["kiosk_id"], ["kiosks.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash", name="uq_kiosk_api_keys_key_hash"),
    )
    op.create_index("ix_kiosk_api_keys_key_prefix", "kiosk_api_keys", ["key_prefix"])
    op.create_index("ix_kiosk_api_keys_kiosk_status", "kiosk_api_keys", ["kiosk_id", "status"])

    # A duplicate hash was already unusable: the previous dependency returned 401
    # when two kiosks shared it. Do not make one of them authenticate by accident.
    op.execute(
        sa.text(
            """
            INSERT INTO kiosk_api_keys (kiosk_id, key_prefix, key_hash, status)
            SELECT k.id, 'legacy__', k.api_key_hash, 'ACTIVE'
            FROM kiosks AS k
            JOIN (
                SELECT api_key_hash
                FROM kiosks
                WHERE api_key_hash ~ '^[0-9a-f]{64}$'
                GROUP BY api_key_hash
                HAVING COUNT(*) = 1
            ) AS unique_legacy ON unique_legacy.api_key_hash = k.api_key_hash
            """
        )
    )
    op.drop_column("kiosks", "api_key_hash")


def downgrade() -> None:
    bind = op.get_bind()
    cannot_represent = bind.execute(
        sa.text(
            """
            SELECT EXISTS (
                SELECT 1
                FROM kiosks AS k
                LEFT JOIN kiosk_api_keys AS key ON key.kiosk_id = k.id
                GROUP BY k.id
                HAVING COUNT(key.id) <> 1
                    OR COUNT(*) FILTER (
                        WHERE key.status <> 'ACTIVE'
                           OR key.expires_at IS NOT NULL
                           OR key.revoked_at IS NOT NULL
                    ) > 0
            )
            """
        )
    ).scalar_one()
    if cannot_represent:
        raise RuntimeError(
            "Cannot downgrade kiosk API keys: every kiosk must have exactly one "
            "active, non-expiring key. Reissue missing keys and resolve multiple "
            "or revoked keys before retrying."
        )

    op.add_column("kiosks", sa.Column("api_key_hash", sa.String(length=255), nullable=True))
    op.execute(
        sa.text(
            """
            UPDATE kiosks AS k
            SET api_key_hash = key.key_hash
            FROM kiosk_api_keys AS key
            WHERE key.kiosk_id = k.id
            """
        )
    )
    op.alter_column("kiosks", "api_key_hash", existing_type=sa.String(length=255), nullable=False)
    op.drop_index("ix_kiosk_api_keys_kiosk_status", table_name="kiosk_api_keys")
    op.drop_index("ix_kiosk_api_keys_key_prefix", table_name="kiosk_api_keys")
    op.drop_table("kiosk_api_keys")
