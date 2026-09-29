from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, CheckConstraint, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class KioskApiKey(Base):
    """키오스크별 API Key. 원문은 저장하지 않는다 (ADR-0010)."""

    __tablename__ = "kiosk_api_keys"
    __table_args__ = (
        CheckConstraint("status IN ('ACTIVE', 'REVOKED')", name="ck_kiosk_api_keys_status"),
        UniqueConstraint("key_hash", name="uq_kiosk_api_keys_key_hash"),
        Index("ix_kiosk_api_keys_key_prefix", "key_prefix"),
        Index("ix_kiosk_api_keys_kiosk_status", "kiosk_id", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    kiosk_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("kiosks.id"), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, server_default="ACTIVE")
    last_used_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
