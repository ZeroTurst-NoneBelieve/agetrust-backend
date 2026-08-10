from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, CheckConstraint, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Device(Base):
    """설계서 04. devices

    Holder Private Key, 등록 얼굴 임베딩, OS 지문/Face ID 원본은 DB 저장 금지.
    """

    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint("platform IN ('ANDROID', 'IOS')", name="ck_devices_platform"),
        CheckConstraint("status IN ('ACTIVE', 'REVOKED', 'LOST')", name="ck_devices_status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    device_identifier: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    platform: Mapped[str] = mapped_column(String(20), nullable=False)
    holder_did: Mapped[str | None] = mapped_column(String(500), unique=True, nullable=True)
    holder_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, server_default="ACTIVE")
    registered_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
