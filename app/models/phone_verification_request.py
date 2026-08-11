import uuid
from datetime import datetime

from sqlalchemy import TIMESTAMP, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class PhoneVerificationRequest(Base):
    """설계서 02. phone_verification_requests

    users 생성 전에도 존재해야 하므로 user_id FK를 두지 않는다.
    """

    __tablename__ = "phone_verification_requests"
    __table_args__ = (
        Index(
            "ix_phone_verification_requests_lookup",
            "phone_number",
            "purpose",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    phone_number: Mapped[str] = mapped_column(String(30), nullable=False)
    otp_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    purpose: Mapped[str] = mapped_column(String(30), nullable=False, server_default="SIGN_UP")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    resend_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    last_sent_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
