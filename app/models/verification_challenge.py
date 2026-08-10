from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, CheckConstraint, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class VerificationChallenge(Base):
    """설계서 12. verification_challenges

    nonce는 한 번만 사용하는 랜덤 값으로 Replay 공격을 막는다.
    QR 원문(challenge_qr_data)은 DB에 저장하지 않는다.
    """

    __tablename__ = "verification_challenges"
    __table_args__ = (
        CheckConstraint("transport_type IN ('QR', 'NFC', 'BLE')", name="ck_verification_challenges_transport_type"),
        CheckConstraint(
            "status IN ('PENDING', 'CONSUMED', 'EXPIRED', 'CANCELLED')",
            name="ck_verification_challenges_status",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    kiosk_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("kiosks.id"), nullable=False)
    transport_type: Mapped[str] = mapped_column(String(20), nullable=False)
    challenge_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, server_default="PENDING")
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
