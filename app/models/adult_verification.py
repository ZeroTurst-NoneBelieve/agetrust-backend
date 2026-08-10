from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, Boolean, CheckConstraint, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AdultVerification(Base):
    """설계서 09. adult_verifications

    생년월일/OCR 원문/얼굴 원본/임베딩/raw similarity score는 저장하지 않는다.
    """

    __tablename__ = "adult_verifications"
    __table_args__ = (
        CheckConstraint(
            "result_status IN ('SUCCESS', 'FAIL_AGE', 'FAIL_FACE_MISMATCH', 'FAIL_LIVENESS', 'ERROR')",
            name="ck_adult_verifications_result_status",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("devices.id"), nullable=False)
    age_check_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    id_face_match_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    liveness_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    age_policy_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    threshold_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    result_status: Mapped[str] = mapped_column(String(50), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verified_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    invalidated_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
