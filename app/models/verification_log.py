from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, Boolean, CheckConstraint, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class VerificationLog(Base):
    """설계서 13. verification_logs

    user_id는 저장하지 않아 중앙 DB가 사용자별 매장 방문 패턴을 직접 연결하지 않는다.
    kiosk_id는 challenge_id -> verification_challenges -> kiosks로 조회한다.
    """

    __tablename__ = "verification_logs"
    __table_args__ = (
        CheckConstraint(
            "result_status IN ("
            "'SUCCESS', 'FAIL_EXPIRED', 'FAIL_FACE_MISMATCH', 'FAIL_INVALID_VC', "
            "'FAIL_INVALID_VP', 'FAIL_REVOKED_VC', 'FAIL_CHALLENGE', 'INTERNAL_ERROR'"
            ")",
            name="ck_verification_logs_result_status",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    challenge_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("verification_challenges.id"), unique=True, nullable=False
    )
    is_vc_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_vp_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_face_matched: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_liveness_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    face_model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    threshold_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    result_status: Mapped[str] = mapped_column(String(50), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verified_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
