from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, Boolean, CheckConstraint, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class VerificationLog(Base):
    """설계서 13. verification_logs (개정된 검증 흐름 반영, #31)

    user_id는 저장하지 않아 중앙 DB가 사용자별 매장 방문 패턴을 직접 연결하지 않는다.

    ## 개정 전과 달라진 점

    개정 전에는 서버가 챌린지를 발급했고, 이 테이블은 `challenge_id`로
    verification_challenges를 참조해 `challenge_id -> verification_challenges
    -> kiosks` 경로로 인증 위치를 조회했다.

    개정 후(mobile #7 K-1)에는 키오스크가 nonce를 로컬에서 생성하고 백엔드를
    호출하지 않는다. 서버에 challenge 행이 생기지 않으므로 참조할 대상이 없다.
    그래서 경유 테이블을 없애고 다음 두 컬럼을 직접 둔다.

    - `kiosk_id`: 인증이 발생한 키오스크. admin-web #3 매장별 감사 로그 조회에
      쓰인다 (kiosks -> stores -> businesses JOIN).
    - `nonce`: 키오스크가 생성한 일회성 값. UNIQUE를 걸어 mobile #17(K-7)의
      "로컬 큐잉 + 재시도"로 같은 결과가 두 번 전송되는 것을 DB 차원에서 막는다.

    replay 방지 자체는 키오스크 책임으로 이동했다. 이 UNIQUE는 결과 기록의
    중복을 막는 것이지 인증 시점의 replay를 막는 것이 아니다.
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
    kiosk_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("kiosks.id"), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    is_vc_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_vp_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_face_matched: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_liveness_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    face_model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    threshold_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    result_status: Mapped[str] = mapped_column(String(50), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verified_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
