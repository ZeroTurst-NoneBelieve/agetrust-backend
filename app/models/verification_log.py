from datetime import datetime

from sqlalchemy import (
    TIMESTAMP,
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
)
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
    - `nonce_hash`: 키오스크가 생성한 일회성 값의 SHA-256. 설계서 §12의
      "nonce는 원문 대신 hash를 저장한다" 원칙을 따른다.

    ## UNIQUE를 키오스크 단위로 거는 이유

    `(kiosk_id, nonce_hash)` 복합 UNIQUE는 mobile #17(K-7)의 "로컬 큐잉 + 재시도"로
    같은 결과가 두 번 전송되는 것을 DB 차원에서 막는다.

    전역 UNIQUE로 걸지 않는다. nonce는 K-1에서 키오스크들이 서로 조율 없이 각자
    만들고 서버는 형식도 엔트로피도 강제하지 않는다. 전역이면 서로 다른 두
    키오스크가 같은 값을 만들었을 때 뒤에 온 쪽의 INSERT가 거부되고, K-7이 같은
    payload로 재시도하므로 영원히 실패한다. 정상 인증 한 건이 감사 테이블에서
    조용히 사라지는 것은 중복 기록보다 나쁜 실패다. 막으려는 것이 "같은 결과의
    중복 전송"이므로 의미상으로도 키오스크 단위가 맞다.

    ## nonce_hash가 보장하는 범위

    해결하는 것 - 설계서 §12 원칙 준수, 64자 고정, DB 덤프만 가진 사람이 원문
    nonce를 알 수 없다.

    해결하지 않는 것이 둘 있다.

    1. 충돌 위험은 줄지 않는다. 해시는 결정적이라 키오스크가 카운터나 타임스탬프
       같은 저엔트로피 nonce를 쓰면 `nonce_hash`도 똑같이 충돌한다. 오히려 충돌
       시 원본을 볼 수 없어 원인 파악이 어렵다. 위 복합 UNIQUE가 필요한 이유다.
    2. nonce 원문을 아는 상대에게는 연결을 막지 못한다. SHA-256은 키 없는 해시라
       기기나 키오스크 쪽에서 nonce를 확보한 사람은 그대로 해시해 행을 특정할 수
       있다. user_id 미저장이 노리는 "매장 방문 연결 차단"을 `nonce_hash`가
       넓혀주는 범위는 DB 덤프 단독 열람자까지다.

    replay 방지 자체는 키오스크 책임으로 이동했다. 이 UNIQUE는 결과 기록의
    중복을 막는 것이지 인증 시점의 replay를 막는 것이 아니다.

    `result_status`의 `FAIL_CHALLENGE`는 개정 후에도 유지한다. 서버가 챌린지를
    처리하지 않을 뿐, 키오스크가 자기 챌린지 검증 실패를 판정해 보고하는 값이다.
    """

    __tablename__ = "verification_logs"
    __table_args__ = (
        UniqueConstraint("kiosk_id", "nonce_hash", name="uq_verification_logs_kiosk_nonce"),
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
    nonce_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    is_vc_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_vp_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_face_matched: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_liveness_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    face_model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    threshold_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    result_status: Mapped[str] = mapped_column(String(50), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verified_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
