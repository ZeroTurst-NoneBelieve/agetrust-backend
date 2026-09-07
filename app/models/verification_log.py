from datetime import datetime

from sqlalchemy import (
    TIMESTAMP,
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
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

    `transport_type`은 삭제된 verification_challenges에서 갈 곳이 없어진 컬럼을
    옮겨 온 것이다. 값은 `'QR_BLE'` 하나다. QR로 세션을 열고 BLE로 본 데이터를
    보내는 2채널 조합이라 `'QR'`이나 `'BLE'` 단독이 아니다(ADR-0003). NFC는
    MVP에서 빠졌고, 추가되면 CHECK를 넓히는 마이그레이션이 필요하다.

    ## UNIQUE를 키오스크 단위로 거는 이유

    `(kiosk_id, nonce_hash)` 복합 UNIQUE는 mobile #17(K-7)의 "로컬 큐잉 + 재시도"로
    같은 결과가 두 번 전송되는 것을 DB 차원에서 막는다. ADR-0011이 nonce를 결과
    기록 API의 멱등키로 쓰기로 했고, 요청 본문에 kiosk_identifier가 함께 오므로
    키오스크 단위 중복 판정으로 그 계약이 그대로 성립한다.

    전역 UNIQUE로 걸지 않는다. nonce는 K-1에서 키오스크들이 서로 조율 없이 각자
    만들고 서버는 형식도 엔트로피도 강제하지 않는다. 전역이면 서로 다른 두
    키오스크가 같은 값을 만들었을 때 뒤에 온 쪽의 INSERT가 거부되고, K-7이 같은
    payload로 재시도하므로 영원히 실패한다. 정상 인증 한 건이 감사 테이블에서
    조용히 사라지는 것은 중복 기록보다 나쁜 실패다. ADR-0003이 R8로 잡아 둔
    "nonce 전역 UNIQUE 충돌" 위험을, 16 B CSPRNG 스펙 명시와 별개로 DB 층에서도
    막는다.

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

    ## 시각을 둘 다 남기는 이유 (ADR-0011)

    `verified_at`은 키오스크가 판정한 시각, `received_at`은 서버가 받은 시각이다.
    키오스크는 오프라인으로 며칠을 버틸 수 있고 NTP가 어긋날 수 있어 키오스크
    시계만 믿으면 감사 로그의 시간 순서가 무너진다. 둘이 어긋날 때 조사할 수
    있도록 함께 남긴다.

    `is_late`는 `verified_at`이 수신 시점 기준 7일을 넘긴 기록을 표시한다. 늦게
    온 결과를 버리면 인증이 일어났다는 사실 자체가 지워지므로, 저장하되 표시해
    통계에서 분리한다. 7일은 감사 규정이 아니라 데이터 품질 기준이다.

    `status_list_age_seconds`는 키오스크가 판정에 쓴 StatusList 캐시의 나이다
    (ADR-0013). 캐시가 낡았을 때 거절하면 네트워크 장애가 곧 영업 중단이 되므로
    통과시키되, 나이를 남겨 사후 추적을 가능하게 한다. StatusList를 쓰지 않은
    판정에는 값이 없으므로 NULL을 허용한다.

    `result_status`의 `FAIL_CHALLENGE`는 개정 후에도 유지한다. 서버가 챌린지를
    처리하지 않을 뿐, 키오스크가 자기 챌린지 검증 실패를 판정해 보고하는 값이다.

    ## 정상 판정이 `SUCCESS`가 아니라 `PASS`인 이유

    설계서 §13과 초기 마이그레이션은 이 컬럼의 정상값을 `SUCCESS`로 잡았으나,
    ADR-0011이 결과 기록 API의 요청 본문을 `"result_status": "PASS"`로 확정했다.
    승인된 API 계약을 기준으로 모델과 CHECK를 `PASS`로 맞춘다.

    계약이 `PASS`인 것은 이 값의 출처가 서버가 아니라 키오스크이기 때문이다.
    키오스크는 판정을 BLE `status_notify` `0x20 PASS`로 폰에 먼저 보내고
    (transport-protocol §5.7) 같은 판정을 이 API로 보고한다. 경계마다 이름을
    바꾸면 폰 화면과 서버 기록의 용어가 갈라진다 — `failure_code`를 `0x21`의
    코드와 같은 값으로 맞춘 것과 같은 이유다(ADR-0011).

    `adult_verifications.result_status`는 `SUCCESS`로 남는다. 그쪽은 서버가
    신분증-셀카 대조를 직접 판정해 남기는 다른 테이블이고, 값을 정한 계약도
    다르다. 두 테이블의 정상값이 다른 것은 실수가 아니다.
    """

    __tablename__ = "verification_logs"
    __table_args__ = (
        UniqueConstraint("kiosk_id", "nonce_hash", name="uq_verification_logs_kiosk_nonce"),
        CheckConstraint(
            "result_status IN ("
            "'PASS', 'FAIL_EXPIRED', 'FAIL_FACE_MISMATCH', 'FAIL_INVALID_VC', "
            "'FAIL_INVALID_VP', 'FAIL_REVOKED_VC', 'FAIL_CHALLENGE', 'INTERNAL_ERROR'"
            ")",
            name="ck_verification_logs_result_status",
        ),
        CheckConstraint(
            "transport_type IN ('QR_BLE')",
            name="ck_verification_logs_transport_type",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    kiosk_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("kiosks.id"), nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    transport_type: Mapped[str] = mapped_column(String(20), nullable=False)
    is_vc_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_vp_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_face_matched: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_liveness_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    face_model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    threshold_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status_list_age_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result_status: Mapped[str] = mapped_column(String(50), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verified_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    received_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    is_late: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
