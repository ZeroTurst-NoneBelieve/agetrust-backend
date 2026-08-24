"""감사 로그 이벤트 타입 사전 및 조회 응답 스키마."""

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class AuditActorType(StrEnum):
    """설계서 15. audit_logs의 actor_type CHECK 값과 일치해야 한다."""

    USER = "USER"
    ADMIN = "ADMIN"
    KIOSK = "KIOSK"
    SYSTEM = "SYSTEM"


class AuditEventType(StrEnum):
    """감사 대상 이벤트.

    문자열을 각 엔드포인트에 흩어두면 오타가 나도 조회 시점에야 드러나므로
    여기서 한 번에 관리한다.
    """

    PHONE_VERIFICATION_SUCCEEDED = "PHONE_VERIFICATION_SUCCEEDED"
    PHONE_VERIFICATION_FAILED = "PHONE_VERIFICATION_FAILED"
    USER_SIGNED_UP = "USER_SIGNED_UP"
    LOGIN_SUCCEEDED = "LOGIN_SUCCEEDED"
    LOGIN_FAILED = "LOGIN_FAILED"
    DEVICE_REGISTERED = "DEVICE_REGISTERED"
    HOLDER_KEY_BOUND = "HOLDER_KEY_BOUND"
    HOLDER_KEY_REBOUND = "HOLDER_KEY_REBOUND"
    ADULT_VERIFICATION_RECORDED = "ADULT_VERIFICATION_RECORDED"
    VC_ISSUED = "VC_ISSUED"


class AuditAggregateType(StrEnum):
    USER = "USER"
    DEVICE = "DEVICE"
    ADULT_VERIFICATION = "ADULT_VERIFICATION"
    VC_CREDENTIAL = "VC_CREDENTIAL"
    PHONE_VERIFICATION = "PHONE_VERIFICATION"


class AuditLogResponse(BaseModel):
    id: int
    event_id: uuid.UUID
    event_type: str
    actor_type: str
    actor_ref: str | None
    source_kiosk_id: int | None
    aggregate_type: str | None
    aggregate_id: str | None
    payload: dict
    previous_hash: str | None
    event_hash: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogPage(BaseModel):
    """오프셋 기반 페이지 응답."""

    items: list[AuditLogResponse]
    total: int = Field(description="필터 조건에 해당하는 전체 건수")
    limit: int
    offset: int


class ChainBreak(BaseModel):
    audit_log_id: int
    event_id: uuid.UUID
    reason: str = Field(
        description="LINK_MISMATCH=직전 해시 불일치, HASH_MISMATCH=본문 변조"
    )
    expected: str
    stored: str


class ChainVerificationResponse(BaseModel):
    """해시 체인 무결성 검증 결과."""

    checked: int
    is_intact: bool
    first_break: ChainBreak | None = None
    from_id: int | None = None
    to_id: int | None = None
