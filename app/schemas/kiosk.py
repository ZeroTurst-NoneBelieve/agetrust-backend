"""키오스크가 이미 판정한 결과의 업로드 계약 (#42)."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, field_validator

from app.schemas.errors import VerificationResultStatus


class KioskVerificationResultRequest(BaseModel):
    # 사용자 식별자, VP/VC 원문, 얼굴 임베딩 등은 결과 수집 대상이 아니다.
    model_config = ConfigDict(extra="forbid")

    kiosk_identifier: str = Field(min_length=1, max_length=255, strict=True)
    nonce: str = Field(
        min_length=1, max_length=128, strict=True,
        description="키오스크 세션의 nonce 원문. 서버는 UTF-8 문자열의 SHA-256만 저장한다.",
    )
    verified_at: AwareDatetime = Field(description="시간대가 포함된 키오스크 판정 시각 (ISO 8601).")
    result_status: VerificationResultStatus
    is_vc_valid: StrictBool
    is_face_matched: StrictBool
    transport_type: Literal["QR_BLE"]
    # 기존 ADR-0011 예제에는 이 두 필드가 없다. DB 기본값과 맞추고,
    # PASS만 보고 서버가 실제 수행되지 않은 VP/라이브니스 검증을 추론하지 않는다.
    is_vp_valid: StrictBool = False
    is_liveness_valid: StrictBool | None = None
    failure_code: str | None = Field(default=None, min_length=1, max_length=100, strict=True)
    face_model_version: str | None = Field(default=None, min_length=1, max_length=100, strict=True)
    threshold_version: str | None = Field(default=None, min_length=1, max_length=100, strict=True)
    status_list_age_seconds: int | None = Field(default=None, ge=0, le=2**31 - 1, strict=True)

    @field_validator(
        "kiosk_identifier", "nonce", "failure_code", "face_model_version", "threshold_version",
    )
    @classmethod
    def validate_text(cls, value: str | None) -> str | None:
        # PostgreSQL text는 NUL을 저장하지 못한다. 잘못된 본문을 재시도할
        # 5xx로 돌려보내지 않도록 요청 경계에서 거절한다. nonce는 변형하지 않는다.
        if value is not None and (not value.strip() or "\x00" in value):
            raise ValueError("Expected nonblank text without NUL characters")
        return value

    @field_validator("verified_at", mode="before")
    @classmethod
    def require_datetime(cls, value):
        # Pydantic은 숫자 문자열도 Unix timestamp로 변환하므로 ISO 형식을
        # 먼저 확인한다. 시간대 포함 여부는 AwareDatetime이 검증한다.
        if isinstance(value, str):
            return datetime.fromisoformat(value)
        if not isinstance(value, (str, datetime)):
            raise ValueError("Expected an ISO 8601 timestamp with timezone")
        return value

    @field_validator("verified_at")
    @classmethod
    def ensure_utc_representable(cls, value: datetime) -> datetime:
        try:
            value.astimezone(timezone.utc)
        except (OverflowError, ValueError):
            raise ValueError("Timestamp must be representable in UTC") from None
        return value


class KioskVerificationResultResponse(BaseModel):
    """처음 저장한 결과의 영수증. 재전송에도 같은 값을 돌려준다."""

    id: int
    received_at: datetime
    is_late: bool

    model_config = ConfigDict(from_attributes=True)
