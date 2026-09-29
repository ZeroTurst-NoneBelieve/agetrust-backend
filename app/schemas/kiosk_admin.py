"""관리자용 키오스크 등록 및 API Key 관리 응답.

키 원문은 발급 응답에서 한 번만 노출한다. 조회 응답 모델에는 포함하지 않는다.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RegisterKioskRequest(BaseModel):
    store_id: int = Field(gt=0)
    software_version: str | None = Field(default=None, max_length=100)


class IssueKioskKeyRequest(BaseModel):
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("expires_at must include a timezone")
        return value


class SetKioskKeyExpiryRequest(BaseModel):
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")
        return value


class KioskKeyIssuedResponse(BaseModel):
    """이 모델 외의 어디에도 raw_key를 직렬화하지 않는다."""

    key_id: int
    api_key: str = Field(description="키 원문. 이 응답에서만 제공되므로 안전하게 보관한다.")
    key_prefix: str
    expires_at: datetime | None


class KioskRegisteredResponse(BaseModel):
    kiosk_identifier: str
    store_id: int
    status: str
    key: KioskKeyIssuedResponse


class KioskKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key_id: int = Field(validation_alias="id")
    key_prefix: str
    status: str
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None


class KioskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    kiosk_identifier: str
    store_id: int
    status: str
    revoked_at: datetime | None
